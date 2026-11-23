import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

private let kEnvelopeVersion = 1
private let kSharedInfoPrefix = "free-inference-se-v1|"
private let kDefaultAccount = "free-inference"
private let kSkipExitCode: Int32 = 77

// MARK: - Hardening & Helpers

private func disableDebuggerAttachment() {
    typealias PtraceFn = @convention(c) (CInt, pid_t, caddr_t?, CInt) -> CInt
    let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)
    if let sym = dlsym(rtldDefault, "ptrace") {
        let ptrace = unsafeBitCast(sym, to: PtraceFn.self)
        _ = ptrace(31 /* PT_DENY_ATTACH */, 0, nil, 0)
    }
}

private func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
    if a.count != b.count {
        return false
    }
    var diff: UInt8 = 0
    for i in 0..<a.count {
        diff |= a[i] ^ b[i]
    }
    return diff == 0
}

private func bestEffortZero(_ data: inout Data) {
    if !data.isEmpty {
        data.resetBytes(in: 0..<data.count)
    }
}

private func sha256Hex(_ data: Data) -> String {
    let digest = SHA256.hash(data: data)
    return digest.map { String(format: "%02x", $0) }.joined()
}

private func isoNow() -> String {
    let fmt = ISO8601DateFormatter()
    return fmt.string(from: Date())
}

private func writeStderr(_ msg: String) {
    if let data = (msg + "\n").data(using: .utf8) {
        FileHandle.standardError.write(data)
    }
}

private func printJSON(_ dict: [String: Any]) {
    if let data = try? JSONSerialization.data(
        withJSONObject: dict,
        options: [.prettyPrinted, .sortedKeys]
    ), let text = String(data: data, encoding: .utf8) {
        print(text)
    }
}

private func trimASCIIWhitespaceAndZero(_ raw: inout Data) -> Data {
    defer { bestEffortZero(&raw) }
    var start = 0
    var end = raw.count
    while start < end {
        let b = raw[start]
        if b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D || b == 0x0B || b == 0x0C {
            start += 1
        } else {
            break
        }
    }
    while end > start {
        let b = raw[end - 1]
        if b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D || b == 0x0B || b == 0x0C {
            end -= 1
        } else {
            break
        }
    }
    if start >= end {
        return Data()
    }
    return Data(raw[start..<end])
}

private func readAllFromFD(_ fd: Int32, maxBytes: Int = 8192) throws -> Data {
    var result = Data()
    var buf = [UInt8](repeating: 0, count: 1024)
    defer {
        for idx in 0..<buf.count {
            buf[idx] = 0
        }
    }
    while result.count < maxBytes {
        let n = Darwin.read(fd, &buf, min(buf.count, maxBytes - result.count))
        if n > 0 {
            result.append(contentsOf: buf[0..<n])
        } else if n == 0 {
            break
        } else {
            if errno == EINTR { continue }
            bestEffortZero(&result)
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "read(fd=\(fd)) failed: errno=\(errno)"]
            )
        }
    }
    _ = Darwin.close(fd)
    return result
}

private var gTTYRestoreFD: Int32 = -1
private var gTTYOldTerm = termios()
private var gTTYNeedsRestore: sig_atomic_t = 0

private let ttySignalHandler: @convention(c) (Int32) -> Void = { sig in
    if gTTYNeedsRestore != 0 && gTTYRestoreFD >= 0 {
        var termCopy = gTTYOldTerm
        _ = tcsetattr(gTTYRestoreFD, TCSAFLUSH, &termCopy)
        _ = "\n".withCString { ptr in Darwin.write(gTTYRestoreFD, ptr, 1) }
    }
    Darwin._exit(128 + sig)
}

private func readSecretFromTTY(prompt: String) throws -> Data {
    let fd = Darwin.open("/dev/tty", O_RDWR)
    guard fd >= 0 else {
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "Could not open /dev/tty for interactive secret input"]
        )
    }
    defer { _ = Darwin.close(fd) }

    var oldTerm = termios()
    guard tcgetattr(fd, &oldTerm) == 0 else {
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "tcgetattr failed on /dev/tty"]
        )
    }
    gTTYRestoreFD = fd
    gTTYOldTerm = oldTerm
    gTTYNeedsRestore = 1
    let prevInt = signal(SIGINT, ttySignalHandler)
    let prevTerm = signal(SIGTERM, ttySignalHandler)

    var newTerm = oldTerm
    newTerm.c_lflag &= ~UInt(ECHO)
    guard tcsetattr(fd, TCSAFLUSH, &newTerm) == 0 else {
        gTTYNeedsRestore = 0
        signal(SIGINT, prevInt)
        signal(SIGTERM, prevTerm)
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "tcsetattr failed on /dev/tty"]
        )
    }
    defer {
        gTTYNeedsRestore = 0
        _ = tcsetattr(fd, TCSAFLUSH, &oldTerm)
        signal(SIGINT, prevInt)
        signal(SIGTERM, prevTerm)
        _ = prompt.withCString { _ in Darwin.write(fd, "\n", 1) }
    }

    _ = prompt.withCString { ptr in
        Darwin.write(fd, ptr, strlen(ptr))
    }

    var out = Data()
    var byte: UInt8 = 0
    defer { byte = 0 }
    while true {
        let n = Darwin.read(fd, &byte, 1)
        if n <= 0 { break }
        if byte == 0x0A || byte == 0x0D { break }
        out.append(byte)
    }
    return out
}

// MARK: - ECIES Envelope & Protected File Store

private struct SealedEnvelope: Codable {
    let version: Int
    let service: String
    let created_at: String
    let key_fingerprint: String
    let se_private_key_blob: String
    let ephemeral_public_key_x963: String
    let aes_gcm_combined: String
    let envelope_sha256: String
}

private struct EnvelopeStateRecord: Codable {
    let state: String
    let service: String
    let account: String
    let updated_at: String
}

private func computeEnvelopeDigest(
    version: Int,
    service: String,
    createdAt: String,
    keyFingerprint: String,
    sePrivateKeyBlob: String,
    ephemeralPublicKeyX963: String,
    aesGcmCombined: String
) -> String {
    let canonical =
        "\(version)\0\(service)\0\(createdAt)\0\(keyFingerprint)\0\(sePrivateKeyBlob)\0\(ephemeralPublicKeyX963)\0\(aesGcmCombined)"
    return sha256Hex(Data(canonical.utf8))
}

private func randomHexBytes(_ byteCount: Int) -> String {
    var bytes = [UInt8](repeating: 0, count: byteCount)
    _ = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
    defer {
        for idx in 0..<bytes.count { bytes[idx] = 0 }
    }
    return bytes.map { String(format: "%02x", $0) }.joined()
}

private func sealPayloadWithPublicKeyAndSecret(
    secret: Data,
    recipientPublicKeyX963: Data,
    service: String
) throws -> (ephemeralPubX963: Data, combinedCiphertext: Data, sharedSecret: SharedSecret) {
    let pubKey = try P256.KeyAgreement.PublicKey(x963Representation: recipientPublicKeyX963)
    let ephPriv = P256.KeyAgreement.PrivateKey()
    let ephPubData = ephPriv.publicKey.x963Representation
    let shared = try ephPriv.sharedSecretFromKeyAgreement(with: pubKey)
    let contextData = Data((kSharedInfoPrefix + service).utf8)
    let symKey = shared.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: ephPubData,
        sharedInfo: contextData,
        outputByteCount: 32
    )
    let sealedBox = try AES.GCM.seal(secret, using: symKey, authenticating: contextData)
    guard let combined = sealedBox.combined else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "AES.GCM.seal produced nil combined representation"]
        )
    }
    return (ephPubData, combined, shared)
}

private func sealPayloadWithPublicKey(
    secret: Data,
    recipientPublicKeyX963: Data,
    service: String
) throws -> (ephemeralPubX963: Data, combinedCiphertext: Data) {
    let (ephPubData, combined, _) = try sealPayloadWithPublicKeyAndSecret(
        secret: secret,
        recipientPublicKeyX963: recipientPublicKeyX963,
        service: service
    )
    return (ephPubData, combined)
}

private func unsealPayloadWithSharedSecret(
    sharedSecret: SharedSecret,
    ephemeralPubX963: Data,
    combinedCiphertext: Data,
    service: String
) throws -> Data {
    let contextData = Data((kSharedInfoPrefix + service).utf8)
    let symKey = sharedSecret.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: ephemeralPubX963,
        sharedInfo: contextData,
        outputByteCount: 32
    )
    let box = try AES.GCM.SealedBox(combined: combinedCiphertext)
    return try AES.GCM.open(box, using: symKey, authenticating: contextData)
}

private func ensureOwnedDirectoryComponent(
    path: String,
    createIfMissing: Bool,
    requireMode0700: Bool
) throws {
    let uid = geteuid()
    var st = stat()
    if Darwin.lstat(path, &st) != 0 {
        guard errno == ENOENT, createIfMissing else {
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "Envelope directory component missing or inaccessible: \(path)"]
            )
        }
        if Darwin.mkdir(path, 0o700) != 0 && errno != EEXIST {
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "mkdir(\(path)) failed with errno \(errno)"]
            )
        }
        guard Darwin.lstat(path, &st) == 0 else {
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "lstat(\(path)) failed after mkdir"]
            )
        }
    }
    if (st.st_mode & S_IFMT) == S_IFLNK {
        throw NSError(
            domain: "SEKeyProxy",
            code: 10,
            userInfo: [NSLocalizedDescriptionKey: "Refusing symlinked directory component: \(path)"]
        )
    }
    guard (st.st_mode & S_IFMT) == S_IFDIR else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 11,
            userInfo: [NSLocalizedDescriptionKey: "Expected directory at \(path)"]
        )
    }
    guard st.st_uid == uid else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 12,
            userInfo: [NSLocalizedDescriptionKey: "Directory \(path) must be owned by uid \(uid), got \(st.st_uid)"]
        )
    }
    if requireMode0700 && (st.st_mode & 0o077) != 0 {
        throw NSError(
            domain: "SEKeyProxy",
            code: 13,
            userInfo: [NSLocalizedDescriptionKey: "Directory \(path) must not have group/other permissions (mode=\(String(st.st_mode & 0o777, radix: 8)))"]
        )
    }
    if !requireMode0700 && (st.st_mode & 0o022) != 0 {
        throw NSError(
            domain: "SEKeyProxy",
            code: 14,
            userInfo: [NSLocalizedDescriptionKey: "Directory \(path) must not be group/world-writable"]
        )
    }
}

private func resolveEnvelopeDirectory(createIfMissing: Bool) throws -> String {
    #if SE_KEY_TESTING
    if let rawOverride = ProcessInfo.processInfo.environment["FREE_INFERENCE_SE_ENVELOPE_DIR"]?
        .trimmingCharacters(in: .whitespacesAndNewlines),
       !rawOverride.isEmpty {
        let segments = rawOverride.split(separator: "/", omittingEmptySubsequences: true)
        guard rawOverride.hasPrefix("/"), !segments.contains(".."), !segments.contains(".") else {
            throw NSError(
                domain: "SEKeyProxy",
                code: 15,
                userInfo: [NSLocalizedDescriptionKey: "FREE_INFERENCE_SE_ENVELOPE_DIR must be an absolute normalized path"]
            )
        }
        let cleanOverride = "/" + segments.joined(separator: "/")
        try ensureOwnedDirectoryComponent(
            path: cleanOverride,
            createIfMissing: createIfMissing,
            requireMode0700: true
        )
        return cleanOverride
    }
    #endif

    let uid = geteuid()
    guard let pw = getpwuid(uid), let pwDirPtr = pw.pointee.pw_dir else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 16,
            userInfo: [NSLocalizedDescriptionKey: "Could not resolve user home directory via getpwuid(\(uid))"]
        )
    }
    let homeRaw = String(cString: pwDirPtr)
    let homeSegments = homeRaw.split(separator: "/", omittingEmptySubsequences: true)
    guard homeRaw.hasPrefix("/"), !homeSegments.isEmpty, !homeSegments.contains(".."), !homeSegments.contains(".") else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 17,
            userInfo: [NSLocalizedDescriptionKey: "Invalid user home directory from getpwuid: \(homeRaw)"]
        )
    }
    let homeDir = "/" + homeSegments.joined(separator: "/")
    try ensureOwnedDirectoryComponent(path: homeDir, createIfMissing: false, requireMode0700: false)
    let dotConfig = homeDir + "/.config"
    try ensureOwnedDirectoryComponent(path: dotConfig, createIfMissing: createIfMissing, requireMode0700: false)
    let freeInfDir = dotConfig + "/free-inference"
    try ensureOwnedDirectoryComponent(path: freeInfDir, createIfMissing: createIfMissing, requireMode0700: true)
    let envDir = freeInfDir + "/se-envelopes"
    try ensureOwnedDirectoryComponent(path: envDir, createIfMissing: createIfMissing, requireMode0700: true)
    return envDir
}

private func envelopeStem(service: String, account: String) -> String {
    return sha256Hex(Data((service + "\0" + account).utf8))
}

private func fsyncDirectory(_ dirPath: String, context: String) throws {
    let dirFD = Darwin.open(dirPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard dirFD >= 0 else {
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [
                NSLocalizedDescriptionKey:
                    "partial publication (\(context)): failed to open directory '\(dirPath)' for fsync (errno \(errno))"
            ]
        )
    }
    defer { _ = Darwin.close(dirFD) }
    #if SE_KEY_TESTING
    if ProcessInfo.processInfo.environment["SE_KEY_TEST_FAIL_FSYNC_DIR"] == "1" {
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(EIO),
            userInfo: [
                NSLocalizedDescriptionKey:
                    "partial publication (\(context)): simulated directory fsync failure on '\(dirPath)' after filesystem update"
            ]
        )
    }
    #endif
    guard Darwin.fsync(dirFD) == 0 else {
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [
                NSLocalizedDescriptionKey:
                    "partial publication (\(context)): directory fsync failed on '\(dirPath)' after filesystem update (errno \(errno))"
            ]
        )
    }
}

private func readOwnedRegularFile0600(path: String) throws -> Data {
    let uid = geteuid()
    let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW)
    guard fd >= 0 else {
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "Could not open file '\(path)' (errno \(errno))"]
        )
    }
    defer { _ = Darwin.close(fd) }

    var st = stat()
    guard Darwin.fstat(fd, &st) == 0 else {
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "fstat failed on '\(path)' (errno \(errno))"]
        )
    }
    guard (st.st_mode & S_IFMT) == S_IFREG else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 18,
            userInfo: [NSLocalizedDescriptionKey: "Refusing non-regular file '\(path)'"]
        )
    }
    guard st.st_uid == uid else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 19,
            userInfo: [NSLocalizedDescriptionKey: "File '\(path)' must be owned by uid \(uid), got \(st.st_uid)"]
        )
    }
    guard (st.st_mode & 0o077) == 0 else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 20,
            userInfo: [NSLocalizedDescriptionKey: "File '\(path)' must have 0600 permissions (got mode \(String(st.st_mode & 0o777, radix: 8)))"]
        )
    }
    guard st.st_size >= 0 && st.st_size <= 65536 else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 21,
            userInfo: [NSLocalizedDescriptionKey: "File '\(path)' exceeds maximum envelope size"]
        )
    }

    var result = Data()
    var buf = [UInt8](repeating: 0, count: 4096)
    while true {
        let n = Darwin.read(fd, &buf, buf.count)
        if n > 0 {
            result.append(contentsOf: buf[0..<n])
        } else if n == 0 {
            break
        } else {
            if errno == EINTR { continue }
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "read failed on '\(path)' (errno \(errno))"]
            )
        }
    }
    return result
}

private func writeStageFile0600(dir: String, prefix: String, data: Data) throws -> String {
    let tmpPath = "\(dir)/.\(prefix)-\(getpid())-\(randomHexBytes(8)).tmp"
    let fd = Darwin.open(tmpPath, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0o600)
    guard fd >= 0 else {
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "Failed to create staging file '\(tmpPath)' (errno \(errno))"]
        )
    }
    var ok = false
    defer {
        if fd >= 0 {
            _ = Darwin.close(fd)
        }
        if !ok {
            _ = Darwin.unlink(tmpPath)
        }
    }
    guard Darwin.fchmod(fd, 0o600) == 0 else {
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "fchmod(0600) failed on '\(tmpPath)'"]
        )
    }
    guard writeAllToFD(fd, data: data) else {
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "Failed writing bytes to '\(tmpPath)'"]
        )
    }
    guard Darwin.fsync(fd) == 0 else {
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "fsync failed on '\(tmpPath)'"]
        )
    }
    ok = true
    return tmpPath
}

private func ensureDestinationNotSymlink(path: String) throws {
    var st = stat()
    if Darwin.lstat(path, &st) == 0 {
        if (st.st_mode & S_IFMT) == S_IFLNK || (st.st_mode & S_IFMT) != S_IFREG {
            throw NSError(
                domain: "SEKeyProxy",
                code: 22,
                userInfo: [NSLocalizedDescriptionKey: "Refusing non-regular or symlinked destination file '\(path)'"]
            )
        }
    } else if errno != ENOENT {
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "lstat failed on '\(path)' (errno \(errno))"]
        )
    }
}

private func atomicPublishStageFile(dir: String, stagePath: String, targetPath: String) throws {
    try ensureDestinationNotSymlink(path: targetPath)
    guard Darwin.rename(stagePath, targetPath) == 0 else {
        _ = Darwin.unlink(stagePath)
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "rename('\(stagePath)' -> '\(targetPath)') failed (errno \(errno))"]
        )
    }
    try fsyncDirectory(dir, context: "renamed '\(stagePath)' -> '\(targetPath)'")
}

private func withStemLock<T>(dir: String, stem: String, body: () throws -> T) throws -> T {
    let lockPath = "\(dir)/\(stem).lock"
    let fd = Darwin.open(lockPath, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
    guard fd >= 0 else {
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "Could not open lock file '\(lockPath)' (errno \(errno))"]
        )
    }
    defer { _ = Darwin.close(fd) }

    var st = stat()
    guard Darwin.fstat(fd, &st) == 0,
          (st.st_mode & S_IFMT) == S_IFREG,
          st.st_uid == geteuid(),
          (st.st_mode & 0o077) == 0 else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 23,
            userInfo: [NSLocalizedDescriptionKey: "Lock file '\(lockPath)' failed ownership or 0600 mode check"]
        )
    }

    while true {
        if flock(fd, LOCK_EX) == 0 {
            break
        }
        if errno == EINTR {
            continue
        }
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "flock(LOCK_EX) failed on '\(lockPath)' (errno \(errno))"]
        )
    }
    defer { _ = flock(fd, LOCK_UN) }
    return try body()
}

private func optionalFileSHA256(path: String) throws -> String? {
    var st = stat()
    if Darwin.lstat(path, &st) != 0 {
        if errno == ENOENT {
            return nil
        }
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "lstat failed on '\(path)' (errno \(errno))"]
        )
    }
    let data = try readOwnedRegularFile0600(path: path)
    return sha256Hex(data)
}

private func readStemSnapshot(dir: String, stem: String) throws -> (envSha: String?, stateSha: String?) {
    let envPath = "\(dir)/\(stem).json"
    let statePath = "\(dir)/\(stem).state.json"
    return (
        try optionalFileSHA256(path: envPath),
        try optionalFileSHA256(path: statePath)
    )
}

private func loadStateRecord(dir: String, stem: String) throws -> EnvelopeStateRecord? {
    let statePath = "\(dir)/\(stem).state.json"
    var st = stat()
    if Darwin.lstat(statePath, &st) != 0 {
        if errno == ENOENT {
            return nil
        }
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "lstat failed on '\(statePath)'"]
        )
    }
    let data = try readOwnedRegularFile0600(path: statePath)
    return try JSONDecoder().decode(EnvelopeStateRecord.self, from: data)
}

private func writeStateRecord(
    dir: String,
    stem: String,
    state: String,
    service: String,
    account: String,
    updatedAt: String
) throws {
    let rec = EnvelopeStateRecord(
        state: state,
        service: service,
        account: account,
        updated_at: updatedAt
    )
    let bytes = try JSONEncoder().encode(rec)
    let stage = try writeStageFile0600(dir: dir, prefix: "state-\(stem)", data: bytes)
    try atomicPublishStageFile(dir: dir, stagePath: stage, targetPath: "\(dir)/\(stem).state.json")
}

private func verifySEPKeyBlobNonInteractive(seBlob: Data, ephemeralPubKey: P256.KeyAgreement.PublicKey) throws {
    guard SecureEnclave.isAvailable else { return }
    let nonInteractiveCtx = LAContext()
    nonInteractiveCtx.interactionNotAllowed = true
    nonInteractiveCtx.touchIDAuthenticationAllowableReuseDuration = 0

    let allowedBlockDomainCodes: [(domain: String, code: Int)] = [
        ("com.apple.LocalAuthentication", -1004),
        (NSOSStatusErrorDomain, -25308),
        (NSOSStatusErrorDomain, -25293),
    ]
    do {
        let loadedKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: seBlob,
            authenticationContext: nonInteractiveCtx
        )
        _ = try loadedKey.sharedSecretFromKeyAgreement(with: ephemeralPubKey)
        throw NSError(
            domain: "SEKeyProxy",
            code: 24,
            userInfo: [NSLocalizedDescriptionKey: "Secure Enclave key unsealed with interactionNotAllowed=true"]
        )
    } catch {
        let chain = extractUnderlyingErrorCodes(error)
        let matched = chain.contains { item in
            allowedBlockDomainCodes.contains { $0.domain == item.domain && $0.code == item.code }
        }
        guard matched else {
            throw NSError(
                domain: "SEKeyProxy",
                code: 25,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "Secure Enclave key blob failed non-interactive recognition: \(error.localizedDescription)"
                ]
            )
        }
    }
}

private func loadAndValidateEnvelopeFromPath(
    path: String,
    expectedService: String,
    checkSEPNonInteractive: Bool
) throws -> SealedEnvelope {
    let data = try readOwnedRegularFile0600(path: path)
    let env = try JSONDecoder().decode(SealedEnvelope.self, from: data)
    guard env.version == kEnvelopeVersion, env.service == expectedService else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 26,
            userInfo: [NSLocalizedDescriptionKey: "Envelope version or service mismatch for '\(expectedService)'"]
        )
    }
    let expectedDigest = computeEnvelopeDigest(
        version: env.version,
        service: env.service,
        createdAt: env.created_at,
        keyFingerprint: env.key_fingerprint,
        sePrivateKeyBlob: env.se_private_key_blob,
        ephemeralPublicKeyX963: env.ephemeral_public_key_x963,
        aesGcmCombined: env.aes_gcm_combined
    )
    guard constantTimeEquals(Data(env.envelope_sha256.utf8), Data(expectedDigest.utf8)) else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 27,
            userInfo: [NSLocalizedDescriptionKey: "Envelope integrity digest mismatch for '\(expectedService)'"]
        )
    }
    guard
        let seBlob = Data(base64Encoded: env.se_private_key_blob), !seBlob.isEmpty,
        let ephPubData = Data(base64Encoded: env.ephemeral_public_key_x963),
        let ephPubKey = try? P256.KeyAgreement.PublicKey(x963Representation: ephPubData),
        let combined = Data(base64Encoded: env.aes_gcm_combined), combined.count > 28
    else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 28,
            userInfo: [NSLocalizedDescriptionKey: "Envelope cryptographic fields failed validation for '\(expectedService)'"]
        )
    }
    if checkSEPNonInteractive {
        try verifySEPKeyBlobNonInteractive(seBlob: seBlob, ephemeralPubKey: ephPubKey)
    }
    return env
}

private func loadEnvelope(
    service: String,
    account: String,
    checkSEPNonInteractive: Bool = false
) throws -> SealedEnvelope {
    let dir = try resolveEnvelopeDirectory(createIfMissing: false)
    let stem = envelopeStem(service: service, account: account)
    let envPath = "\(dir)/\(stem).json"
    return try loadAndValidateEnvelopeFromPath(
        path: envPath,
        expectedService: service,
        checkSEPNonInteractive: checkSEPNonInteractive
    )
}

private func sealAndPublishEnvelopeLocked(
    dir: String,
    stem: String,
    service: String,
    account: String,
    secretData: Data,
    stateLabel: String
) throws -> SealedEnvelope {
    var cfErr: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet],
        &cfErr
    ) else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 29,
            userInfo: [NSLocalizedDescriptionKey: "SecAccessControlCreateWithFlags failed: \(String(describing: cfErr))"]
        )
    }

    let sePriv = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
    let pubX963 = sePriv.publicKey.x963Representation
    let keyFingerprint = String(sha256Hex(pubX963).prefix(16))

    let (ephPub, combined, sharedSecret) = try sealPayloadWithPublicKeyAndSecret(
        secret: secretData,
        recipientPublicKeyX963: pubX963,
        service: service
    )

    let createdAt = isoNow()
    let seBlobB64 = sePriv.dataRepresentation.base64EncodedString()
    let ephPubB64 = ephPub.base64EncodedString()
    let combinedB64 = combined.base64EncodedString()
    let digest = computeEnvelopeDigest(
        version: kEnvelopeVersion,
        service: service,
        createdAt: createdAt,
        keyFingerprint: keyFingerprint,
        sePrivateKeyBlob: seBlobB64,
        ephemeralPublicKeyX963: ephPubB64,
        aesGcmCombined: combinedB64
    )
    let envelope = SealedEnvelope(
        version: kEnvelopeVersion,
        service: service,
        created_at: createdAt,
        key_fingerprint: keyFingerprint,
        se_private_key_blob: seBlobB64,
        ephemeral_public_key_x963: ephPubB64,
        aes_gcm_combined: combinedB64,
        envelope_sha256: digest
    )
    let envelopeBytes = try JSONEncoder().encode(envelope)
    let stagePath = try writeStageFile0600(dir: dir, prefix: "env-\(stem)", data: envelopeBytes)

    do {
        let readBack = try loadAndValidateEnvelopeFromPath(
            path: stagePath,
            expectedService: service,
            checkSEPNonInteractive: true
        )
        guard
            let rbEphPub = Data(base64Encoded: readBack.ephemeral_public_key_x963),
            let rbCombined = Data(base64Encoded: readBack.aes_gcm_combined)
        else {
            throw NSError(
                domain: "SEKeyProxy",
                code: 30,
                userInfo: [NSLocalizedDescriptionKey: "Read-back envelope missing ciphertext fields"]
            )
        }
        var openedReadBack = try unsealPayloadWithSharedSecret(
            sharedSecret: sharedSecret,
            ephemeralPubX963: rbEphPub,
            combinedCiphertext: rbCombined,
            service: service
        )
        defer { bestEffortZero(&openedReadBack) }
        guard constantTimeEquals(openedReadBack, secretData) else {
            throw NSError(
                domain: "SEKeyProxy",
                code: 31,
                userInfo: [NSLocalizedDescriptionKey: "Read-back authenticated decryption mismatch"]
            )
        }
    } catch {
        _ = Darwin.unlink(stagePath)
        throw error
    }

    let targetPath = "\(dir)/\(stem).json"
    try atomicPublishStageFile(dir: dir, stagePath: stagePath, targetPath: targetPath)
    try writeStateRecord(
        dir: dir,
        stem: stem,
        state: stateLabel,
        service: service,
        account: account,
        updatedAt: createdAt
    )
    return envelope
}

private func deleteEnvelope(service: String, account: String) throws -> Bool {
    let dir = try resolveEnvelopeDirectory(createIfMissing: true)
    let stem = envelopeStem(service: service, account: account)
    return try withStemLock(dir: dir, stem: stem) {
        let envPath = "\(dir)/\(stem).json"
        try ensureDestinationNotSymlink(path: envPath)
        var existed = false
        if Darwin.unlink(envPath) == 0 {
            existed = true
        } else if errno != ENOENT {
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "unlink('\(envPath)') failed (errno \(errno))"]
            )
        }
        try writeStateRecord(
            dir: dir,
            stem: stem,
            state: "deleted",
            service: service,
            account: account,
            updatedAt: isoNow()
        )
        try fsyncDirectory(dir, context: "unlinked '\(envPath)' and wrote deleted tombstone")
        return existed
    }
}

// MARK: - Strict Top-Level JSON Key Counter

private func countTopLevelKeyOccurrences(in data: Data, targetKey: String) -> Int? {
    guard let text = String(data: data, encoding: .utf8) else {
        return nil
    }
    let chars = Array(text.unicodeScalars)
    let n = chars.count
    var i = 0

    func skipWhitespace() {
        while i < n {
            let c = chars[i].value
            if c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D {
                i += 1
            } else {
                break
            }
        }
    }

    func parseJSONString() -> String? {
        guard i < n, chars[i] == "\"" else { return nil }
        i += 1
        var out = String.UnicodeScalarView()
        while i < n {
            let ch = chars[i]
            i += 1
            if ch == "\"" {
                return String(out)
            }
            if ch == "\\" {
                guard i < n else { return nil }
                let esc = chars[i]
                i += 1
                switch esc {
                case "\"", "\\", "/": out.append(esc)
                case "b": out.append(UnicodeScalar(0x08)!)
                case "f": out.append(UnicodeScalar(0x0C)!)
                case "n": out.append(UnicodeScalar(0x0A)!)
                case "r": out.append(UnicodeScalar(0x0D)!)
                case "t": out.append(UnicodeScalar(0x09)!)
                case "u":
                    guard i + 4 <= n else { return nil }
                    let hexStr = String(String.UnicodeScalarView(chars[i..<(i + 4)]))
                    guard hexStr.allSatisfy({ $0.isHexDigit }),
                          let code = UInt32(hexStr, radix: 16) else {
                        return nil
                    }
                    i += 4
                    if code >= 0xD800 && code <= 0xDBFF {
                        guard i + 6 <= n, chars[i] == "\\", chars[i + 1] == "u" else {
                            return nil
                        }
                        let lowHex = String(String.UnicodeScalarView(chars[(i + 2)..<(i + 6)]))
                        guard lowHex.allSatisfy({ $0.isHexDigit }),
                              let low = UInt32(lowHex, radix: 16), low >= 0xDC00 && low <= 0xDFFF else {
                            return nil
                        }
                        i += 6
                        let combined = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                        guard let scalar = UnicodeScalar(combined) else { return nil }
                        out.append(scalar)
                    } else if code >= 0xDC00 && code <= 0xDFFF {
                        return nil
                    } else {
                        guard let scalar = UnicodeScalar(code) else { return nil }
                        out.append(scalar)
                    }
                default:
                    return nil
                }
            } else {
                guard ch.value >= 0x20 else { return nil }
                out.append(ch)
            }
        }
        return nil
    }

    skipWhitespace()
    guard i < n, chars[i] == "{" else { return nil }
    i += 1
    var depth = 1
    var expectingKeyAtTopLevel = true
    var matches = 0

    while i < n && depth > 0 {
        skipWhitespace()
        if i >= n { break }
        let ch = chars[i]
        if ch == "\"" {
            guard let strVal = parseJSONString() else { return nil }
            if depth == 1 && expectingKeyAtTopLevel {
                skipWhitespace()
                guard i < n, chars[i] == ":" else { return nil }
                i += 1
                if strVal == targetKey {
                    matches += 1
                }
                expectingKeyAtTopLevel = false
            }
        } else if ch == "{" || ch == "[" {
            depth += 1
            i += 1
        } else if ch == "}" || ch == "]" {
            depth -= 1
            i += 1
        } else if ch == "," {
            if depth == 1 {
                expectingKeyAtTopLevel = true
            }
            i += 1
        } else {
            i += 1
        }
    }
    return depth == 0 ? matches : nil
}

// MARK: - Streaming Upstream Delegate

private func httpStatusReasonPhrase(_ status: Int) -> String {
    switch status {
    case 200: return "OK"
    case 201: return "Created"
    case 204: return "No Content"
    case 400: return "Bad Request"
    case 401: return "Unauthorized"
    case 403: return "Forbidden"
    case 404: return "Not Found"
    case 411: return "Length Required"
    case 413: return "Payload Too Large"
    case 422: return "Unprocessable Entity"
    case 429: return "Too Many Requests"
    case 500: return "Internal Server Error"
    case 502: return "Bad Gateway"
    case 503: return "Service Unavailable"
    case 504: return "Gateway Timeout"
    default:
        let localized = HTTPURLResponse.localizedString(forStatusCode: status)
        return localized.isEmpty ? "Status" : localized.capitalized
    }
}

private func setNonBlocking(_ fd: Int32) {
    let flags = fcntl(fd, F_GETFL, 0)
    if flags >= 0 {
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
    }
    var noSigPipe: Int32 = 1
    _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
}

private struct UpstreamProcessBinding {
    let pid: pid_t
    let port: UInt16
    let startSec: UInt64
    let startUsec: UInt64
    let listenPCB: UInt64
}

private func inspectUpstreamProcess(
    pid: pid_t,
    port: UInt16
) -> (startSec: UInt64, startUsec: UInt64, listenPCB: UInt64)? {
    guard pid > 1 else { return nil }
    var bsdInfo = proc_bsdinfo()
    let bsdSize = proc_pidinfo(
        pid,
        PROC_PIDTBSDINFO,
        0,
        &bsdInfo,
        Int32(MemoryLayout<proc_bsdinfo>.size)
    )
    guard bsdSize == Int32(MemoryLayout<proc_bsdinfo>.size),
          bsdInfo.pbi_status != UInt32(SZOMB) else {
        return nil
    }

    let byteCount = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
    guard byteCount > 0 else { return nil }
    let count = Int(byteCount) / MemoryLayout<proc_fdinfo>.size + 16
    var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: count)
    let actualBytes = proc_pidinfo(
        pid,
        PROC_PIDLISTFDS,
        0,
        &fds,
        Int32(count * MemoryLayout<proc_fdinfo>.size)
    )
    guard actualBytes > 0 else { return nil }
    let actualCount = Int(actualBytes) / MemoryLayout<proc_fdinfo>.size

    let expectedLoopback = inet_addr("127.0.0.1")
    var matchedPCB: UInt64? = nil
    for i in 0..<actualCount where fds[i].proc_fdtype == PROX_FDTYPE_SOCKET {
        var sinfo = socket_fdinfo()
        let sz = proc_pidfdinfo(
            pid,
            fds[i].proc_fd,
            PROC_PIDFDSOCKETINFO,
            &sinfo,
            Int32(MemoryLayout<socket_fdinfo>.size)
        )
        guard sz == Int32(MemoryLayout<socket_fdinfo>.size) else { continue }
        guard sinfo.psi.soi_kind == SOCKINFO_TCP else { continue }
        let tcp = sinfo.psi.soi_proto.pri_tcp
        guard tcp.tcpsi_state == TSI_S_LISTEN else { continue }
        let lport = UInt16(bigEndian: UInt16(truncatingIfNeeded: tcp.tcpsi_ini.insi_lport))
        guard lport == port else { continue }
        let laddr = tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr
        guard laddr == expectedLoopback else { continue }
        // Reject listeners that set SO_REUSEPORT, since another process could share the port.
        if (Int32(sinfo.psi.soi_options) & Int32(SO_REUSEPORT)) != 0 {
            return nil
        }
        if sinfo.psi.soi_pcb != 0 {
            matchedPCB = sinfo.psi.soi_pcb
        }
    }
    guard let pcb = matchedPCB else { return nil }
    return (bsdInfo.pbi_start_tvsec, bsdInfo.pbi_start_tvusec, pcb)
}

private func verifyUpstreamBinding(_ binding: UpstreamProcessBinding) -> Bool {
    guard let info = inspectUpstreamProcess(pid: binding.pid, port: binding.port) else {
        return false
    }
    return (
        info.startSec == binding.startSec
        && info.startUsec == binding.startUsec
        && info.listenPCB == binding.listenPCB
    )
}

private func waitForUpstreamBinding(
    pid: pid_t,
    port: UInt16,
    timeoutSeconds: Double
) -> UpstreamProcessBinding? {
    let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(max(0.1, timeoutSeconds) * 1_000_000_000)
    while DispatchTime.now().uptimeNanoseconds < deadline {
        var bsdInfo = proc_bsdinfo()
        let bsdSize = proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            &bsdInfo,
            Int32(MemoryLayout<proc_bsdinfo>.size)
        )
        if bsdSize != Int32(MemoryLayout<proc_bsdinfo>.size) || bsdInfo.pbi_status == UInt32(SZOMB) {
            return nil
        }
        if let info = inspectUpstreamProcess(pid: pid, port: port) {
            return UpstreamProcessBinding(
                pid: pid,
                port: port,
                startSec: info.startSec,
                startUsec: info.startUsec,
                listenPCB: info.listenPCB
            )
        }
        if kill(pid, 0) != 0 && errno == ESRCH {
            return nil
        }
        usleep(25_000)
    }
    return nil
}

private func remainingConnectSliceMs(nowNs: UInt64, connectLimitNs: UInt64) -> Int32? {
    if nowNs >= connectLimitNs {
        return nil
    }
    let remMs = (connectLimitNs - nowNs) / 1_000_000
    return Int32(min(100, max(1, remMs)))
}

// MARK: - Live Usage Metering, Exact 128-Bit Accounting, and Capacity-Bounded Raw Buffers

private let kMaxChatRequestsLimit = 2_147_483_647
private let kMaxPerRequestTokens: Int64 = 1_000_000_000
private let kMaxCumulativeTokens: Int64 = 1_000_000_000_000
private let kMaxWireMicroUsd: Int64 = 100_000_000_000_000
private let kMaxActualMicroUsdLimit: Int64 = 100_000_000_000
private let kMaxPriceMicroUsdPerM: Int64 = 10_000_000_000
private let kMaxTotalObserverBytes = 2_097_152
private let kMaxUsageJSONBodyBytes = 524_288
private let kMaxUsageSSELineBytes = 65_536
private let kMaxUsageSSEEventBytes = 65_536
private let kMaxOuterJSONScanDepth = 64
private let kMaxUsageJSONScanDepth = 8

private struct PricingRates {
    let inputMicroPerM: Int64
    let outputMicroPerM: Int64
    let cachedInputMicroPerM: Int64
}

private struct ParsedTokenUsage: Equatable {
    let promptTokens: Int64
    let cachedPromptTokens: Int64
    let completionTokens: Int64
}

private enum UsageScanState: Equatable {
    case missing
    case nullValue
    case valid(ParsedTokenUsage)
    case invalid
}

private struct UInt128Pair: Equatable, Comparable {
    let hi: UInt64
    let lo: UInt64

    static let zero = UInt128Pair(hi: 0, lo: 0)
    static let max = UInt128Pair(hi: UInt64.max, lo: UInt64.max)

    static func < (lhs: UInt128Pair, rhs: UInt128Pair) -> Bool {
        if lhs.hi != rhs.hi { return lhs.hi < rhs.hi }
        return lhs.lo < rhs.lo
    }

    static func mul64(_ a: UInt64, _ b: UInt64) -> UInt128Pair {
        let p = a.multipliedFullWidth(by: b)
        return UInt128Pair(hi: p.high, lo: p.low)
    }

    func addingClamped(_ other: UInt128Pair) -> UInt128Pair {
        let (loSum, carryLo) = lo.addingReportingOverflow(other.lo)
        let (hiPart, carryHi1) = hi.addingReportingOverflow(other.hi)
        if carryHi1 { return .max }
        let (hiSum, carryHi2) = hiPart.addingReportingOverflow(carryLo ? 1 : 0)
        if carryHi2 { return .max }
        return UInt128Pair(hi: hiSum, lo: loSum)
    }

    func divMod1000000() -> (quotient: UInt128Pair, remainder: UInt64) {
        let divisor: UInt64 = 1_000_000
        var qHi: UInt64 = 0
        var qLo: UInt64 = 0
        var rem: UInt64 = 0
        for bit in stride(from: 63, through: 0, by: -1) {
            rem = (rem << 1) | ((hi >> bit) & 1)
            if rem >= divisor {
                rem -= divisor
                qHi |= (UInt64(1) << bit)
            }
        }
        for bit in stride(from: 63, through: 0, by: -1) {
            rem = (rem << 1) | ((lo >> bit) & 1)
            if rem >= divisor {
                rem -= divisor
                qLo |= (UInt64(1) << bit)
            }
        }
        return (UInt128Pair(hi: qHi, lo: qLo), rem)
    }

    func clampedInt64(max maxVal: Int64) -> Int64 {
        let limit = UInt64(maxVal)
        if hi > 0 || lo >= limit {
            return maxVal
        }
        return Int64(lo)
    }
}

private func parseDecimalMicroUsd(_ raw: String, minMicro: Int64, maxMicro: Int64) -> Int64? {
    let bytes = Array(raw.utf8)
    guard !bytes.isEmpty && bytes.count <= 32 else { return nil }
    var intDigits = 0
    var fracDigits = 0
    var seenDot = false
    var intPart: Int64 = 0
    var fracPart: Int64 = 0
    for b in bytes {
        if b == 0x2E { // '.'
            if seenDot || intDigits == 0 { return nil }
            seenDot = true
        } else if b >= 0x30 && b <= 0x39 {
            let d = Int64(b - 0x30)
            if !seenDot {
                intDigits += 1
                if intDigits > 6 { return nil }
                intPart = intPart * 10 + d
            } else {
                fracDigits += 1
                if fracDigits > 6 { return nil }
                fracPart = fracPart * 10 + d
            }
        } else {
            return nil
        }
    }
    if intDigits == 0 || (seenDot && fracDigits == 0) {
        return nil
    }
    var scale: Int64 = 1
    for _ in 0..<(6 - fracDigits) {
        scale *= 10
    }
    let total = intPart * 1_000_000 + fracPart * scale
    guard total >= minMicro && total <= maxMicro else { return nil }
    return total
}

private func formatMicroUsdForMessage(_ micro: Int64) -> String {
    let whole = micro / 1_000_000
    let frac = micro % 1_000_000
    if frac == 0 {
        return String(format: "$%lld.00", whole)
    }
    let fracStr = String(format: "%06lld", frac)
    var trimmed = fracStr
    while trimmed.count > 2 && trimmed.hasSuffix("0") {
        trimmed.removeLast()
    }
    return "$\(whole).\(trimmed)"
}

private func saturatingAddToken(_ cur: Int64, _ delta: Int64, cap: Int64 = kMaxCumulativeTokens) -> Int64 {
    if delta <= 0 { return cur }
    if cur >= cap { return cap }
    let room = cap - cur
    return delta >= room ? cap : (cur + delta)
}

private final class ObserverMemoryPool: @unchecked Sendable {
    private let lock = NSLock()
    let limitBytes: Int
    private var currentBytes: Int = 0
    private var peakBytes: Int = 0

    init(limitBytes: Int = kMaxTotalObserverBytes) {
        self.limitBytes = max(0, limitBytes)
    }

    func reserve(_ bytes: Int) -> Bool {
        if bytes < 0 { return false }
        if bytes == 0 { return true }
        lock.lock()
        defer { lock.unlock() }
        guard bytes <= limitBytes - currentBytes else { return false }
        currentBytes += bytes
        if currentBytes > peakBytes {
            peakBytes = currentBytes
        }
        return true
    }

    func release(_ bytes: Int) {
        if bytes <= 0 { return }
        lock.lock()
        currentBytes = max(0, currentBytes - bytes)
        lock.unlock()
    }

    func stats() -> (current: Int, peak: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (currentBytes, peakBytes)
    }
}

private final class OwnedRawBuffer {
    private let pool: ObserverMemoryPool
    let maxBytes: Int
    private var buf: UnsafeMutableBufferPointer<UInt8>? = nil
    private(set) var capacity: Int = 0
    private(set) var count: Int = 0

    init(pool: ObserverMemoryPool, maxBytes: Int) {
        self.pool = pool
        self.maxBytes = maxBytes
    }

    deinit {
        free()
    }

    func append(bytes ptr: UnsafePointer<UInt8>, length n: Int) -> Bool {
        if n <= 0 { return true }
        guard n <= maxBytes - count else { return false }
        let needed = count + n
        if needed > capacity {
            let doubled = capacity > 0 ? (capacity <= maxBytes / 2 ? capacity * 2 : maxBytes) : 256
            let newCap = min(maxBytes, max(needed, doubled))
            // Reserve full replacement capacity WHILE old capacity remains charged to the pool.
            guard pool.reserve(newCap) else { return false }
            let newBuf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: newCap)
            if let oldBuf = buf, let oldBase = oldBuf.baseAddress, let newBase = newBuf.baseAddress {
                if count > 0 {
                    newBase.initialize(from: oldBase, count: count)
                    memset(oldBase, 0, count)
                }
                let oldCap = capacity
                oldBuf.deallocate()
                buf = newBuf
                capacity = newCap
                pool.release(oldCap)
            } else {
                buf = newBuf
                capacity = newCap
            }
        }
        guard let dstBase = buf?.baseAddress else { return false }
        dstBase.advanced(by: count).initialize(from: ptr, count: n)
        count += n
        return true
    }

    func appendByte(_ byte: UInt8) -> Bool {
        var b = byte
        return withUnsafePointer(to: &b) { ptr in
            append(bytes: ptr, length: 1)
        }
    }

    func withReadOnlyBytes<T>(_ body: (UnsafeBufferPointer<UInt8>) -> T) -> T {
        if let rawBuf = buf, let base = rawBuf.baseAddress, count > 0 {
            return body(UnsafeBufferPointer(start: base, count: count))
        }
        return body(UnsafeBufferPointer(start: nil, count: 0))
    }

    func free() {
        guard let oldBuf = buf else {
            count = 0
            capacity = 0
            return
        }
        if let base = oldBuf.baseAddress, count > 0 {
            memset(base, 0, count)
        }
        let oldCap = capacity
        buf = nil
        capacity = 0
        count = 0
        oldBuf.deallocate()
        pool.release(oldCap)
    }
}

// Fixed 64-byte stack-only key buffer for zero-allocation JSON key matching.
private struct StackKey64 {
    var b0: UInt64 = 0; var b1: UInt64 = 0; var b2: UInt64 = 0; var b3: UInt64 = 0
    var b4: UInt64 = 0; var b5: UInt64 = 0; var b6: UInt64 = 0; var b7: UInt64 = 0
    var count: Int = 0
    var overflowed: Bool = false

    mutating func append(_ byte: UInt8) {
        guard count < 64 else {
            overflowed = true
            return
        }
        let word = count >> 3
        let shift = (count & 7) << 3
        let val = UInt64(byte) << shift
        switch word {
        case 0: b0 |= val
        case 1: b1 |= val
        case 2: b2 |= val
        case 3: b3 |= val
        case 4: b4 |= val
        case 5: b5 |= val
        case 6: b6 |= val
        default: b7 |= val
        }
        count += 1
    }

    mutating func appendUTF8(scalar: UInt32) {
        if scalar <= 0x7F {
            append(UInt8(scalar))
        } else if scalar <= 0x7FF {
            append(UInt8(0xC0 | (scalar >> 6)))
            append(UInt8(0x80 | (scalar & 0x3F)))
        } else if scalar <= 0xFFFF {
            append(UInt8(0xE0 | (scalar >> 12)))
            append(UInt8(0x80 | ((scalar >> 6) & 0x3F)))
            append(UInt8(0x80 | (scalar & 0x3F)))
        } else {
            append(UInt8(0xF0 | (scalar >> 18)))
            append(UInt8(0x80 | ((scalar >> 12) & 0x3F)))
            append(UInt8(0x80 | ((scalar >> 6) & 0x3F)))
            append(UInt8(0x80 | (scalar & 0x3F)))
        }
    }

    func byte(at index: Int) -> UInt8 {
        let word = index >> 3
        let shift = (index & 7) << 3
        let w: UInt64
        switch word {
        case 0: w = b0
        case 1: w = b1
        case 2: w = b2
        case 3: w = b3
        case 4: w = b4
        case 5: w = b5
        case 6: w = b6
        default: w = b7
        }
        return UInt8((w >> shift) & 0xFF)
    }

    func equalsASCII(_ s: StaticString) -> Bool {
        if overflowed { return false }
        let n = s.utf8CodeUnitCount
        if count != n { return false }
        return s.withUTF8Buffer { ptr in
            for i in 0..<n {
                if byte(at: i) != ptr[i] { return false }
            }
            return true
        }
    }
}

private struct LexicalJSONUsageScanner {
    let bytes: UnsafeBufferPointer<UInt8>
    var pos: Int = 0

    mutating func skipWS() {
        while pos < bytes.count {
            let b = bytes[pos]
            if b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D {
                pos += 1
            } else {
                break
            }
        }
    }

    mutating func parseHex4() -> UInt16? {
        guard pos + 4 <= bytes.count else { return nil }
        var acc: UInt16 = 0
        for _ in 0..<4 {
            guard let v = hexDigitValue(bytes[pos]) else { return nil }
            acc = (acc << 4) | UInt16(v)
            pos += 1
        }
        return acc
    }

    mutating func parseStringKey() -> StackKey64? {
        guard pos < bytes.count, bytes[pos] == 0x22 else { return nil }
        pos += 1
        var key = StackKey64()
        while pos < bytes.count {
            let b = bytes[pos]
            if b == 0x22 {
                pos += 1
                return key
            }
            if b < 0x20 { return nil }
            if b == 0x5C {
                pos += 1
                guard pos < bytes.count else { return nil }
                let esc = bytes[pos]
                pos += 1
                switch esc {
                case 0x22: key.append(0x22)
                case 0x5C: key.append(0x5C)
                case 0x2F: key.append(0x2F)
                case 0x62: key.append(0x08)
                case 0x66: key.append(0x0C)
                case 0x6E: key.append(0x0A)
                case 0x72: key.append(0x0D)
                case 0x74: key.append(0x09)
                case 0x75:
                    guard let cu1 = parseHex4() else { return nil }
                    if (0xD800...0xDBFF).contains(cu1) {
                        guard pos + 2 <= bytes.count, bytes[pos] == 0x5C, bytes[pos + 1] == 0x75 else {
                            return nil
                        }
                        pos += 2
                        guard let cu2 = parseHex4(), (0xDC00...0xDFFF).contains(cu2) else {
                            return nil
                        }
                        let scalar = 0x10000 + ((UInt32(cu1) - 0xD800) << 10) + (UInt32(cu2) - 0xDC00)
                        key.appendUTF8(scalar: scalar)
                    } else if (0xDC00...0xDFFF).contains(cu1) {
                        return nil
                    } else {
                        key.appendUTF8(scalar: UInt32(cu1))
                    }
                default:
                    return nil
                }
            } else if b >= 0x80 {
                let seqLen = validUTF8MultibyteLength(at: pos)
                guard seqLen > 0 else { return nil }
                for i in 0..<seqLen {
                    key.append(bytes[pos + i])
                }
                pos += seqLen
            } else {
                key.append(b)
                pos += 1
            }
        }
        return nil
    }

    private func validUTF8MultibyteLength(at idx: Int) -> Int {
        let b0 = bytes[idx]
        if b0 >= 0xC2 && b0 <= 0xDF {
            guard idx + 1 < bytes.count else { return 0 }
            let b1 = bytes[idx + 1]
            return (b1 >= 0x80 && b1 <= 0xBF) ? 2 : 0
        } else if b0 == 0xE0 {
            guard idx + 2 < bytes.count else { return 0 }
            let b1 = bytes[idx + 1], b2 = bytes[idx + 2]
            return (b1 >= 0xA0 && b1 <= 0xBF && b2 >= 0x80 && b2 <= 0xBF) ? 3 : 0
        } else if (b0 >= 0xE1 && b0 <= 0xEC) || (b0 >= 0xEE && b0 <= 0xEF) {
            guard idx + 2 < bytes.count else { return 0 }
            let b1 = bytes[idx + 1], b2 = bytes[idx + 2]
            return (b1 >= 0x80 && b1 <= 0xBF && b2 >= 0x80 && b2 <= 0xBF) ? 3 : 0
        } else if b0 == 0xED {
            guard idx + 2 < bytes.count else { return 0 }
            let b1 = bytes[idx + 1], b2 = bytes[idx + 2]
            return (b1 >= 0x80 && b1 <= 0x9F && b2 >= 0x80 && b2 <= 0xBF) ? 3 : 0
        } else if b0 == 0xF0 {
            guard idx + 3 < bytes.count else { return 0 }
            let b1 = bytes[idx + 1], b2 = bytes[idx + 2], b3 = bytes[idx + 3]
            return (b1 >= 0x90 && b1 <= 0xBF && b2 >= 0x80 && b2 <= 0xBF && b3 >= 0x80 && b3 <= 0xBF) ? 4 : 0
        } else if b0 >= 0xF1 && b0 <= 0xF3 {
            guard idx + 3 < bytes.count else { return 0 }
            let b1 = bytes[idx + 1], b2 = bytes[idx + 2], b3 = bytes[idx + 3]
            return (b1 >= 0x80 && b1 <= 0xBF && b2 >= 0x80 && b2 <= 0xBF && b3 >= 0x80 && b3 <= 0xBF) ? 4 : 0
        } else if b0 == 0xF4 {
            guard idx + 3 < bytes.count else { return 0 }
            let b1 = bytes[idx + 1], b2 = bytes[idx + 2], b3 = bytes[idx + 3]
            return (b1 >= 0x80 && b1 <= 0x8F && b2 >= 0x80 && b2 <= 0xBF && b3 >= 0x80 && b3 <= 0xBF) ? 4 : 0
        }
        return 0
    }

    mutating func skipString() -> Bool {
        guard pos < bytes.count, bytes[pos] == 0x22 else { return false }
        pos += 1
        while pos < bytes.count {
            let b = bytes[pos]
            if b == 0x22 {
                pos += 1
                return true
            }
            if b < 0x20 { return false }
            if b == 0x5C {
                pos += 1
                guard pos < bytes.count else { return false }
                let esc = bytes[pos]
                pos += 1
                switch esc {
                case 0x22, 0x5C, 0x2F, 0x62, 0x66, 0x6E, 0x72, 0x74:
                    break
                case 0x75:
                    guard let cu1 = parseHex4() else { return false }
                    if (0xD800...0xDBFF).contains(cu1) {
                        guard pos + 2 <= bytes.count, bytes[pos] == 0x5C, bytes[pos + 1] == 0x75 else {
                            return false
                        }
                        pos += 2
                        guard let cu2 = parseHex4(), (0xDC00...0xDFFF).contains(cu2) else {
                            return false
                        }
                    } else if (0xDC00...0xDFFF).contains(cu1) {
                        return false
                    }
                default:
                    return false
                }
            } else if b >= 0x80 {
                let seqLen = validUTF8MultibyteLength(at: pos)
                guard seqLen > 0 else { return false }
                pos += seqLen
            } else {
                pos += 1
            }
        }
        return false
    }

    mutating func consumeLiteral(_ lit: StaticString) -> Bool {
        let n = lit.utf8CodeUnitCount
        guard pos + n <= bytes.count else { return false }
        let ok = lit.withUTF8Buffer { ptr in
            for i in 0..<n {
                if bytes[pos + i] != ptr[i] { return false }
            }
            return true
        }
        if ok { pos += n }
        return ok
    }

    mutating func skipNumber() -> Bool {
        let start = pos
        if pos < bytes.count && bytes[pos] == 0x2D { pos += 1 }
        guard pos < bytes.count else { return false }
        if bytes[pos] == 0x30 {
            pos += 1
        } else if bytes[pos] >= 0x31 && bytes[pos] <= 0x39 {
            pos += 1
            while pos < bytes.count && bytes[pos] >= 0x30 && bytes[pos] <= 0x39 { pos += 1 }
        } else {
            return false
        }
        if pos < bytes.count && bytes[pos] == 0x2E {
            pos += 1
            let fracStart = pos
            while pos < bytes.count && bytes[pos] >= 0x30 && bytes[pos] <= 0x39 { pos += 1 }
            if pos == fracStart { return false }
        }
        if pos < bytes.count && (bytes[pos] == 0x65 || bytes[pos] == 0x45) {
            pos += 1
            if pos < bytes.count && (bytes[pos] == 0x2B || bytes[pos] == 0x2D) { pos += 1 }
            let expStart = pos
            while pos < bytes.count && bytes[pos] >= 0x30 && bytes[pos] <= 0x39 { pos += 1 }
            if pos == expStart { return false }
        }
        return pos > start
    }

    mutating func skipValue(depth: Int, maxDepth: Int) -> Bool {
        if depth > maxDepth { return false }
        skipWS()
        guard pos < bytes.count else { return false }
        switch bytes[pos] {
        case 0x7B: // '{'
            pos += 1
            skipWS()
            if pos < bytes.count && bytes[pos] == 0x7D {
                pos += 1
                return true
            }
            while true {
                skipWS()
                guard skipString() else { return false }
                skipWS()
                guard pos < bytes.count && bytes[pos] == 0x3A else { return false }
                pos += 1
                guard skipValue(depth: depth + 1, maxDepth: maxDepth) else { return false }
                skipWS()
                guard pos < bytes.count else { return false }
                if bytes[pos] == 0x2C {
                    pos += 1
                } else if bytes[pos] == 0x7D {
                    pos += 1
                    return true
                } else {
                    return false
                }
            }
        case 0x5B: // '['
            pos += 1
            skipWS()
            if pos < bytes.count && bytes[pos] == 0x5D {
                pos += 1
                return true
            }
            while true {
                guard skipValue(depth: depth + 1, maxDepth: maxDepth) else { return false }
                skipWS()
                guard pos < bytes.count else { return false }
                if bytes[pos] == 0x2C {
                    pos += 1
                } else if bytes[pos] == 0x5D {
                    pos += 1
                    return true
                } else {
                    return false
                }
            }
        case 0x22:
            return skipString()
        case 0x74:
            return consumeLiteral("true")
        case 0x66:
            return consumeLiteral("false")
        case 0x6E:
            return consumeLiteral("null")
        default:
            return skipNumber()
        }
    }

    enum LexicalOptionalInt {
        case nullValue
        case integer(Int64)
        case invalid
    }

    mutating func parseLexicalOptionalNonNegInt64() -> LexicalOptionalInt {
        skipWS()
        guard pos < bytes.count else { return .invalid }
        if bytes[pos] == 0x6E {
            return consumeLiteral("null") ? .nullValue : .invalid
        }
        // Strictly accept exact JSON non-negative integer token: "0" or [1-9][0-9]*
        // Reject negatives, booleans, strings, leading zeros, fractional (1.0), and exponent (1e2).
        let first = bytes[pos]
        var acc: Int64 = 0
        if first == 0x30 {
            pos += 1
        } else if first >= 0x31 && first <= 0x39 {
            acc = Int64(first - 0x30)
            pos += 1
            while pos < bytes.count && bytes[pos] >= 0x30 && bytes[pos] <= 0x39 {
                let d = Int64(bytes[pos] - 0x30)
                if acc > (kMaxPerRequestTokens - d) / 10 {
                    return .invalid
                }
                acc = acc * 10 + d
                pos += 1
            }
        } else {
            return .invalid
        }
        // Must be immediately terminated by JSON delimiter (never '.', 'e', 'E', digit, etc.)
        if pos < bytes.count {
            let next = bytes[pos]
            if next != 0x20 && next != 0x09 && next != 0x0A && next != 0x0D && next != 0x2C && next != 0x7D && next != 0x5D {
                return .invalid
            }
        }
        guard acc <= kMaxPerRequestTokens else { return .invalid }
        return .integer(acc)
    }

    mutating func parsePromptTokensDetails() -> LexicalOptionalInt {
        skipWS()
        guard pos < bytes.count else { return .invalid }
        if bytes[pos] == 0x6E {
            return consumeLiteral("null") ? .nullValue : .invalid
        }
        guard bytes[pos] == 0x7B else { return .invalid }
        pos += 1
        skipWS()
        if pos < bytes.count && bytes[pos] == 0x7D {
            pos += 1
            return .nullValue
        }
        var sawCachedKey = false
        var cachedVal: Int64? = nil
        while true {
            skipWS()
            guard let key = parseStringKey() else { return .invalid }
            skipWS()
            guard pos < bytes.count && bytes[pos] == 0x3A else { return .invalid }
            pos += 1
            if key.equalsASCII("cached_tokens") {
                if sawCachedKey { return .invalid }
                sawCachedKey = true
                switch parseLexicalOptionalNonNegInt64() {
                case .nullValue:
                    cachedVal = nil
                case .integer(let v):
                    cachedVal = v
                case .invalid:
                    return .invalid
                }
            } else {
                guard skipValue(depth: 2, maxDepth: kMaxUsageJSONScanDepth) else { return .invalid }
            }
            skipWS()
            guard pos < bytes.count else { return .invalid }
            if bytes[pos] == 0x2C {
                pos += 1
            } else if bytes[pos] == 0x7D {
                pos += 1
                break
            } else {
                return .invalid
            }
        }
        if let v = cachedVal { return .integer(v) }
        return .nullValue
    }

    mutating func parseUsageObject() -> UsageScanState {
        skipWS()
        guard pos < bytes.count else { return .invalid }
        if bytes[pos] == 0x6E {
            return consumeLiteral("null") ? .nullValue : .invalid
        }
        guard bytes[pos] == 0x7B else { return .invalid }
        pos += 1
        skipWS()
        if pos < bytes.count && bytes[pos] == 0x7D {
            pos += 1
            return .invalid
        }

        var seenMask: UInt32 = 0
        var promptTokens: Int64? = nil
        var completionTokens: Int64? = nil
        var cachedFromDetails: Int64? = nil
        var cachedPromptTokens: Int64? = nil
        var cachedTokens: Int64? = nil
        var promptCacheHitTokens: Int64? = nil

        while true {
            skipWS()
            guard let key = parseStringKey() else { return .invalid }
            skipWS()
            guard pos < bytes.count && bytes[pos] == 0x3A else { return .invalid }
            pos += 1

            if key.equalsASCII("prompt_tokens") {
                if (seenMask & 1) != 0 { return .invalid }
                seenMask |= 1
                guard case .integer(let v) = parseLexicalOptionalNonNegInt64() else { return .invalid }
                promptTokens = v
            } else if key.equalsASCII("completion_tokens") {
                if (seenMask & 2) != 0 { return .invalid }
                seenMask |= 2
                guard case .integer(let v) = parseLexicalOptionalNonNegInt64() else { return .invalid }
                completionTokens = v
            } else if key.equalsASCII("prompt_tokens_details") {
                if (seenMask & 4) != 0 { return .invalid }
                seenMask |= 4
                switch parsePromptTokensDetails() {
                case .nullValue: cachedFromDetails = nil
                case .integer(let v): cachedFromDetails = v
                case .invalid: return .invalid
                }
            } else if key.equalsASCII("cached_prompt_tokens") {
                if (seenMask & 8) != 0 { return .invalid }
                seenMask |= 8
                switch parseLexicalOptionalNonNegInt64() {
                case .nullValue: cachedPromptTokens = nil
                case .integer(let v): cachedPromptTokens = v
                case .invalid: return .invalid
                }
            } else if key.equalsASCII("cached_tokens") {
                if (seenMask & 16) != 0 { return .invalid }
                seenMask |= 16
                switch parseLexicalOptionalNonNegInt64() {
                case .nullValue: cachedTokens = nil
                case .integer(let v): cachedTokens = v
                case .invalid: return .invalid
                }
            } else if key.equalsASCII("prompt_cache_hit_tokens") {
                if (seenMask & 32) != 0 { return .invalid }
                seenMask |= 32
                switch parseLexicalOptionalNonNegInt64() {
                case .nullValue: promptCacheHitTokens = nil
                case .integer(let v): promptCacheHitTokens = v
                case .invalid: return .invalid
                }
            } else {
                guard skipValue(depth: 1, maxDepth: kMaxUsageJSONScanDepth) else { return .invalid }
            }

            skipWS()
            guard pos < bytes.count else { return .invalid }
            if bytes[pos] == 0x2C {
                pos += 1
            } else if bytes[pos] == 0x7D {
                pos += 1
                break
            } else {
                return .invalid
            }
        }

        guard let pt = promptTokens, let ct = completionTokens else {
            return .invalid
        }
        var agreedCached: Int64? = nil
        for cand in [cachedFromDetails, cachedPromptTokens, cachedTokens, promptCacheHitTokens] {
            if let v = cand {
                if let prev = agreedCached {
                    if prev != v { return .invalid }
                } else {
                    agreedCached = v
                }
            }
        }
        let finalCached = agreedCached ?? 0
        guard finalCached <= pt else { return .invalid }
        return .valid(ParsedTokenUsage(promptTokens: pt, cachedPromptTokens: finalCached, completionTokens: ct))
    }

    mutating func scanTopLevel() -> UsageScanState {
        skipWS()
        guard pos < bytes.count && bytes[pos] == 0x7B else { return .invalid }
        pos += 1
        skipWS()
        if pos < bytes.count && bytes[pos] == 0x7D {
            pos += 1
            skipWS()
            return pos == bytes.count ? .missing : .invalid
        }
        var sawUsageKey = false
        var result: UsageScanState = .missing
        while true {
            skipWS()
            guard let key = parseStringKey() else { return .invalid }
            skipWS()
            guard pos < bytes.count && bytes[pos] == 0x3A else { return .invalid }
            pos += 1
            if key.equalsASCII("usage") {
                if sawUsageKey { return .invalid }
                sawUsageKey = true
                result = parseUsageObject()
                if result == .invalid { return .invalid }
            } else {
                guard skipValue(depth: 1, maxDepth: kMaxOuterJSONScanDepth) else { return .invalid }
            }
            skipWS()
            guard pos < bytes.count else { return .invalid }
            if bytes[pos] == 0x2C {
                pos += 1
            } else if bytes[pos] == 0x7D {
                pos += 1
                break
            } else {
                return .invalid
            }
        }
        skipWS()
        guard pos == bytes.count else { return .invalid }
        return result
    }
}

private func scanTopLevelUsageJSON(_ bytes: UnsafeBufferPointer<UInt8>) -> UsageScanState {
    var scanner = LexicalJSONUsageScanner(bytes: bytes)
    return scanner.scanTopLevel()
}

private func isHTTPTChar(_ b: UInt8) -> Bool {
    if (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) {
        return true
    }
    switch b {
    case 0x21, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2A, 0x2B, 0x2D, 0x2E, 0x5E, 0x5F, 0x60, 0x7C, 0x7E:
        return true
    default:
        return false
    }
}

private func isHTTPFieldVCharOrObsOrWS(_ b: UInt8) -> Bool {
    return b == 0x09 || (b >= 0x20 && b <= 0x7E) || b >= 0x80
}

private func parseHTTPStatusLineBytes(_ line: [UInt8]) -> Int? {
    // Require exact "HTTP/1.0" or "HTTP/1.1" + SP + 3 ASCII digits + SP + optional valid reason-phrase bytes
    guard line.count >= 13 else { return nil }
    guard line[0] == 0x48 && line[1] == 0x54 && line[2] == 0x54 && line[3] == 0x50
        && line[4] == 0x2F && line[5] == 0x31 && line[6] == 0x2E
        && (line[7] == 0x30 || line[7] == 0x31)
        && line[8] == 0x20 else {
        return nil
    }
    guard line[9] >= 0x31 && line[9] <= 0x35
        && line[10] >= 0x30 && line[10] <= 0x39
        && line[11] >= 0x30 && line[11] <= 0x39
        && line[12] == 0x20 else {
        return nil
    }
    for idx in 13..<line.count {
        if !isHTTPFieldVCharOrObsOrWS(line[idx]) { return nil }
    }
    return Int(line[9] - 0x30) * 100 + Int(line[10] - 0x30) * 10 + Int(line[11] - 0x30)
}

private func parseHTTPFieldLineBytes(_ line: [UInt8]) -> (nameLowerASCII: String, valueBytes: [UInt8])? {
    guard let colonIdx = line.firstIndex(of: 0x3A), colonIdx > 0 else {
        return nil
    }
    var lowerName = [UInt8]()
    lowerName.reserveCapacity(colonIdx)
    for idx in 0..<colonIdx {
        let b = line[idx]
        guard isHTTPTChar(b) else { return nil }
        if b >= 0x41 && b <= 0x5A {
            lowerName.append(b + 32)
        } else {
            lowerName.append(b)
        }
    }
    for idx in (colonIdx + 1)..<line.count {
        guard isHTTPFieldVCharOrObsOrWS(line[idx]) else { return nil }
    }
    let valSlice = Array(line[(colonIdx + 1)..<line.count])
    return (String(decoding: lowerName, as: UTF8.self), valSlice)
}

private func trimASCIIOWS(_ bytes: [UInt8]) -> [UInt8] {
    var start = 0
    var end = bytes.count
    while start < end && (bytes[start] == 0x20 || bytes[start] == 0x09) { start += 1 }
    while end > start && (bytes[end - 1] == 0x20 || bytes[end - 1] == 0x09) { end -= 1 }
    return start < end ? Array(bytes[start..<end]) : []
}

private func parseASCIIPureASCIIString(_ bytes: [UInt8]) -> String? {
    for b in bytes {
        if b > 0x7F { return nil }
    }
    return String(decoding: bytes, as: UTF8.self)
}

private func parseChunkSizeLineBytes(_ line: [UInt8]) -> (size: Int, hasExtension: Bool)? {
    guard !line.isEmpty else { return nil }
    var hexEnd = line.count
    var hasExt = false
    if let semi = line.firstIndex(of: 0x3B) {
        hexEnd = semi
        hasExt = true
        // RFC 9112 §7.1.1: chunk-ext = *( BWS ";" BWS chunk-ext-name ... ) where BWS = *( SP / HTAB )
        while hexEnd > 0 && (line[hexEnd - 1] == 0x20 || line[hexEnd - 1] == 0x09) {
            hexEnd -= 1
        }
    }
    guard hexEnd >= 1 && hexEnd <= 8 else { return nil }
    var val: Int = 0
    for idx in 0..<hexEnd {
        guard let nib = hexDigitValue(line[idx]) else { return nil }
        val = (val << 4) | Int(nib)
    }
    return (val, hasExt)
}

private struct ObserverOutcome {
    let upstreamRequestWritten: Bool
    let httpStatus: Int?
    let transportComplete: Bool
    let usageState: UsageScanState
}

private final class ChatUsageObserver: @unchecked Sendable {
    private enum Mode {
        case pending
        case json
        case sse
        case unsupported
    }

    private let lock = NSLock()
    private let pool: ObserverMemoryPool
    private var mode: Mode = .pending
    private var detached = false
    private var upstreamRequestWritten = false
    private var httpStatus: Int? = nil
    private var framingInvalid = false
    private var transportComplete = false
    private var overflowed = false
    private var usageState: UsageScanState = .missing
    private var sawSSEDone = false
    private var sseBomDone = false
    private var sseBomPendingCount = 0
    private var ssePrevWasCR = false
    private var sseEventHasData = false
    private var cachedOutcome: ObserverOutcome? = nil

    private let jsonBuf: OwnedRawBuffer
    private let ssePartialLine: OwnedRawBuffer
    private let sseEventBuf: OwnedRawBuffer

    init(pool: ObserverMemoryPool) {
        self.pool = pool
        self.jsonBuf = OwnedRawBuffer(pool: pool, maxBytes: kMaxUsageJSONBodyBytes)
        self.ssePartialLine = OwnedRawBuffer(pool: pool, maxBytes: kMaxUsageSSELineBytes)
        self.sseEventBuf = OwnedRawBuffer(pool: pool, maxBytes: kMaxUsageSSEEventBytes)
    }

    private func freeAllBuffersLocked() {
        jsonBuf.free()
        ssePartialLine.free()
        sseEventBuf.free()
    }

    func markUpstreamRequestWritten() {
        lock.lock()
        if !detached {
            upstreamRequestWritten = true
        }
        lock.unlock()
    }

    func markFramingInvalid() {
        lock.lock()
        if !detached {
            framingInvalid = true
            transportComplete = false
        }
        lock.unlock()
    }

    func markTransportComplete() {
        lock.lock()
        if !detached && !framingInvalid {
            transportComplete = true
        }
        lock.unlock()
    }

    func onHeaders(status: Int, contentType: String) {
        lock.lock()
        defer { lock.unlock() }
        guard !detached else { return }
        httpStatus = status
        guard status == 200 else {
            mode = .unsupported
            return
        }
        let media = contentType
            .split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)
            .first
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() } ?? ""
        if media == "text/event-stream" {
            mode = .sse
        } else if media == "application/json" || media.hasSuffix("+json") {
            mode = .json
        } else {
            mode = .unsupported
        }
    }

    func onChunk(_ data: Data) {
        if data.isEmpty { return }
        lock.lock()
        defer { lock.unlock() }
        guard !detached && !overflowed else { return }
        switch mode {
        case .json:
            let ok = data.withUnsafeBytes { raw -> Bool in
                guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return true }
                return jsonBuf.append(bytes: base, length: raw.count)
            }
            if !ok {
                overflowed = true
                usageState = .invalid
                freeAllBuffersLocked()
            }
        case .sse:
            data.withUnsafeBytes { raw in
                guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
                let total = raw.count
                var startIdx = 0
                if !sseBomDone {
                    // SSE standard §9.2.6: ignore one leading UTF-8 BOM (0xEF 0xBB 0xBF), even if split across chunks
                    while startIdx < total && !sseBomDone {
                        let b = base[startIdx]
                        if sseBomPendingCount == 0 {
                            if b == 0xEF {
                                sseBomPendingCount = 1
                                startIdx += 1
                            } else {
                                sseBomDone = true
                            }
                        } else if sseBomPendingCount == 1 {
                            if b == 0xBB {
                                sseBomPendingCount = 2
                                startIdx += 1
                            } else {
                                sseBomDone = true
                                sseBomPendingCount = 0
                                let prev: [UInt8] = [0xEF]
                                let ok = prev.withUnsafeBufferPointer { buf -> Bool in
                                    guard let p = buf.baseAddress else { return true }
                                    return ssePartialLine.append(bytes: p, length: 1)
                                }
                                if !ok {
                                    overflowed = true
                                    usageState = .invalid
                                    freeAllBuffersLocked()
                                    return
                                }
                            }
                        } else {
                            sseBomDone = true
                            sseBomPendingCount = 0
                            if b == 0xBF {
                                startIdx += 1
                            } else {
                                let prev: [UInt8] = [0xEF, 0xBB]
                                let ok = prev.withUnsafeBufferPointer { buf -> Bool in
                                    guard let p = buf.baseAddress else { return true }
                                    return ssePartialLine.append(bytes: p, length: 2)
                                }
                                if !ok {
                                    overflowed = true
                                    usageState = .invalid
                                    freeAllBuffersLocked()
                                    return
                                }
                            }
                        }
                    }
                }
                var segStart = startIdx
                var i = startIdx
                while i < total && !overflowed {
                    let b = base[i]
                    if ssePrevWasCR {
                        ssePrevWasCR = false
                        if b == 0x0A {
                            i += 1
                            segStart = i
                            continue
                        }
                    }
                    if b == 0x0A || b == 0x0D {
                        if i > segStart {
                            if !ssePartialLine.append(bytes: base.advanced(by: segStart), length: i - segStart) {
                                overflowed = true
                                usageState = .invalid
                                freeAllBuffersLocked()
                                return
                            }
                        }
                        processCompleteSSELineLocked()
                        if overflowed { return }
                        if b == 0x0D {
                            ssePrevWasCR = true
                        }
                        i += 1
                        segStart = i
                    } else {
                        i += 1
                    }
                }
                if !overflowed && total > segStart {
                    if !ssePartialLine.append(bytes: base.advanced(by: segStart), length: total - segStart) {
                        overflowed = true
                        usageState = .invalid
                        freeAllBuffersLocked()
                    }
                }
            }
        case .pending, .unsupported:
            break
        }
    }

    private func processCompleteSSELineLocked() {
        defer { ssePartialLine.free() }
        if ssePartialLine.count == 0 {
            // Blank line = SSE event boundary
            if sseEventHasData {
                dispatchSSEEventLocked()
                sseEventBuf.free()
                sseEventHasData = false
            }
            return
        }
        ssePartialLine.withReadOnlyBytes { line in
            guard line.count > 0 else { return }
            if line[0] == 0x3A { // ':' comment line
                return
            }
            var colonIdx: Int? = nil
            for idx in 0..<line.count {
                if line[idx] == 0x3A {
                    colonIdx = idx
                    break
                }
            }
            let fieldLen = colonIdx ?? line.count
            // Match exact "data" field name (colonless bare "data" OR "data:...")
            guard fieldLen == 4
                && line[0] == 0x64 && line[1] == 0x61 && line[2] == 0x74 && line[3] == 0x61 else {
                return
            }
            if sseEventHasData {
                if !sseEventBuf.appendByte(0x0A) {
                    overflowed = true
                    usageState = .invalid
                    freeAllBuffersLocked()
                    return
                }
            }
            sseEventHasData = true
            if let cIdx = colonIdx {
                var valStart = cIdx + 1
                if valStart < line.count && line[valStart] == 0x20 {
                    valStart += 1
                }
                let valLen = line.count - valStart
                if valLen > 0, let base = line.baseAddress {
                    if !sseEventBuf.append(bytes: base.advanced(by: valStart), length: valLen) {
                        overflowed = true
                        usageState = .invalid
                        freeAllBuffersLocked()
                        return
                    }
                }
            }
        }
    }

    private func dispatchSSEEventLocked() {
        sseEventBuf.withReadOnlyBytes { payload in
            if payload.count == 0 { return }
            // Check exact "[DONE]"
            let isDone = payload.count == 6
                && payload[0] == 0x5B && payload[1] == 0x44 && payload[2] == 0x4F
                && payload[3] == 0x4E && payload[4] == 0x45 && payload[5] == 0x5D
            if sawSSEDone {
                usageState = .invalid
                return
            }
            if isDone {
                sawSSEDone = true
                return
            }
            let scanned = scanTopLevelUsageJSON(payload)
            switch scanned {
            case .missing, .nullValue:
                break
            case .valid(let parsed):
                if usageState != .invalid {
                    usageState = .valid(parsed)
                }
            case .invalid:
                usageState = .invalid
            }
        }
    }

    func detachAndFinalize(forceIncomplete: Bool) -> ObserverOutcome {
        lock.lock()
        defer { lock.unlock() }
        if detached, let prev = cachedOutcome {
            return prev
        }
        detached = true
        let finalTransportComplete = (!forceIncomplete && !framingInvalid && transportComplete)
        var finalUsageState = usageState
        if overflowed || !finalTransportComplete {
            finalUsageState = .invalid
        } else if httpStatus == 200 {
            switch mode {
            case .json:
                if jsonBuf.count == 0 {
                    finalUsageState = .missing
                } else {
                    let scanned = jsonBuf.withReadOnlyBytes { scanTopLevelUsageJSON($0) }
                    finalUsageState = (scanned == .nullValue) ? .missing : scanned
                }
            case .sse:
                // Unfinished SSE event data (non-empty line/event, dangling BOM prefix, or bare/empty data field lacking blank delimiter)
                if ssePartialLine.count > 0 || sseEventBuf.count > 0 || sseEventHasData || sseBomPendingCount > 0 {
                    finalUsageState = .invalid
                }
            case .pending, .unsupported:
                finalUsageState = .missing
            }
        }
        freeAllBuffersLocked()
        let out = ObserverOutcome(
            upstreamRequestWritten: upstreamRequestWritten,
            httpStatus: httpStatus,
            transportComplete: finalTransportComplete,
            usageState: finalUsageState
        )
        cachedOutcome = out
        return out
    }
}

private final class StreamingForwardDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var clientFD: Int32
    private let timeoutSecondsClamped: UInt64
    private(set) var deadlineUptimeNs: UInt64
    private var _usageObserver: ChatUsageObserver?
    private let sem = DispatchSemaphore(value: 0)
    private var wroteHeaders = false
    private var cancelled = false
    private var signaled = false
    private(set) var completedError: Error?

    init(clientFD: Int32, timeoutSeconds: Int, usageObserver: ChatUsageObserver? = nil) {
        self.clientFD = clientFD
        let clamped = UInt64(max(1, timeoutSeconds))
        self.timeoutSecondsClamped = clamped
        self.deadlineUptimeNs = DispatchTime.now().uptimeNanoseconds + clamped * 1_000_000_000
        self._usageObserver = usageObserver
    }

    func resetDeadline() {
        self.deadlineUptimeNs = DispatchTime.now().uptimeNanoseconds + timeoutSecondsClamped * 1_000_000_000
    }

    func setUsageObserver(_ obs: ChatUsageObserver?) {
        lock.lock()
        _usageObserver = obs
        lock.unlock()
    }

    var usageObserver: ChatUsageObserver? {
        lock.lock()
        defer { lock.unlock() }
        return _usageObserver
    }

    func remainingMilliseconds() -> Int32 {
        let now = DispatchTime.now().uptimeNanoseconds
        if now >= deadlineUptimeNs {
            return 0
        }
        let remMs = (deadlineUptimeNs - now) / 1_000_000
        return Int32(min(UInt64(Int32.max), max(1, remMs)))
    }

    func isCancelledOrPastDeadline() -> Bool {
        if DispatchTime.now().uptimeNanoseconds >= deadlineUptimeNs {
            return true
        }
        lock.lock()
        let stop = (clientFD < 0 || cancelled)
        lock.unlock()
        return stop
    }

    func cancelAndShutdownSocket() {
        lock.lock()
        cancelled = true
        if clientFD >= 0 {
            _ = Darwin.shutdown(clientFD, SHUT_RDWR)
        }
        lock.unlock()
    }

    func waitForCompletion(timeoutSeconds: Double) -> Bool {
        return sem.wait(timeout: .now() + timeoutSeconds) == .success
    }

    func closeClientSocket() {
        lock.lock()
        cancelled = true
        let fd = clientFD
        clientFD = -1
        lock.unlock()
        if fd >= 0 {
            _ = Darwin.close(fd)
        }
    }

    func writeSafe(_ data: Data) -> Bool {
        if data.isEmpty { return true }
        return data.withUnsafeBytes { rawBuf -> Bool in
            guard let base = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return true
            }
            var sent = 0
            while sent < data.count {
                if DispatchTime.now().uptimeNanoseconds >= deadlineUptimeNs {
                    cancelAndShutdownSocket()
                    return false
                }
                lock.lock()
                let fd = clientFD
                let isCanc = cancelled
                var n = -1
                var err: Int32 = 0
                if fd >= 0 && !isCanc {
                    n = Darwin.write(fd, base.advanced(by: sent), data.count - sent)
                    if n < 0 {
                        err = errno
                    }
                }
                lock.unlock()

                if fd < 0 || isCanc {
                    return false
                }
                if n > 0 {
                    sent += n
                    continue
                }
                if n < 0 && err == EINTR {
                    continue
                }
                if n < 0 && (err == EAGAIN || err == EWOULDBLOCK) {
                    let remMs = remainingMilliseconds()
                    if remMs <= 0 {
                        cancelAndShutdownSocket()
                        return false
                    }
                    let sliceMs = min(100, remMs)
                    var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                    let prc = Darwin.poll(&pfd, 1, sliceMs)
                    if prc < 0 && errno != EINTR {
                        return false
                    }
                    if (pfd.revents & Int16(POLLERR | POLLHUP | POLLNVAL)) != 0 {
                        return false
                    }
                    continue
                }
                return false
            }
            return true
        }
    }

    func writeHeadersSafe(status: Int, contentType: String) -> Bool {
        let reason = httpStatusReasonPhrase(status)
        let cleanCT = contentType
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\n", with: "")
        let headerBlock =
            "HTTP/1.1 \(status) \(reason)\r\n" +
            "Content-Type: \(cleanCT)\r\n" +
            "Cache-Control: no-cache\r\n" +
            "Connection: close\r\n\r\n"
        lock.lock()
        let canWrite = (clientFD >= 0 && !cancelled && !wroteHeaders)
        if canWrite {
            wroteHeaders = true
        }
        lock.unlock()
        guard canWrite, let hData = headerBlock.data(using: .utf8) else {
            return false
        }
        return writeSafe(hData)
    }

    func sendErrorSafe(status: Int, statusText: String, errorCode: String, message: String) {
        lock.lock()
        let canWrite = (clientFD >= 0 && !cancelled && !wroteHeaders)
        if canWrite {
            wroteHeaders = true
        }
        lock.unlock()
        guard canWrite else { return }
        let bodyObj: [String: Any] = [
            "error": [
                "type": errorCode,
                "code": errorCode,
                "message": message,
            ]
        ]
        let bodyData = (try? JSONSerialization.data(withJSONObject: bodyObj, options: [])) ?? Data("{}".utf8)
        let header =
            "HTTP/1.1 \(status) \(statusText)\r\n" +
            "Content-Type: application/json\r\n" +
            "Content-Length: \(bodyData.count)\r\n" +
            "Connection: close\r\n\r\n"
        if let hData = header.data(using: .utf8) {
            _ = writeSafe(hData)
        }
        _ = writeSafe(bodyData)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        // Never follow redirects from upstream.
        completionHandler(nil)
    }

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        guard let httpResp = response as? HTTPURLResponse else {
            completionHandler(.cancel)
            return
        }
        let status = httpResp.statusCode
        let contentType = httpResp.value(forHTTPHeaderField: "Content-Type") ?? "application/json"
        usageObserver?.onHeaders(status: status, contentType: contentType)
        let ok = writeHeadersSafe(status: status, contentType: contentType)
        completionHandler(ok ? .allow : .cancel)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        if !data.isEmpty {
            usageObserver?.onChunk(data)
            if !writeSafe(data) {
                dataTask.cancel()
            }
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error = error {
            self.completedError = error
            sendErrorSafe(
                status: 502,
                statusText: "Bad Gateway",
                errorCode: "upstream_error",
                message: "Upstream connection failed: \(error.localizedDescription)"
            )
        } else {
            usageObserver?.markTransportComplete()
        }
        lock.lock()
        let shouldSignal = !signaled
        signaled = true
        lock.unlock()
        if shouldSignal {
            sem.signal()
        }
    }
}

private func writeAllToFD(_ fd: Int32, data: Data) -> Bool {
    return data.withUnsafeBytes { rawBuf -> Bool in
        guard let base = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
            return true
        }
        var sent = 0
        while sent < data.count {
            let n = Darwin.write(fd, base.advanced(by: sent), data.count - sent)
            if n > 0 {
                sent += n
            } else if n < 0 && errno == EINTR {
                continue
            } else {
                return false
            }
        }
        return true
    }
}

private func sendHTTPError(
    clientFD: Int32,
    status: Int,
    statusText: String,
    errorCode: String,
    message: String
) {
    let bodyObj: [String: Any] = [
        "error": [
            "type": errorCode,
            "code": errorCode,
            "message": message,
        ]
    ]
    let bodyData = (try? JSONSerialization.data(withJSONObject: bodyObj, options: [])) ?? Data("{}".utf8)
    let header =
        "HTTP/1.1 \(status) \(statusText)\r\n" +
        "Content-Type: application/json\r\n" +
        "Content-Length: \(bodyData.count)\r\n" +
        "Connection: close\r\n\r\n"
    if let hData = header.data(using: .utf8) {
        _ = writeAllToFD(clientFD, data: hData)
    }
    _ = writeAllToFD(clientFD, data: bodyData)
}

private let kTokenPrefixLeakRegex = try! NSRegularExpression(
    pattern: "\\b(?:se-session|oc-relay|worker-relay)-[A-Za-z0-9_-]{12,}",
    options: []
)

private let kBase64TokenPrefixes: [String] = [
    "c2Utc2Vzc2lvbi0",
    "b2MtcmVsYXkt",
    "d29ya2VyLXJlbGF5LQ",
]

private let kBase64CandidateRegex = try! NSRegularExpression(
    pattern: "[A-Za-z0-9+/_-]{16,}={0,2}",
    options: []
)

private let kMaxJSONContainerDepth = 64
private let kMaxEmbeddedJSONDecodes = 6
private let kMaxVisitedJSONNodes = 20_000
private let kMaxBase64CandidatesPerString = 16_384

private func hexDigitValue(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 0x30...0x39: return byte - 0x30
    case 0x41...0x46: return byte - 0x41 + 10
    case 0x61...0x66: return byte - 0x61 + 10
    default: return nil
    }
}

private func decodePercentLenient(_ data: Data) -> String {
    let bytes = [UInt8](data)
    var out: [UInt8] = []
    out.reserveCapacity(bytes.count)
    var idx = 0
    while idx < bytes.count {
        if bytes[idx] == 0x25 && idx + 2 < bytes.count,
           let hi = hexDigitValue(bytes[idx + 1]),
           let lo = hexDigitValue(bytes[idx + 2]) {
            out.append((hi << 4) | lo)
            idx += 3
        } else {
            out.append(bytes[idx])
            idx += 1
        }
    }
    return String(decoding: out, as: UTF8.self)
}

private func secretEncodingVariants(_ secretData: Data) -> [String] {
    let trimmedStr = String(decoding: secretData, as: UTF8.self)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmedStr.utf8.count >= 8 else { return [] }
    let cleanData = Data(trimmedStr.utf8)
    let b64Std = cleanData.base64EncodedString()
    let b64NoPad = b64Std.trimmingCharacters(in: CharacterSet(charactersIn: "="))
    let b64Url = b64NoPad
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
    let basicOc = Data("opencode:\(trimmedStr)".utf8)
        .base64EncodedString()
        .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    let basicAnon = Data(":\(trimmedStr)".utf8)
        .base64EncodedString()
        .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    var variants: [String] = []
    for cand in [trimmedStr, b64Std, b64NoPad, b64Url, basicOc, basicAnon] where cand.count >= 8 {
        if !variants.contains(cand) {
            variants.append(cand)
        }
    }
    return variants
}

private func decodeJSONEscapeSequencesLenient(_ input: String) -> String {
    guard input.contains("\\") else { return input }
    let utf16 = Array(input.utf16)
    var out: [UInt16] = []
    out.reserveCapacity(utf16.count)
    var idx = 0

    func parseHex4(at start: Int) -> UInt16? {
        guard start + 4 <= utf16.count else { return nil }
        var acc: UInt16 = 0
        for off in 0..<4 {
            let unit = utf16[start + off]
            guard unit <= 0x7F, let nib = hexDigitValue(UInt8(unit)) else { return nil }
            acc = (acc << 4) | UInt16(nib)
        }
        return acc
    }

    while idx < utf16.count {
        let cu = utf16[idx]
        if cu == 0x5C && idx + 1 < utf16.count {
            let next = utf16[idx + 1]
            switch next {
            case 0x2F: // \/ -> /
                out.append(0x2F)
                idx += 2
            case 0x22: // \" -> "
                out.append(0x22)
                idx += 2
            case 0x5C: // \\ -> \
                out.append(0x5C)
                idx += 2
            case 0x6E: // \n
                out.append(0x0A)
                idx += 2
            case 0x72: // \r
                out.append(0x0D)
                idx += 2
            case 0x74: // \t
                out.append(0x09)
                idx += 2
            case 0x62: // \b
                out.append(0x08)
                idx += 2
            case 0x66: // \f
                out.append(0x0C)
                idx += 2
            case 0x75: // \uXXXX
                if let codeUnit = parseHex4(at: idx + 2) {
                    out.append(codeUnit)
                    idx += 6
                } else {
                    out.append(cu)
                    idx += 1
                }
            default:
                out.append(cu)
                idx += 1
            }
        } else {
            out.append(cu)
            idx += 1
        }
    }
    return String(decoding: out, as: UTF16.self)
}

private func trimmedSecretString(_ secretData: Data) -> String? {
    let s = String(decoding: secretData, as: UTF8.self)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    return s.utf8.count >= 8 ? s : nil
}

private func textMatchesDirectLeak(
    _ text: String,
    needles: [String]
) -> Bool {
    if text.isEmpty { return false }
    for needle in needles where text.contains(needle) {
        return true
    }
    for b64Pref in kBase64TokenPrefixes where text.contains(b64Pref) {
        return true
    }
    let nsRange = NSRange(text.startIndex..<text.endIndex, in: text)
    if kTokenPrefixLeakRegex.firstMatch(in: text, options: [], range: nsRange) != nil {
        return true
    }
    return false
}

private func decodeBase64Candidate(_ token: String) -> Data? {
    var normalized = token
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
        .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    guard normalized.count >= 12 else { return nil }
    let rem = normalized.count % 4
    if rem == 1 {
        return nil
    }
    if rem > 0 {
        normalized += String(repeating: "=", count: 4 - rem)
    }
    return Data(base64Encoded: normalized)
}

private func stringContainsCredentialLeak(
    _ rawString: String,
    needles: [String],
    rawSecrets: [String]
) -> Bool {
    if rawString.isEmpty { return false }
    var candidateSet: [String] = []
    func addCandidate(_ s: String) {
        if !s.isEmpty && !candidateSet.contains(s) {
            candidateSet.append(s)
        }
    }

    addCandidate(rawString)
    addCandidate(decodePercentLenient(Data(rawString.utf8)))
    var cur = rawString
    for _ in 0..<4 {
        let next = decodeJSONEscapeSequencesLenient(cur)
        if next == cur { break }
        addCandidate(next)
        addCandidate(decodePercentLenient(Data(next.utf8)))
        cur = next
    }

    for cand in candidateSet {
        if textMatchesDirectLeak(cand, needles: needles) {
            return true
        }
        let nsRange = NSRange(cand.startIndex..<cand.endIndex, in: cand)
        let matches = kBase64CandidateRegex.matches(in: cand, options: [], range: nsRange)
        if matches.count > kMaxBase64CandidatesPerString {
            return true
        }
        for match in matches {
            guard let swiftRange = Range(match.range, in: cand) else { continue }
            let tok = String(cand[swiftRange])
            for offset in 0..<4 {
                let slice = offset == 0 ? tok : String(tok.dropFirst(offset))
                guard slice.count >= 12,
                      let decoded = decodeBase64Candidate(slice),
                      !decoded.isEmpty else {
                    continue
                }
                let decStr = String(decoding: decoded, as: UTF8.self)
                let decPct = decodePercentLenient(decoded)
                let decUnesc = decodeJSONEscapeSequencesLenient(decStr)
                for sub in [decStr, decPct, decUnesc] where !sub.isEmpty {
                    for rawSec in rawSecrets where sub.contains(rawSec) {
                        return true
                    }
                    if textMatchesDirectLeak(sub, needles: needles) {
                        return true
                    }
                }
            }
        }
    }
    return false
}

private func containsCredentialLeak(
    bodyData: Data,
    sessionToken: Data,
    apiKeyData: Data
) -> Bool {
    if bodyData.isEmpty { return false }
    var needles = secretEncodingVariants(sessionToken)
    for v in secretEncodingVariants(apiKeyData) where !needles.contains(v) {
        needles.append(v)
    }
    var rawSecrets: [String] = []
    if let s = trimmedSecretString(sessionToken) { rawSecrets.append(s) }
    if let k = trimmedSecretString(apiKeyData), !rawSecrets.contains(k) { rawSecrets.append(k) }

    let rawText = String(decoding: bodyData, as: UTF8.self)
    return stringContainsCredentialLeak(rawText, needles: needles, rawSecrets: rawSecrets)
}

private func combinedCredentialLeakMaterial(_ secrets: [Data]) -> (needles: [String], raw: [String]) {
    var needles = Set<String>()
    var raw = Set<String>()
    for secret in secrets {
        for value in secretEncodingVariants(secret) { needles.insert(value) }
        if let value = trimmedSecretString(secret) { raw.insert(value) }
    }
    return (Array(needles), Array(raw))
}

private func jsonNodeContainsCredentialLeak(
    _ value: Any,
    needles: [String],
    rawSecrets: [String],
    containerDepth: Int,
    embeddedDecodeDepth: Int,
    visitedNodes: inout Int
) -> Bool {
    visitedNodes += 1
    if containerDepth > kMaxJSONContainerDepth || visitedNodes > kMaxVisitedJSONNodes {
        return true
    }

    if let str = value as? String {
        if stringContainsCredentialLeak(str, needles: needles, rawSecrets: rawSecrets) {
            return true
        }
        let trimmed = str.trimmingCharacters(in: .whitespacesAndNewlines)
        if let first = trimmed.first, (first == "{" || first == "[" || first == "\"") {
            if let nested = try? JSONSerialization.jsonObject(
                with: Data(trimmed.utf8),
                options: [.fragmentsAllowed]
            ) {
                if embeddedDecodeDepth >= kMaxEmbeddedJSONDecodes {
                    return true
                }
                if jsonNodeContainsCredentialLeak(
                    nested,
                    needles: needles,
                    rawSecrets: rawSecrets,
                    containerDepth: 0,
                    embeddedDecodeDepth: embeddedDecodeDepth + 1,
                    visitedNodes: &visitedNodes
                ) {
                    return true
                }
            }
        }
        return false
    }

    if let arr = value as? [Any] {
        for item in arr {
            if jsonNodeContainsCredentialLeak(
                item,
                needles: needles,
                rawSecrets: rawSecrets,
                containerDepth: containerDepth + 1,
                embeddedDecodeDepth: embeddedDecodeDepth,
                visitedNodes: &visitedNodes
            ) {
                return true
            }
        }
        return false
    }

    if let dict = value as? [String: Any] {
        for (k, v) in dict {
            if jsonNodeContainsCredentialLeak(
                k,
                needles: needles,
                rawSecrets: rawSecrets,
                containerDepth: containerDepth + 1,
                embeddedDecodeDepth: embeddedDecodeDepth,
                visitedNodes: &visitedNodes
            ) {
                return true
            }
            if jsonNodeContainsCredentialLeak(
                v,
                needles: needles,
                rawSecrets: rawSecrets,
                containerDepth: containerDepth + 1,
                embeddedDecodeDepth: embeddedDecodeDepth,
                visitedNodes: &visitedNodes
            ) {
                return true
            }
        }
        return false
    }

    return false
}

private func jsonObjectContainsCredentialLeak(
    _ root: Any,
    sessionToken: Data,
    apiKeyData: Data
) -> Bool {
    var needles = secretEncodingVariants(sessionToken)
    for v in secretEncodingVariants(apiKeyData) where !needles.contains(v) {
        needles.append(v)
    }
    var rawSecrets: [String] = []
    if let s = trimmedSecretString(sessionToken) { rawSecrets.append(s) }
    if let k = trimmedSecretString(apiKeyData), !rawSecrets.contains(k) { rawSecrets.append(k) }

    var visitedNodes = 0
    return jsonNodeContainsCredentialLeak(
        root,
        needles: needles,
        rawSecrets: rawSecrets,
        containerDepth: 0,
        embeddedDecodeDepth: 0,
        visitedNodes: &visitedNodes
    )
}

// MARK: - HTTP/1.1 Loopback Server

private func isSafeTokenFileForUnlink(_ path: String) -> Bool {
    let url = URL(fileURLWithPath: path)
    let name = url.lastPathComponent
    guard name.hasPrefix(".se-session-"), name.hasSuffix(".token") else {
        return false
    }
    var st = stat()
    guard lstat(path, &st) == 0 else {
        return false
    }
    return (st.st_mode & S_IFMT) == S_IFREG
}

private let kMaxDefaultChatParamsBytes = 4096
private let kReservedChatParamKeys: Set<String> = [
    "model",
    "messages",
    "n",
    "best_of",
    "max_tokens",
    "max_completion_tokens",
    "maxOutputTokens",
    "stream",
]

private func parseAndValidateDefaultChatParams(rawJSON: String) throws -> [String: Any] {
    let utf8Count = rawJSON.utf8.count
    guard utf8Count <= kMaxDefaultChatParamsBytes else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 40,
            userInfo: [
                NSLocalizedDescriptionKey:
                    "--default-chat-params-json exceeds \(kMaxDefaultChatParamsBytes) bytes (\(utf8Count) bytes)"
            ]
        )
    }
    guard
        let rawData = rawJSON.data(using: .utf8),
        let parsed = try? JSONSerialization.jsonObject(with: rawData, options: []),
        let dict = parsed as? [String: Any],
        JSONSerialization.isValidJSONObject(dict)
    else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 41,
            userInfo: [NSLocalizedDescriptionKey: "--default-chat-params-json must be a valid JSON object"]
        )
    }
    for key in dict.keys {
        if kReservedChatParamKeys.contains(key) {
            throw NSError(
                domain: "SEKeyProxy",
                code: 42,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "--default-chat-params-json cannot contain reserved key '\(key)'"
                ]
            )
        }
    }
    if let ctk = dict["chat_template_kwargs"], !(ctk is [String: Any]) {
        throw NSError(
            domain: "SEKeyProxy",
            code: 43,
            userInfo: [
                NSLocalizedDescriptionKey:
                    "--default-chat-params-json 'chat_template_kwargs' must be a JSON object"
            ]
        )
    }
    return dict
}

private func continuousSeconds() -> Double {
    var scale = mach_timebase_info_data_t()
    mach_timebase_info(&scale)
    return Double(mach_continuous_time()) * Double(scale.numer) / Double(scale.denom) / 1_000_000_000
}

private final class ProxyServer: @unchecked Sendable {
    let listenPort: UInt16
    let upstreamBaseURL: URL
    let allowedModel: String
    private var activeSessionToken: Data
    private var retiredSessionTokens: [Data] = []
    private let maxSessionGenerations = 32
    var sessionToken: Data {
        lock.lock(); defer { lock.unlock() }
        return activeSessionToken
    }
    var apiKeyData: Data
    let maxChatRequests: Int
    let maxRequestBytes: Int
    let maxTokensCap: Int
    let streamTimeoutSeconds: Int
    let upstreamPID: pid_t?
    let upstreamBinding: UpstreamProcessBinding?
    let forceURLSession: Bool
    let sessionTokenFile: String?
    let defaultChatParams: [String: Any]
    let pricing: PricingRates?
    let maxActualMicroUsd: Int64?

    private let lock = NSCondition()
    private let observerPool = ObserverMemoryPool(limitBytes: kMaxTotalObserverBytes)
    private var chatRequestsUsed = 0
    private var uncachedPromptTokensTotal: Int64 = 0
    private var cachedPromptTokensTotal: Int64 = 0
    private var completionTokensTotal: Int64 = 0
    private var usageReportedRequests = 0
    private var usageUnreportedRequests = 0
    private var spendPicoUsd = UInt128Pair.zero
    private var spendIndeterminate = false
    private var cappedChatOwnerID: UInt64? = nil
    private var nextAdmissionID: UInt64 = 0
    private var cleanedUp = false
    private let urlSession: URLSession
    private let renewalLock = NSLock()
    private let sessionID = UUID().uuidString
    private var generation = 1
    private var windowSeconds: Int
    private var deadline: Double
    private var expiresAt: Int
    private var controlSocketPath: String?
    private var controlFD: Int32 = -1
    private var renewalAuthorizer: ((Int) throws -> Data)?
    #if SE_KEY_TESTING
    var testingPublicationFault = 0
    #endif

    init(
        listenPort: UInt16,
        upstreamBaseURL: URL,
        allowedModel: String,
        sessionToken: Data,
        apiKeyData: Data,
        maxChatRequests: Int,
        maxRequestBytes: Int,
        maxTokensCap: Int,
        streamTimeoutSeconds: Int,
        upstreamPID: pid_t?,
        upstreamBinding: UpstreamProcessBinding?,
        forceURLSession: Bool,
        sessionTokenFile: String?,
        defaultChatParams: [String: Any] = [:],
        ttlSeconds: Int = 3600,
        pricing: PricingRates? = nil,
        maxActualMicroUsd: Int64? = nil,
        renewalAuthorizer: ((Int) throws -> Data)? = nil
    ) {
        self.listenPort = listenPort
        self.upstreamBaseURL = upstreamBaseURL
        self.allowedModel = allowedModel
        self.activeSessionToken = sessionToken
        self.apiKeyData = apiKeyData
        self.maxChatRequests = maxChatRequests
        self.maxRequestBytes = maxRequestBytes
        self.maxTokensCap = maxTokensCap
        self.streamTimeoutSeconds = max(1, streamTimeoutSeconds)
        self.upstreamPID = upstreamPID
        self.upstreamBinding = upstreamBinding
        self.forceURLSession = forceURLSession
        self.sessionTokenFile = sessionTokenFile
        self.defaultChatParams = defaultChatParams
        self.windowSeconds = ttlSeconds
        self.deadline = continuousSeconds() + Double(ttlSeconds)
        self.expiresAt = Int(Date().timeIntervalSince1970) + ttlSeconds
        self.pricing = pricing
        self.maxActualMicroUsd = maxActualMicroUsd
        self.renewalAuthorizer = renewalAuthorizer

        let cfg = URLSessionConfiguration.ephemeral
        cfg.httpCookieStorage = nil
        cfg.urlCache = nil
        cfg.httpShouldSetCookies = false
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.connectionProxyDictionary = [:]
        cfg.timeoutIntervalForRequest = Double(self.streamTimeoutSeconds)
        cfg.timeoutIntervalForResource = Double(self.streamTimeoutSeconds)
        self.urlSession = URLSession(configuration: cfg)
    }

    private func estimatedMicroUsdLocked() -> Int64 {
        let rounded = spendPicoUsd.addingClamped(UInt128Pair(hi: 0, lo: 500_000)).divMod1000000().quotient
        return rounded.clampedInt64(max: kMaxWireMicroUsd)
    }

    private func isSpendCapExceededLocked() -> Bool {
        guard let capMicro = maxActualMicroUsd else { return false }
        let capPico = UInt128Pair.mul64(UInt64(capMicro), 1_000_000)
        return spendPicoUsd >= capPico
    }

    private func isSpendCapLowLocked() -> Bool {
        guard let capMicro = maxActualMicroUsd else { return false }
        if isSpendCapExceededLocked() { return false }
        let warnPico = UInt128Pair.mul64(UInt64(capMicro), 900_000)
        return spendPicoUsd >= warnPico
    }

    private func settleChatOutcomeLocked(outcome: ObserverOutcome, admissionID: UInt64?) {
        defer {
            if let owner = admissionID, cappedChatOwnerID == owner {
                cappedChatOwnerID = nil
                lock.broadcast()
            }
        }
        guard outcome.upstreamRequestWritten else {
            return
        }
        if outcome.transportComplete && outcome.httpStatus == 200, case .valid(let usage) = outcome.usageState {
            let uncached = usage.promptTokens - usage.cachedPromptTokens
            uncachedPromptTokensTotal = saturatingAddToken(uncachedPromptTokensTotal, uncached)
            cachedPromptTokensTotal = saturatingAddToken(cachedPromptTokensTotal, usage.cachedPromptTokens)
            completionTokensTotal = saturatingAddToken(completionTokensTotal, usage.completionTokens)
            if usageReportedRequests < kMaxChatRequestsLimit {
                usageReportedRequests += 1
            }
            if let rates = pricing {
                let p1 = UInt128Pair.mul64(UInt64(uncached), UInt64(rates.inputMicroPerM))
                let p2 = UInt128Pair.mul64(UInt64(usage.cachedPromptTokens), UInt64(rates.cachedInputMicroPerM))
                let p3 = UInt128Pair.mul64(UInt64(usage.completionTokens), UInt64(rates.outputMicroPerM))
                spendPicoUsd = spendPicoUsd.addingClamped(p1).addingClamped(p2).addingClamped(p3)
            }
            return
        }
        if maxActualMicroUsd != nil {
            if usageUnreportedRequests < kMaxChatRequestsLimit {
                usageUnreportedRequests += 1
            }
            spendIndeterminate = true
            return
        }
        // Uncapped session: clean non-200 HTTP rejections are non-metered; 200 without usage or interrupted framing increments telemetry only.
        if outcome.transportComplete, let st = outcome.httpStatus, st != 200 {
            return
        }
        if usageUnreportedRequests < kMaxChatRequestsLimit {
            usageUnreportedRequests += 1
        }
    }

    private func snapshotLocked() -> [String: Any] {
        let remaining = max(0, deadline - continuousSeconds())
        let left = Int(ceil(remaining))
        var snap: [String: Any] = [
            "protocol": 1,
            "session_id": sessionID,
            "pid": Int(getpid()),
            "model": allowedModel,
            "state": left > 0 && !cleanedUp ? "ON" : "OFF",
            "generation": generation,
            "remaining_seconds": left,
            "remaining_milliseconds": Int(floor(remaining * 1000)),
            "expires_at": expiresAt,
            "window_seconds": windowSeconds,
            "requests_used": chatRequestsUsed,
            "request_limit": maxChatRequests,
            "requests_remaining": max(0, maxChatRequests - chatRequestsUsed),
            "prompt_tokens": uncachedPromptTokensTotal + cachedPromptTokensTotal,
            "cached_prompt_tokens": cachedPromptTokensTotal,
            "completion_tokens": completionTokensTotal,
            "usage_reported_requests": usageReportedRequests,
            "usage_unreported_requests": usageUnreportedRequests,
        ]
        if pricing != nil {
            snap["estimated_micro_usd"] = estimatedMicroUsdLocked()
        }
        if let capMicro = maxActualMicroUsd {
            snap["max_actual_micro_usd"] = capMicro
            snap["spend_cap_exceeded"] = isSpendCapExceededLocked()
            snap["spend_cap_low"] = isSpendCapLowLocked()
            snap["spend_indeterminate"] = spendIndeterminate
        }
        return snap
    }

    private func credentialEnvelope(token: Data, generation: Int) throws -> Data {
        return try JSONSerialization.data(withJSONObject: ["token": String(decoding: token, as: UTF8.self),
            "session_id": sessionID, "generation": generation])
    }

    func expireIfNeeded() {
        lock.lock()
        let expired = continuousSeconds() >= deadline
        lock.unlock()
        if expired { cleanupAndExit(code: 0) }
    }

    func startControl(path originalPath: String) throws {
        let path = URL(fileURLWithPath: originalPath).standardizedFileURL.path
        let addressName = URL(fileURLWithPath: path).lastPathComponent
        guard addressName.utf8.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path),
              let rawTokenPath = sessionTokenFile, isSafeTokenFileForUnlink(rawTokenPath) else {
            throw NSError(domain: "SessionControl", code: 1)
        }
        let tokenPath = URL(fileURLWithPath: rawTokenPath).standardizedFileURL.path
        let dir = URL(fileURLWithPath: path).deletingLastPathComponent().path
        try ensureOwnedDirectoryComponent(path: dir, createIfMissing: true, requireMode0700: true)
        // Startup only, before any control/HTTP traffic is accepted. A relative Unix
        // address avoids sun_path limits without placing a socket outside runs/.
        let originalDir = Darwin.open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard originalDir >= 0 else { throw NSError(domain: "SessionControl", code: 7) }
        defer { Darwin.close(originalDir) }
        let controlDir = Darwin.open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard controlDir >= 0 else { throw NSError(domain: "SessionControl", code: 7) }
        defer { Darwin.close(controlDir) }
        guard Darwin.fchdir(controlDir) == 0 else { throw NSError(domain: "SessionControl", code: 7) }
        var restored = false
        defer { if !restored && Darwin.fchdir(originalDir) != 0 { Darwin._exit(1) } }
        // Refuse a live or untrusted endpoint. Recover an owned, unbound socket after SIGKILL.
        var existing = stat()
        if lstat(path, &existing) == 0 {
            guard (existing.st_mode & S_IFMT) == S_IFSOCK, existing.st_uid == geteuid(),
                  (existing.st_mode & 0o777) == 0o600 else { throw NSError(domain: "SessionControl", code: 2) }
            let probe = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
            guard probe >= 0 else { throw NSError(domain: "SessionControl", code: 2) }
            var target = sockaddr_un(); target.sun_family = sa_family_t(AF_UNIX)
            target.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
            withUnsafeMutableBytes(of: &target.sun_path) { bytes in
                bytes.copyBytes(from: Array(addressName.utf8) + [0] + Array(repeating: 0, count: bytes.count - addressName.utf8.count - 1))
            }
            let connected = withUnsafePointer(to: &target) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(probe, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            let probeError = errno
            Darwin.close(probe)
            guard connected != 0, probeError == ECONNREFUSED else { throw NSError(domain: "SessionControl", code: 2) }
            var current = stat()
            guard lstat(path, &current) == 0, current.st_ino == existing.st_ino,
                  current.st_dev == existing.st_dev, unlink(path) == 0 else { throw NSError(domain: "SessionControl", code: 2) }
        } else if errno != ENOENT { throw NSError(domain: "SessionControl", code: 2) }
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw NSError(domain: "SessionControl", code: 3) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { bytes in
            bytes.copyBytes(from: Array(addressName.utf8) + [0] + Array(repeating: 0,
                count: bytes.count - addressName.utf8.count - 1))
        }
        let bound = withUnsafePointer(to: &address) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0 else { Darwin.close(fd); throw NSError(domain: "SessionControl", code: 4) }
        controlSocketPath = path
        guard chmod(path, 0o600) == 0, Darwin.listen(fd, 8) == 0 else {
            Darwin.close(fd); throw NSError(domain: "SessionControl", code: 5)
        }
        controlFD = fd
        let tokenDir = URL(fileURLWithPath: tokenPath).deletingLastPathComponent().path
        _ = try readOwnedRegularFile0600(path: tokenPath)
        let stage = try writeStageFile0600(dir: tokenDir, prefix: "session", data:
            credentialEnvelope(token: activeSessionToken, generation: generation))
        try atomicPublishStageFile(dir: tokenDir, stagePath: stage, targetPath: tokenPath)
        guard Darwin.fchdir(originalDir) == 0 else { throw NSError(domain: "SessionControl", code: 7) }
        restored = true
        DispatchQueue.global().async {
            while true {
                let peer = Darwin.accept(fd, nil, nil)
                if peer < 0 { if errno == EINTR { continue }; break }
                DispatchQueue.global().async { self.handleControl(fd: peer) }
            }
        }
    }

    private func handleControl(fd: Int32) {
        defer { Darwin.close(fd) }
        var uid: uid_t = 0; var gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, uid == geteuid() else { return }
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        func reply(_ payload: [String: Any]) {
            if var bytes = try? JSONSerialization.data(withJSONObject: payload) {
                bytes.append(10); _ = writeAllToFD(fd, data: bytes)
            }
        }
        var raw = Data(); var part = [UInt8](repeating: 0, count: 512)
        while !raw.contains(10) && raw.count < 4096 {
            let n = Darwin.read(fd, &part, min(part.count, 4096 - raw.count))
            if n <= 0 { return }; raw.append(contentsOf: part[0..<n])
        }
        guard let end = raw.firstIndex(of: 10),
              let request = (try? JSONSerialization.jsonObject(with: raw.prefix(upTo: end))) as? [String: Any],
              let action = request["action"] as? String else { reply(["error": "invalid_request"]); return }
        guard request.keys.allSatisfy({ countTopLevelKeyOccurrences(in: Data(raw.prefix(upTo: end)), targetKey: $0) == 1 }) else {
            reply(["error": "duplicate_key"]); return
        }
        if action == "status", request.count == 1 {
            lock.lock(); let result = snapshotLocked(); lock.unlock(); reply(result); return
        }
        #if SE_KEY_TESTING
        if action == "debug_pool_stats", request.count == 1 {
            let st = observerPool.stats()
            reply(["current_reserved_bytes": st.current, "peak_reserved_bytes": st.peak, "limit_bytes": observerPool.limitBytes])
            return
        }
        #endif
        guard action == "renew", Set(request.keys) == Set(["action", "seconds", "session_id", "generation"]),
              let number = request["seconds"] as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue == Double(number.intValue), (1...86400).contains(number.intValue),
              let requestedGeneration = request["generation"] as? NSNumber,
              CFGetTypeID(requestedGeneration) != CFBooleanGetTypeID(),
              requestedGeneration.doubleValue == Double(requestedGeneration.intValue),
              request["session_id"] as? String == sessionID,
              renewalLock.try() else { reply(["error": "renewal_refused"]); return }
        defer { renewalLock.unlock() }
        func eligible() -> Bool {
            return !cleanedUp && generation == requestedGeneration.intValue
                && generation < maxSessionGenerations
                && continuousSeconds() < deadline && chatRequestsUsed < maxChatRequests
                && !spendIndeterminate && !isSpendCapExceededLocked() && cappedChatOwnerID == nil
        }
        lock.lock(); let canRenew = eligible(); lock.unlock()
        guard canRenew, let authorize = renewalAuthorizer, let tokenPath = sessionTokenFile else {
            reply(["error": "renewal_refused"]); return
        }
        var freshKey: Data
        do { freshKey = try authorize(number.intValue) }
        catch { reply(["error": "authorization_cancelled"]); return }
        defer { bestEffortZero(&freshKey) }
        lock.lock()
        guard eligible(), constantTimeEquals(freshKey, apiKeyData) else {
            lock.unlock(); reply(["error": "renewal_refused"]); return
        }
        let nextToken = Data(("se-session-" + randomHexBytes(32)).utf8)
        let tokenDir = URL(fileURLWithPath: tokenPath).deletingLastPathComponent().path
        var stage: String?; var published = false
        do {
            #if SE_KEY_TESTING
            if testingPublicationFault == 1 { throw NSError(domain: "SessionPublicationTest", code: 1) }
            #endif
            _ = try readOwnedRegularFile0600(path: tokenPath)
            stage = try writeStageFile0600(dir: tokenDir, prefix: "session", data:
                credentialEnvelope(token: nextToken, generation: generation + 1))
            try ensureDestinationNotSymlink(path: tokenPath)
            guard Darwin.rename(stage!, tokenPath) == 0 else { throw NSError(domain: "SessionControl", code: 6) }
            published = true
            #if SE_KEY_TESTING
            if testingPublicationFault == 2 { throw NSError(domain: "SessionPublicationTest", code: 2) }
            #endif
            try fsyncDirectory(tokenDir, context: "session renewal")
            retiredSessionTokens.append(activeSessionToken)
            activeSessionToken = nextToken
            generation += 1
            windowSeconds = number.intValue
            deadline = continuousSeconds() + Double(windowSeconds)
            expiresAt = Int(Date().timeIntervalSince1970) + windowSeconds
            let result = snapshotLocked()
            lock.unlock(); reply(result)
        } catch {
            lock.unlock()
            if let stage = stage { unlink(stage) }
            if published { cleanupAndExit(code: 1) }
            reply(["error": "publication_failed"])
        }
    }

    private func rejectStaleCredential(fd: Int32, providedToken: Data, nonce: String?) {
        // Complete the refusal before closing a socket whose request body may be unread.
        // Otherwise Darwin can reset the connection and discard the proof response.
        defer {
            _ = Darwin.shutdown(fd, SHUT_WR)
            var discarded = [UInt8](repeating: 0, count: 4096)
            var left = 65536
            while left > 0 {
                let n = Darwin.recv(fd, &discarded, min(left, discarded.count), MSG_DONTWAIT)
                if n <= 0 { break }
                left -= n
            }
        }
        lock.lock()
        let gen = generation; let key = activeSessionToken; let sid = sessionID
        let wasIssued = retiredSessionTokens.contains { constantTimeEquals(providedToken, $0) }
        lock.unlock()
        guard wasIssued, gen > 1, let nonce = nonce, nonce.count == 32,
              nonce.allSatisfy({ $0.isHexDigit && $0.isASCII }) else {
            sendHTTPError(clientFD: fd, status: 401, statusText: "Unauthorized", errorCode: "unauthorized", message: "Invalid session token")
            return
        }
        let material = "free-inference-stale-v1|\(sid)|\(gen)|\(nonce)"
        let proof = HMAC<SHA256>.authenticationCode(for: Data(material.utf8), using: SymmetricKey(data: key))
            .map { String(format: "%02x", $0) }.joined()
        let body = try! JSONSerialization.data(withJSONObject: ["error": ["code": "session_credential_stale",
            "session_id": sid, "generation": gen, "request_id": nonce, "proof": proof]])
        let header = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        _ = writeAllToFD(fd, data: Data(header.utf8)); _ = writeAllToFD(fd, data: body)
    }

    func cleanupAndExit(code: Int32) -> Never {
        lock.lock()
        if !cleanedUp {
            cleanedUp = true
            lock.broadcast()
            bestEffortZero(&apiKeyData)
            bestEffortZero(&activeSessionToken)
            for index in retiredSessionTokens.indices { bestEffortZero(&retiredSessionTokens[index]) }
            retiredSessionTokens.removeAll(keepingCapacity: false)
            if let path = controlSocketPath { unlink(path) }
            if controlFD >= 0 { Darwin.close(controlFD) }
            if let tokenPath = sessionTokenFile, isSafeTokenFileForUnlink(tokenPath) {
                unlink(tokenPath)
            }
            if let upid = upstreamPID, upid > 1, upid != getpid(), upid != getppid() {
                if kill(upid, 0) == 0 {
                    kill(upid, SIGTERM)
                }
            }
        }
        lock.unlock()
        Darwin.exit(code)
    }

    func handleClient(fd: Int32) {
        var myAdmissionID: UInt64? = nil
        var usageObserver: ChatUsageObserver? = nil
        var forceIncompleteOnFinalize = false
        var finalizedOutcome = false
        func finishRequestUsageOnce() {
            if finalizedOutcome { return }
            finalizedOutcome = true
            if let obs = usageObserver {
                let outcome = obs.detachAndFinalize(forceIncomplete: forceIncompleteOnFinalize)
                lock.lock()
                settleChatOutcomeLocked(outcome: outcome, admissionID: myAdmissionID)
                lock.unlock()
            } else if let owner = myAdmissionID {
                lock.lock()
                if cappedChatOwnerID == owner {
                    cappedChatOwnerID = nil
                    lock.broadcast()
                }
                lock.unlock()
            }
        }
        let delegate = StreamingForwardDelegate(clientFD: fd, timeoutSeconds: streamTimeoutSeconds)
        defer {
            finishRequestUsageOnce()
            delegate.closeClientSocket()
        }
        lock.lock(); let expired = continuousSeconds() >= deadline; lock.unlock()
        if expired {
            sendHTTPError(clientFD: fd, status: 401, statusText: "Unauthorized", errorCode: "session_expired", message: "Session authorization expired")
            return
        }

        var tv = timeval(tv_sec: 15, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Read headers up to \r\n\r\n (cap at 16384 bytes)
        let maxHeaderBytes = 16384
        var buffer = Data()
        var temp = [UInt8](repeating: 0, count: 2048)
        let delimiter = Data([0x0D, 0x0A, 0x0D, 0x0A])
        var headerEndRange: Range<Data.Index>? = nil

        while buffer.count < maxHeaderBytes {
            if let r = buffer.range(of: delimiter) {
                headerEndRange = r
                break
            }
            let n = Darwin.read(fd, &temp, min(temp.count, maxHeaderBytes - buffer.count))
            if n > 0 {
                buffer.append(contentsOf: temp[0..<n])
                if let r = buffer.range(of: delimiter) {
                    headerEndRange = r
                    break
                }
            } else if n == 0 {
                break
            } else {
                if errno == EINTR { continue }
                return
            }
        }

        guard let headerEnd = headerEndRange else {
            sendHTTPError(
                clientFD: fd,
                status: 400,
                statusText: "Bad Request",
                errorCode: "invalid_headers",
                message: "Malformed or oversized HTTP request headers"
            )
            return
        }

        let headerData = buffer.subdata(in: 0..<headerEnd.lowerBound)
        var bodyData = buffer.subdata(in: headerEnd.upperBound..<buffer.count)

        guard let headerText = String(data: headerData, encoding: .utf8) else {
            sendHTTPError(
                clientFD: fd,
                status: 400,
                statusText: "Bad Request",
                errorCode: "invalid_headers",
                message: "Request headers are not valid UTF-8"
            )
            return
        }

        let lines = headerText.components(separatedBy: "\r\n")
        guard let requestLine = lines.first, !requestLine.isEmpty else {
            sendHTTPError(
                clientFD: fd,
                status: 400,
                statusText: "Bad Request",
                errorCode: "invalid_request_line",
                message: "Empty HTTP request line"
            )
            return
        }

        let reqParts = requestLine.split(separator: " ", omittingEmptySubsequences: false)
        guard reqParts.count == 3, reqParts[2].hasPrefix("HTTP/1.") else {
            sendHTTPError(
                clientFD: fd,
                status: 400,
                statusText: "Bad Request",
                errorCode: "invalid_request_line",
                message: "Expected HTTP/1.x request line"
            )
            return
        }

        let method = String(reqParts[0])
        let rawTarget = String(reqParts[1])

        // Parse headers strictly
        var hostValues: [String] = []
        var contentLengthValues: [String] = []
        var hasTransferEncoding = false
        var authHeader: String? = nil
        var sessionRequestID: String? = nil
        var acceptHeader: String? = nil
        var contentTypeHeader: String? = nil

        for line in lines.dropFirst() {
            if line.isEmpty { continue }
            guard let colonIdx = line.firstIndex(of: ":") else {
                sendHTTPError(
                    clientFD: fd,
                    status: 400,
                    statusText: "Bad Request",
                    errorCode: "invalid_header",
                    message: "Malformed HTTP header line"
                )
                return
            }
            let rawName = String(line[..<colonIdx])
            if rawName.contains(" ") || rawName.contains("\t") {
                sendHTTPError(
                    clientFD: fd,
                    status: 400,
                    statusText: "Bad Request",
                    errorCode: "invalid_header",
                    message: "Invalid whitespace in header name"
                )
                return
            }
            let name = rawName.lowercased()
            let val = String(line[line.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
            switch name {
            case "host":
                hostValues.append(val.lowercased())
            case "content-length":
                contentLengthValues.append(val)
            case "transfer-encoding":
                hasTransferEncoding = true
            case "authorization":
                authHeader = val
            case "x-session-request-id":
                sessionRequestID = val
            case "accept":
                acceptHeader = val
            case "content-type":
                contentTypeHeader = val
            default:
                break
            }
        }

        // 1. Validate Host header (DNS rebinding protection)
        let allowedHosts: Set<String> = [
            "127.0.0.1:\(listenPort)",
            "localhost:\(listenPort)",
        ]
        guard hostValues.count == 1, allowedHosts.contains(hostValues[0]) else {
            sendHTTPError(
                clientFD: fd,
                status: 400,
                statusText: "Bad Request",
                errorCode: "invalid_host",
                message: "Host header must match 127.0.0.1:\(listenPort)"
            )
            return
        }

        // 2. Reject Transfer-Encoding and duplicate Content-Length
        if hasTransferEncoding {
            sendHTTPError(
                clientFD: fd,
                status: 400,
                statusText: "Bad Request",
                errorCode: "transfer_encoding_rejected",
                message: "Transfer-Encoding is not supported; use explicit Content-Length"
            )
            return
        }
        if contentLengthValues.count > 1 {
            sendHTTPError(
                clientFD: fd,
                status: 400,
                statusText: "Bad Request",
                errorCode: "duplicate_content_length",
                message: "Multiple Content-Length headers are not allowed"
            )
            return
        }

        // 3. Verify caller session token in constant time
        guard let rawAuth = authHeader, rawAuth.hasPrefix("Bearer ") else {
            sendHTTPError(
                clientFD: fd,
                status: 401,
                statusText: "Unauthorized",
                errorCode: "unauthorized",
                message: "Missing Bearer session token"
            )
            return
        }
        let providedToken = Data(String(rawAuth.dropFirst("Bearer ".count)).trimmingCharacters(in: .whitespaces).utf8)
        guard constantTimeEquals(providedToken, sessionToken) else {
            rejectStaleCredential(fd: fd, providedToken: providedToken, nonce: sessionRequestID)
            return
        }

        // 4. Strict path & method validation
        if !rawTarget.hasPrefix("/") || rawTarget.contains("..") || rawTarget.contains("\\") || rawTarget.contains("%") {
            sendHTTPError(
                clientFD: fd,
                status: 403,
                statusText: "Forbidden",
                errorCode: "forbidden_path",
                message: "Path is not permitted"
            )
            return
        }

        let targetParts = rawTarget.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
        let pathOnly = String(targetParts[0])
        let queryPart = targetParts.count > 1 ? String(targetParts[1]) : nil

        let isModelsGet = (method == "GET" && (pathOnly == "/v1/models" || pathOnly == "/v1/models/"))
        let isChatPost = (method == "POST" && queryPart == nil && (pathOnly == "/v1/chat/completions" || pathOnly == "/v1/chat/completions/"))

        if !isModelsGet && !isChatPost {
            sendHTTPError(
                clientFD: fd,
                status: 403,
                statusText: "Forbidden",
                errorCode: "forbidden_endpoint",
                message: "Only GET /v1/models and POST /v1/chat/completions are permitted"
            )
            return
        }

        var outboundBody: Data? = nil
        var upstreamPath = isModelsGet ? "/models" : "/chat/completions"
        if isModelsGet, let q = queryPart, !q.isEmpty {
            upstreamPath += "?" + q
        }

        if isChatPost {
            guard let clStr = contentLengthValues.first else {
                sendHTTPError(
                    clientFD: fd,
                    status: 411,
                    statusText: "Length Required",
                    errorCode: "length_required",
                    message: "Content-Length header is required for POST /v1/chat/completions"
                )
                return
            }
            guard let contentLength = Int(clStr), contentLength >= 0, String(contentLength) == clStr else {
                sendHTTPError(
                    clientFD: fd,
                    status: 400,
                    statusText: "Bad Request",
                    errorCode: "invalid_content_length",
                    message: "Invalid Content-Length header"
                )
                return
            }
            if contentLength > maxRequestBytes {
                sendHTTPError(
                    clientFD: fd,
                    status: 413,
                    statusText: "Payload Too Large",
                    errorCode: "payload_too_large",
                    message: "Request body exceeds max_request_bytes (\(maxRequestBytes))"
                )
                return
            }

            while bodyData.count < contentLength {
                let needed = min(temp.count, contentLength - bodyData.count)
                let n = Darwin.read(fd, &temp, needed)
                if n > 0 {
                    bodyData.append(contentsOf: temp[0..<n])
                } else if n == 0 {
                    sendHTTPError(
                        clientFD: fd,
                        status: 400,
                        statusText: "Bad Request",
                        errorCode: "truncated_body",
                        message: "Unexpected EOF while reading request body"
                    )
                    return
                } else {
                    if errno == EINTR { continue }
                    return
                }
            }
            if bodyData.count > contentLength {
                bodyData = bodyData.subdata(in: 0..<contentLength)
            }

            // Reject duplicate or missing top-level "model" key before NSDictionary deserialization
            guard let modelKeyCount = countTopLevelKeyOccurrences(in: bodyData, targetKey: "model") else {
                sendHTTPError(
                    clientFD: fd,
                    status: 400,
                    statusText: "Bad Request",
                    errorCode: "invalid_json",
                    message: "Request body is not a valid JSON object"
                )
                return
            }
            if modelKeyCount != 1 {
                sendHTTPError(
                    clientFD: fd,
                    status: 400,
                    statusText: "Bad Request",
                    errorCode: "duplicate_or_missing_model_key",
                    message: "JSON body must contain exactly one top-level 'model' key (found \(modelKeyCount))"
                )
                return
            }

            guard
                let rawObj = try? JSONSerialization.jsonObject(with: bodyData, options: []),
                var jsonDict = rawObj as? [String: Any]
            else {
                sendHTTPError(
                    clientFD: fd,
                    status: 400,
                    statusText: "Bad Request",
                    errorCode: "invalid_json",
                    message: "Request body must be a JSON object"
                )
                return
            }

            guard let reqModel = jsonDict["model"] as? String, reqModel == allowedModel else {
                sendHTTPError(
                    clientFD: fd,
                    status: 403,
                    statusText: "Forbidden",
                    errorCode: "model_not_allowed",
                    message: "Requested model does not match pinned allowed model '\(allowedModel)'"
                )
                return
            }

            // Merge non-overwriting default chat parameters (e.g. passthrough thinking=false / include_reasoning=false)
            for (key, defaultVal) in defaultChatParams {
                if key == "chat_template_kwargs", let defaultKw = defaultVal as? [String: Any] {
                    if jsonDict[key] == nil {
                        jsonDict[key] = defaultKw
                    } else if var existingKw = jsonDict[key] as? [String: Any] {
                        for (subKey, subVal) in defaultKw {
                            if existingKw[subKey] == nil {
                                existingKw[subKey] = subVal
                            }
                        }
                        jsonDict[key] = existingKw
                    }
                } else if jsonDict[key] == nil {
                    jsonDict[key] = defaultVal
                }
            }

            // Clamp n (and best_of when present) to 1 so worst-case output spend is bounded to 1 completion per request
            if jsonDict["n"] != nil {
                jsonDict["n"] = 1
            }
            if jsonDict["best_of"] != nil {
                jsonDict["best_of"] = 1
            }

            // Clamp max_tokens and strip alternate token-limit keys when maxTokensCap > 0
            if maxTokensCap > 0 {
                var effectiveMax = maxTokensCap
                if let mt = jsonDict["max_tokens"] as? Int, mt > 0 {
                    effectiveMax = min(effectiveMax, mt)
                } else if let mct = jsonDict["max_completion_tokens"] as? Int, mct > 0 {
                    effectiveMax = min(effectiveMax, mct)
                } else if let mot = jsonDict["maxOutputTokens"] as? Int, mot > 0 {
                    effectiveMax = min(effectiveMax, mot)
                }
                jsonDict.removeValue(forKey: "max_completion_tokens")
                jsonDict.removeValue(forKey: "maxOutputTokens")
                jsonDict["max_tokens"] = effectiveMax
            }

            guard let canonicalBody = try? JSONSerialization.data(withJSONObject: jsonDict, options: []) else {
                sendHTTPError(
                    clientFD: fd,
                    status: 500,
                    statusText: "Internal Server Error",
                    errorCode: "serialization_error",
                    message: "Failed to serialize validated JSON payload"
                )
                return
            }

            // Enforce maxRequestBytes on the final merged, canonicalized JSON payload before consuming chat request budget
            if canonicalBody.count > maxRequestBytes {
                sendHTTPError(
                    clientFD: fd,
                    status: 413,
                    statusText: "Payload Too Large",
                    errorCode: "payload_too_large",
                    message: "Request body after default parameter merge exceeds max_request_bytes (\(maxRequestBytes))"
                )
                return
            }

            lock.lock()
            let guardTokens = retiredSessionTokens + [activeSessionToken]
            let guardKey = apiKeyData
            lock.unlock()
            let material = combinedCredentialLeakMaterial(guardTokens + [guardKey])
            var guardNodes = 0
            if jsonNodeContainsCredentialLeak(jsonDict, needles: material.needles, rawSecrets: material.raw,
                    containerDepth: 0, embeddedDecodeDepth: 0, visitedNodes: &guardNodes)
                || stringContainsCredentialLeak(String(decoding: bodyData, as: UTF8.self),
                    needles: material.needles, rawSecrets: material.raw)
                || stringContainsCredentialLeak(String(decoding: canonicalBody, as: UTF8.self),
                    needles: material.needles, rawSecrets: material.raw) {
                sendHTTPError(
                    clientFD: fd,
                    status: 400,
                    statusText: "Bad Request",
                    errorCode: "credential_leak_blocked",
                    message: "Outbound request blocked: request body contains session or provider credential material"
                )
                return
            }

            // Enforce session chat request and spend budgets (with owned single-flight admission on capped sessions)
            let waitDeadline = continuousSeconds() + Double(streamTimeoutSeconds)
            var waitedInQueue = false
            lock.lock()
            if maxActualMicroUsd != nil {
                while cappedChatOwnerID != nil {
                    waitedInQueue = true
                    if isClientWriteSideDisconnected(fd) {
                        lock.unlock()
                        return
                    }
                    if cleanedUp || continuousSeconds() >= deadline {
                        lock.unlock()
                        sendHTTPError(clientFD: fd, status: 401, statusText: "Unauthorized", errorCode: "session_expired", message: "Session authorization expired")
                        return
                    }
                    if continuousSeconds() >= waitDeadline {
                        lock.unlock()
                        sendHTTPError(clientFD: fd, status: 503, statusText: "Service Unavailable", errorCode: "session_busy", message: "Timed out waiting for in-flight spend-capped request to complete")
                        return
                    }
                    lock.wait(until: Date(timeIntervalSinceNow: 0.1))
                }
                if isClientWriteSideDisconnected(fd) {
                    lock.unlock()
                    return
                }
                if waitedInQueue && continuousSeconds() >= waitDeadline {
                    lock.unlock()
                    sendHTTPError(clientFD: fd, status: 503, statusText: "Service Unavailable", errorCode: "session_busy", message: "Timed out waiting for in-flight spend-capped request to complete")
                    return
                }
            }
            if isClientWriteSideDisconnected(fd) {
                lock.unlock()
                return
            }
            if cleanedUp || continuousSeconds() >= deadline {
                lock.unlock()
                sendHTTPError(clientFD: fd, status: 401, statusText: "Unauthorized", errorCode: "session_expired", message: "Session authorization expired")
                return
            }
            // Revalidate presented token under lock after any wait (closes token-rotation race across queued chats)
            if !constantTimeEquals(providedToken, activeSessionToken) {
                lock.unlock()
                rejectStaleCredential(fd: fd, providedToken: providedToken, nonce: sessionRequestID)
                return
            }
            if spendIndeterminate {
                lock.unlock()
                sendHTTPError(
                    clientFD: fd,
                    status: 429,
                    statusText: "Too Many Requests",
                    errorCode: "session_spend_indeterminate",
                    message: "Session spend could not be verified after an unreported or interrupted upstream request; stop and start a fresh session."
                )
                return
            }
            if let capMicro = maxActualMicroUsd, isSpendCapExceededLocked() {
                lock.unlock()
                sendHTTPError(
                    clientFD: fd,
                    status: 429,
                    statusText: "Too Many Requests",
                    errorCode: "session_spend_budget_exceeded",
                    message: "Session spend cap (\(formatMicroUsdForMessage(capMicro))) reached"
                )
                return
            }
            if chatRequestsUsed >= maxChatRequests {
                lock.unlock()
                sendHTTPError(
                    clientFD: fd,
                    status: 429,
                    statusText: "Too Many Requests",
                    errorCode: "session_request_budget_exceeded",
                    message: "Session chat request cap (\(maxChatRequests)) reached"
                )
                return
            }
            if maxActualMicroUsd != nil {
                nextAdmissionID &+= 1
                if nextAdmissionID == 0 { nextAdmissionID = 1 }
                myAdmissionID = nextAdmissionID
                cappedChatOwnerID = myAdmissionID
            }
            chatRequestsUsed += 1
            lock.unlock()

            // Start the upstream request timeout window after single-flight admission is acquired.
            delegate.resetDeadline()
            let obs = ChatUsageObserver(pool: observerPool)
            usageObserver = obs
            delegate.setUsageObserver(obs)
            outboundBody = canonicalBody
        }

        // Switch client socket to non-blocking mode for downstream streaming/writes
        setNonBlocking(fd)

        guard let apiKeyStr = String(data: apiKeyData, encoding: .utf8) else {
            sendHTTPError(
                clientFD: fd,
                status: 500,
                statusText: "Internal Server Error",
                errorCode: "key_encoding_error",
                message: "Invalid UTF-8 in unsealed key"
            )
            return
        }

        // 5. Route loopback HTTP upstream via verified POSIX socket (F1), or pinned HTTPS via URLSession
        if let binding = upstreamBinding, !forceURLSession {
            forwardViaVerifiedLoopbackSocket(
                binding: binding,
                delegate: delegate,
                usageObserver: usageObserver,
                method: method,
                upstreamBaseURL: upstreamBaseURL,
                upstreamPath: upstreamPath,
                acceptHeader: acceptHeader,
                contentTypeHeader: isChatPost ? (contentTypeHeader ?? "application/json") : nil,
                outboundBody: outboundBody,
                apiKeyStr: apiKeyStr
            )
            finishRequestUsageOnce()
            return
        }

        let baseStr = upstreamBaseURL.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let targetURL = URL(string: baseStr + upstreamPath) else {
            sendHTTPError(
                clientFD: fd,
                status: 500,
                statusText: "Internal Server Error",
                errorCode: "invalid_upstream_url",
                message: "Could not construct upstream URL"
            )
            return
        }

        var upstreamReq = URLRequest(url: targetURL)
        upstreamReq.httpMethod = method
        upstreamReq.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        if let accept = acceptHeader, !accept.isEmpty {
            upstreamReq.setValue(accept, forHTTPHeaderField: "Accept")
        } else {
            upstreamReq.setValue("application/json", forHTTPHeaderField: "Accept")
        }
        if isChatPost {
            upstreamReq.setValue(contentTypeHeader ?? "application/json", forHTTPHeaderField: "Content-Type")
            upstreamReq.httpBody = outboundBody
        }
        upstreamReq.setValue("Bearer \(apiKeyStr)", forHTTPHeaderField: "Authorization")

        let session = URLSession(configuration: urlSession.configuration, delegate: delegate, delegateQueue: nil)
        let task = session.dataTask(with: upstreamReq)
        usageObserver?.markUpstreamRequestWritten()
        task.resume()
        let finished = delegate.waitForCompletion(timeoutSeconds: Double(streamTimeoutSeconds))
        if !finished {
            forceIncompleteOnFinalize = true
            delegate.cancelAndShutdownSocket()
            task.cancel()
            session.invalidateAndCancel()
            _ = delegate.waitForCompletion(timeoutSeconds: 2.0)
        } else {
            session.finishTasksAndInvalidate()
        }
        finishRequestUsageOnce()
    }

    private func isClientWriteSideDisconnected(_ fd: Int32) -> Bool {
        // Detect peer write-side teardown (RST / EPIPE / ECONNRESET / EBADF) without falsely rejecting
        // a legal HTTP/1.1 client that has merely half-closed its write side via shutdown(SHUT_WR).
        let kq = kqueue()
        if kq >= 0 {
            defer { close(kq) }
            var ch = kevent(
                ident: UInt(fd),
                filter: Int16(EVFILT_WRITE),
                flags: UInt16(EV_ADD | EV_ONESHOT),
                fflags: 0,
                data: 0,
                udata: nil
            )
            var ev = kevent()
            var ts = timespec(tv_sec: 0, tv_nsec: 0)
            let n = kevent(kq, &ch, 1, &ev, 1, &ts)
            if n < 0 {
                if errno == EBADF { return true }
            } else if n > 0 {
                if (ev.flags & UInt16(EV_EOF | EV_ERROR)) != 0 || ev.fflags != 0 {
                    return true
                }
            }
        }
        var errVal: Int32 = 0
        var errLen = socklen_t(MemoryLayout<Int32>.size)
        if getsockopt(fd, SOL_SOCKET, SO_ERROR, &errVal, &errLen) == 0 && errVal != 0 {
            return true
        }
        return false
    }

    private func writeNonBlocking(_ fd: Int32, data: Data, delegate: StreamingForwardDelegate) -> Bool {
        if data.isEmpty { return true }
        return data.withUnsafeBytes { rawBuf -> Bool in
            guard let base = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return true
            }
            var sent = 0
            while sent < data.count {
                if DispatchTime.now().uptimeNanoseconds >= delegate.deadlineUptimeNs {
                    return false
                }
                let n = Darwin.write(fd, base.advanced(by: sent), data.count - sent)
                if n > 0 {
                    sent += n
                    continue
                }
                if n < 0 && errno == EINTR {
                    continue
                }
                if n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                    let remMs = delegate.remainingMilliseconds()
                    if remMs <= 0 {
                        return false
                    }
                    var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                    let prc = Darwin.poll(&pfd, 1, min(100, remMs))
                    if prc < 0 && errno != EINTR {
                        return false
                    }
                    if (pfd.revents & Int16(POLLERR | POLLHUP | POLLNVAL)) != 0 {
                        return false
                    }
                    continue
                }
                return false
            }
            return true
        }
    }

    private func readSomeNonBlocking(_ fd: Int32, maxBytes: Int, delegate: StreamingForwardDelegate) -> Int {
        var temp = [UInt8](repeating: 0, count: maxBytes)
        while true {
            if DispatchTime.now().uptimeNanoseconds >= delegate.deadlineUptimeNs {
                return -1
            }
            let n = Darwin.read(fd, &temp, maxBytes)
            if n > 0 {
                return n
            }
            if n == 0 {
                return 0
            }
            if errno == EINTR {
                continue
            }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                let remMs = delegate.remainingMilliseconds()
                if remMs <= 0 {
                    return -1
                }
                var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                let prc = Darwin.poll(&pfd, 1, min(100, remMs))
                if prc < 0 && errno != EINTR {
                    return -1
                }
                if (pfd.revents & Int16(POLLNVAL)) != 0 {
                    return -1
                }
                continue
            }
            return -1
        }
    }

    private func readIntoBufferNonBlocking(_ fd: Int32, buffer: inout Data, maxChunk: Int = 4096, delegate: StreamingForwardDelegate) -> Int {
        var temp = [UInt8](repeating: 0, count: maxChunk)
        while true {
            if DispatchTime.now().uptimeNanoseconds >= delegate.deadlineUptimeNs {
                return -1
            }
            let n = Darwin.read(fd, &temp, maxChunk)
            if n > 0 {
                buffer.append(contentsOf: temp[0..<n])
                return n
            }
            if n == 0 {
                return 0
            }
            if errno == EINTR {
                continue
            }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                let remMs = delegate.remainingMilliseconds()
                if remMs <= 0 {
                    return -1
                }
                var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                let prc = Darwin.poll(&pfd, 1, min(100, remMs))
                if prc < 0 && errno != EINTR {
                    return -1
                }
                if (pfd.revents & Int16(POLLNVAL)) != 0 {
                    return -1
                }
                continue
            }
            return -1
        }
    }

    private func forwardViaVerifiedLoopbackSocket(
        binding: UpstreamProcessBinding,
        delegate: StreamingForwardDelegate,
        usageObserver: ChatUsageObserver?,
        method: String,
        upstreamBaseURL: URL,
        upstreamPath: String,
        acceptHeader: String?,
        contentTypeHeader: String?,
        outboundBody: Data?,
        apiKeyStr: String
    ) {
        let upFD = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard upFD >= 0 else {
            delegate.sendErrorSafe(
                status: 502,
                statusText: "Bad Gateway",
                errorCode: "upstream_error",
                message: "Failed to allocate upstream socket"
            )
            return
        }
        var closedUp = false
        defer {
            if !closedUp {
                _ = Darwin.close(upFD)
            }
        }
        setNonBlocking(upFD)

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = binding.port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let connectRC = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.connect(upFD, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if connectRC != 0 {
            if errno == EINPROGRESS {
                let connectLimitNs = min(
                    delegate.deadlineUptimeNs,
                    DispatchTime.now().uptimeNanoseconds + 5_000_000_000
                )
                var connected = false
                while let sliceMs = remainingConnectSliceMs(
                    nowNs: DispatchTime.now().uptimeNanoseconds,
                    connectLimitNs: connectLimitNs
                ) {
                    var pfd = pollfd(fd: upFD, events: Int16(POLLOUT), revents: 0)
                    let prc = Darwin.poll(&pfd, 1, sliceMs)
                    if prc > 0 {
                        var soErr: Int32 = 0
                        var soLen = socklen_t(MemoryLayout<Int32>.size)
                        if getsockopt(upFD, SOL_SOCKET, SO_ERROR, &soErr, &soLen) == 0 && soErr == 0 {
                            connected = true
                        }
                        break
                    } else if prc < 0 && errno != EINTR {
                        break
                    }
                }
                if !connected {
                    delegate.sendErrorSafe(
                        status: 502,
                        statusText: "Bad Gateway",
                        errorCode: "upstream_error",
                        message: "Timed out or failed connecting to loopback upstream"
                    )
                    return
                }
            } else {
                delegate.sendErrorSafe(
                    status: 502,
                    statusText: "Bad Gateway",
                    errorCode: "upstream_error",
                    message: "Failed connecting to loopback upstream (errno=\(errno))"
                )
                return
            }
        }

        // CRITICAL F1 CHECK: Verify after connect() that the approved vendor process (pid + startTime)
        // still owns the exact listening kernel PCB (expectedListenPCB) without SO_REUSEPORT before
        // writing a single byte of the request or Authorization header.
        if !verifyUpstreamBinding(binding) {
            _ = Darwin.close(upFD)
            closedUp = true
            writeStderr("CRITICAL: Upstream listener identity mismatch detected on 127.0.0.1:\(binding.port) for pid \(binding.pid); aborting before sending credentials.")
            delegate.sendErrorSafe(
                status: 502,
                statusText: "Bad Gateway",
                errorCode: "upstream_identity_mismatch",
                message: "Upstream process or listening socket identity changed; refusing to forward credentials"
            )
            delegate.closeClientSocket()
            cleanupAndExit(code: 1)
        }

        let basePath = upstreamBaseURL.path.isEmpty ? "" : (upstreamBaseURL.path == "/" ? "" : upstreamBaseURL.path.trimmingCharacters(in: CharacterSet(charactersIn: "/")))
        let fullRequestPath = basePath.isEmpty ? upstreamPath : ("/" + basePath + upstreamPath)
        let cleanAccept = (acceptHeader ?? "application/json")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\n", with: "")

        var reqHeader =
            "\(method) \(fullRequestPath) HTTP/1.1\r\n" +
            "Host: 127.0.0.1:\(binding.port)\r\n" +
            "Connection: close\r\n" +
            "Accept-Encoding: identity\r\n" +
            "Accept: \(cleanAccept)\r\n" +
            "Authorization: Bearer \(apiKeyStr)\r\n"
        if let ct = contentTypeHeader {
            let cleanCT = ct
                .replacingOccurrences(of: "\r", with: "")
                .replacingOccurrences(of: "\n", with: "")
            reqHeader += "Content-Type: \(cleanCT)\r\n"
        }
        if let body = outboundBody {
            reqHeader += "Content-Length: \(body.count)\r\n"
        }
        reqHeader += "\r\n"

        guard let reqHeaderData = reqHeader.data(using: .utf8) else {
            delegate.sendErrorSafe(
                status: 502,
                statusText: "Bad Gateway",
                errorCode: "upstream_error",
                message: "Failed encoding request headers for upstream"
            )
            return
        }
        // Conservative write milestone: mark upstream write attempted immediately before first write()
        usageObserver?.markUpstreamRequestWritten()
        guard writeNonBlocking(upFD, data: reqHeaderData, delegate: delegate) else {
            delegate.sendErrorSafe(
                status: 502,
                statusText: "Bad Gateway",
                errorCode: "upstream_error",
                message: "Failed sending request headers to upstream"
            )
            return
        }
        if let body = outboundBody, !body.isEmpty {
            guard writeNonBlocking(upFD, data: body, delegate: delegate) else {
                delegate.sendErrorSafe(
                    status: 502,
                    statusText: "Bad Gateway",
                    errorCode: "upstream_error",
                    message: "Failed sending request body to upstream"
                )
                return
            }
        }

        // Read upstream response headers up to \r\n\r\n (cap at 32768 bytes)
        let maxRespHeaderBytes = 32768
        var upBuf = Data()
        let delimiter = Data([0x0D, 0x0A, 0x0D, 0x0A])
        var respHeaderEnd: Range<Data.Index>? = nil

        while upBuf.count < maxRespHeaderBytes {
            if let r = upBuf.range(of: delimiter) {
                respHeaderEnd = r
                break
            }
            let n = readIntoBufferNonBlocking(
                upFD,
                buffer: &upBuf,
                maxChunk: min(4096, maxRespHeaderBytes - upBuf.count),
                delegate: delegate
            )
            if n > 0 {
                if let r = upBuf.range(of: delimiter) {
                    respHeaderEnd = r
                    break
                }
            } else if n == 0 {
                break
            } else {
                delegate.sendErrorSafe(
                    status: 502,
                    statusText: "Bad Gateway",
                    errorCode: "upstream_error",
                    message: "Upstream read timed out or failed before response headers completed"
                )
                return
            }
        }

        guard let headerEnd = respHeaderEnd else {
            delegate.sendErrorSafe(
                status: 502,
                statusText: "Bad Gateway",
                errorCode: "upstream_error",
                message: "Malformed or oversized upstream HTTP response headers"
            )
            return
        }

        // Strict raw-byte parsing of status line and RFC 9110 header field lines (preserves legal obs-text 0x80..0xFF)
        let rawHeaderBytes = [UInt8](upBuf.subdata(in: 0..<headerEnd.lowerBound))
        var remBuf = Data(upBuf.subdata(in: headerEnd.upperBound..<upBuf.count))

        var rawLines: [[UInt8]] = []
        var lineStart = 0
        var scanIdx = 0
        while scanIdx < rawHeaderBytes.count {
            if scanIdx + 1 < rawHeaderBytes.count && rawHeaderBytes[scanIdx] == 0x0D && rawHeaderBytes[scanIdx + 1] == 0x0A {
                rawLines.append(Array(rawHeaderBytes[lineStart..<scanIdx]))
                scanIdx += 2
                lineStart = scanIdx
            } else {
                scanIdx += 1
            }
        }
        rawLines.append(Array(rawHeaderBytes[lineStart..<rawHeaderBytes.count]))

        guard let statusLineBytes = rawLines.first,
              let statusCode = parseHTTPStatusLineBytes(statusLineBytes) else {
            delegate.sendErrorSafe(
                status: 502,
                statusText: "Bad Gateway",
                errorCode: "upstream_error",
                message: "Invalid upstream HTTP status line"
            )
            return
        }

        var respContentType = "application/json"
        var isChunked = false
        var respContentLength: Int? = nil
        var contentLengthCount = 0
        var transferEncodingCount = 0
        var framingInvalid = false

        for lineBytes in rawLines.dropFirst() {
            if lineBytes.isEmpty {
                framingInvalid = true
                continue
            }
            guard let parsed = parseHTTPFieldLineBytes(lineBytes) else {
                framingInvalid = true
                continue
            }
            switch parsed.nameLowerASCII {
            case "content-type":
                let trimmed = trimASCIIOWS(parsed.valueBytes)
                if let ct = parseASCIIPureASCIIString(trimmed), !ct.isEmpty {
                    respContentType = ct
                } else {
                    framingInvalid = true
                }
            case "transfer-encoding":
                transferEncodingCount += 1
                let trimmed = trimASCIIOWS(parsed.valueBytes)
                if let teStr = parseASCIIPureASCIIString(trimmed), teStr.lowercased() == "chunked" {
                    isChunked = true
                } else {
                    framingInvalid = true
                }
            case "content-length":
                contentLengthCount += 1
                let trimmed = trimASCIIOWS(parsed.valueBytes)
                if let clStr = parseASCIIPureASCIIString(trimmed),
                   !clStr.isEmpty,
                   clStr.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
                   let cl = Int(clStr), cl >= 0 {
                    respContentLength = cl
                } else {
                    framingInvalid = true
                }
            default:
                // Strip Set-Cookie and all other non-essential headers; legal obs-text accepted above
                break
            }
        }

        if contentLengthCount > 1 || transferEncodingCount > 1 || (transferEncodingCount > 0 && contentLengthCount > 0) {
            framingInvalid = true
        }
        if framingInvalid {
            usageObserver?.markFramingInvalid()
        }
        usageObserver?.onHeaders(status: statusCode, contentType: respContentType)

        guard delegate.writeHeadersSafe(status: statusCode, contentType: respContentType) else {
            return
        }

        if isChunked {
            let crlf = Data([0x0D, 0x0A])
            var sawCleanTerminalTrailer = false
            while true {
                // Find chunk-size line ending in \r\n
                while remBuf.range(of: crlf) == nil {
                    if remBuf.count > 4096 {
                        return
                    }
                    let n = readIntoBufferNonBlocking(upFD, buffer: &remBuf, delegate: delegate)
                    if n <= 0 {
                        return
                    }
                }
                guard let lineRange = remBuf.range(of: crlf) else {
                    return
                }
                let sizeLineBytes = [UInt8](remBuf.subdata(in: 0..<lineRange.lowerBound))
                remBuf.removeSubrange(0..<lineRange.upperBound)

                guard let parsedChunk = parseChunkSizeLineBytes(sizeLineBytes) else {
                    usageObserver?.markFramingInvalid()
                    return
                }
                if parsedChunk.hasExtension {
                    // Chunk extensions are unsupported for metering; fail closed on framing completeness.
                    framingInvalid = true
                    usageObserver?.markFramingInvalid()
                }
                let chunkSize = parsedChunk.size

                if chunkSize == 0 {
                    // Terminal chunk: validate every non-empty trailer line and require explicit terminating empty \r\n
                    while true {
                        if let tRange = remBuf.range(of: crlf) {
                            let trailerLen = tRange.lowerBound
                            let trailerBytes = [UInt8](remBuf.subdata(in: 0..<trailerLen))
                            remBuf.removeSubrange(0..<tRange.upperBound)
                            if trailerLen == 0 {
                                sawCleanTerminalTrailer = true
                                break
                            }
                            if parseHTTPFieldLineBytes(trailerBytes) == nil {
                                framingInvalid = true
                                usageObserver?.markFramingInvalid()
                            }
                        } else {
                            if remBuf.count > 16384 {
                                usageObserver?.markFramingInvalid()
                                return
                            }
                            let n = readIntoBufferNonBlocking(upFD, buffer: &remBuf, delegate: delegate)
                            if n <= 0 {
                                // EOF before terminating empty trailer line -> framing incomplete!
                                return
                            }
                        }
                    }
                    break
                }

                var remainingChunk = chunkSize
                while remainingChunk > 0 {
                    if !remBuf.isEmpty {
                        let take = min(remainingChunk, remBuf.count)
                        let slice = Data(remBuf.subdata(in: 0..<take))
                        remBuf.removeSubrange(0..<take)
                        remainingChunk -= take
                        usageObserver?.onChunk(slice)
                        if !delegate.writeSafe(slice) {
                            return
                        }
                    } else {
                        let n = readIntoBufferNonBlocking(upFD, buffer: &remBuf, maxChunk: min(16384, remainingChunk + 2), delegate: delegate)
                        if n <= 0 {
                            return
                        }
                    }
                }

                // Consume trailing \r\n after chunk data
                while remBuf.count < 2 {
                    let n = readIntoBufferNonBlocking(upFD, buffer: &remBuf, maxChunk: 2, delegate: delegate)
                    if n <= 0 {
                        return
                    }
                }
                guard remBuf[remBuf.startIndex] == 0x0D && remBuf[remBuf.startIndex + 1] == 0x0A else {
                    usageObserver?.markFramingInvalid()
                    return
                }
                remBuf.removeSubrange(0..<2)
            }
            if sawCleanTerminalTrailer && !framingInvalid {
                usageObserver?.markTransportComplete()
            }
        } else if let cl = respContentLength {
            var remaining = cl
            if !remBuf.isEmpty {
                let take = min(remaining, remBuf.count)
                let slice = Data(remBuf.subdata(in: 0..<take))
                remBuf.removeSubrange(0..<take)
                remaining -= take
                usageObserver?.onChunk(slice)
                if !delegate.writeSafe(slice) {
                    return
                }
            }
            while remaining > 0 {
                var chunkBuf = Data()
                let n = readIntoBufferNonBlocking(upFD, buffer: &chunkBuf, maxChunk: min(16384, remaining), delegate: delegate)
                if n <= 0 {
                    return
                }
                remaining -= chunkBuf.count
                usageObserver?.onChunk(chunkBuf)
                if !delegate.writeSafe(chunkBuf) {
                    return
                }
            }
            if remaining == 0 && !framingInvalid {
                usageObserver?.markTransportComplete()
            }
        } else {
            if !remBuf.isEmpty {
                usageObserver?.onChunk(remBuf)
                if !delegate.writeSafe(remBuf) {
                    return
                }
                remBuf.removeAll()
            }
            var sawCleanEOF = false
            while true {
                var chunkBuf = Data()
                let n = readIntoBufferNonBlocking(upFD, buffer: &chunkBuf, maxChunk: 16384, delegate: delegate)
                if n > 0 {
                    usageObserver?.onChunk(chunkBuf)
                    if !delegate.writeSafe(chunkBuf) {
                        return
                    }
                } else if n == 0 {
                    sawCleanEOF = true
                    break
                } else {
                    break
                }
            }
            if sawCleanEOF && !framingInvalid {
                usageObserver?.markTransportComplete()
            }
        }
    }
}

// MARK: - Subcommands

private func runSeal(args: [String]) -> Int32 {
    disableDebuggerAttachment()

    var service: String?
    var account = kDefaultAccount
    var secretFD: Int32?

    var i = 0
    while i < args.count {
        switch args[i] {
        case "--service":
            i += 1
            if i < args.count { service = args[i] }
        case "--account":
            i += 1
            if i < args.count { account = args[i] }
        case "--secret-fd":
            i += 1
            if i < args.count, let fd = Int32(args[i]) { secretFD = fd }
        default:
            writeStderr("Unknown seal argument: \(args[i])")
            return 2
        }
        i += 1
    }

    guard let svc = service, !svc.isEmpty else {
        writeStderr("usage: se-key-proxy seal --service <service> [--account <account>] [--secret-fd <fd>]")
        return 2
    }

    guard SecureEnclave.isAvailable else {
        writeStderr("Secure Enclave is not available on this Mac.")
        return 1
    }

    do {
        var secretData: Data
        if let fd = secretFD {
            var raw = try readAllFromFD(fd)
            secretData = trimASCIIWhitespaceAndZero(&raw)
        } else {
            var raw = try readSecretFromTTY(prompt: "Enter API key for \(svc): ")
            secretData = trimASCIIWhitespaceAndZero(&raw)
        }
        defer { bestEffortZero(&secretData) }

        guard !secretData.isEmpty else {
            writeStderr("Refusing to seal an empty secret.")
            return 1
        }

        let dir = try resolveEnvelopeDirectory(createIfMissing: true)
        let stem = envelopeStem(service: svc, account: account)
        let envelope = try withStemLock(dir: dir, stem: stem) {
            return try sealAndPublishEnvelopeLocked(
                dir: dir,
                stem: stem,
                service: svc,
                account: account,
                secretData: secretData,
                stateLabel: "sealed"
            )
        }

        printJSON([
            "status": "sealed",
            "service": svc,
            "account": account,
            "key_fingerprint": envelope.key_fingerprint,
            "created_at": envelope.created_at,
            "envelope_sha256": envelope.envelope_sha256,
            "access_control": "biometryCurrentSet",
        ])
        return 0
    } catch {
        writeStderr("seal failed: \(error.localizedDescription)")
        return 1
    }
}

private func runStatus(args: [String]) -> Int32 {
    var service: String?
    var account = kDefaultAccount

    var i = 0
    while i < args.count {
        switch args[i] {
        case "--service":
            i += 1
            if i < args.count { service = args[i] }
        case "--account":
            i += 1
            if i < args.count { account = args[i] }
        default:
            writeStderr("Unknown status argument: \(args[i])")
            return 2
        }
        i += 1
    }

    guard let svc = service, !svc.isEmpty else {
        writeStderr("usage: se-key-proxy status --service <service> [--account <account>]")
        return 2
    }

    do {
        let env = try loadEnvelope(service: svc, account: account, checkSEPNonInteractive: true)
        guard
            let seBlob = Data(base64Encoded: env.se_private_key_blob),
            let combined = Data(base64Encoded: env.aes_gcm_combined)
        else {
            writeStderr("Envelope for '\(svc)' failed structural validation.")
            return 1
        }
        printJSON([
            "exists": true,
            "service": svc,
            "account": account,
            "version": env.version,
            "key_fingerprint": env.key_fingerprint,
            "created_at": env.created_at,
            "envelope_sha256": env.envelope_sha256,
            "envelope_integrity_ok": true,
            "sep_key_recognized": SecureEnclave.isAvailable,
            "se_blob_bytes": seBlob.count,
            "ciphertext_bytes": combined.count,
        ])
        return 0
    } catch {
        var stateVal: String = "none"
        if let dir = try? resolveEnvelopeDirectory(createIfMissing: false),
           let stRec = try? loadStateRecord(dir: dir, stem: envelopeStem(service: svc, account: account)) {
            stateVal = stRec.state
        }
        printJSON([
            "exists": false,
            "service": svc,
            "account": account,
            "lifecycle_state": stateVal,
            "error": error.localizedDescription,
        ])
        return 1
    }
}

private func runDelete(args: [String]) -> Int32 {
    var service: String?
    var account = kDefaultAccount

    var i = 0
    while i < args.count {
        switch args[i] {
        case "--service":
            i += 1
            if i < args.count { service = args[i] }
        case "--account":
            i += 1
            if i < args.count { account = args[i] }
        default:
            writeStderr("Unknown delete argument: \(args[i])")
            return 2
        }
        i += 1
    }

    guard let svc = service, !svc.isEmpty else {
        writeStderr("usage: se-key-proxy delete --service <service> [--account <account>]")
        return 2
    }

    do {
        let deleted = try deleteEnvelope(service: svc, account: account)
        printJSON([
            "deleted": deleted,
            "service": svc,
            "account": account,
            "lifecycle_state": "deleted",
        ])
        return 0
    } catch {
        writeStderr("delete failed: \(error.localizedDescription)")
        return 1
    }
}

private func inspectProcessStartTimes(pid: pid_t) -> (startSec: UInt64, startUsec: UInt64)? {
    guard pid > 1 else { return nil }
    var bsdInfo = proc_bsdinfo()
    let bsdSize = proc_pidinfo(
        pid,
        PROC_PIDTBSDINFO,
        0,
        &bsdInfo,
        Int32(MemoryLayout<proc_bsdinfo>.size)
    )
    guard bsdSize == Int32(MemoryLayout<proc_bsdinfo>.size),
          bsdInfo.pbi_status != UInt32(SZOMB) else {
        return nil
    }
    return (bsdInfo.pbi_start_tvsec, bsdInfo.pbi_start_tvusec)
}

private func verifyChildOwnsOutboundTCPConnection(
    pid: pid_t,
    expectedStartSec: UInt64,
    expectedStartUsec: UInt64,
    localPort: UInt16,
    remotePort: UInt16
) -> Bool {
    guard let times = inspectProcessStartTimes(pid: pid),
          times.startSec == expectedStartSec,
          times.startUsec == expectedStartUsec else {
        return false
    }
    let byteCount = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
    guard byteCount > 0 else { return false }
    let count = Int(byteCount) / MemoryLayout<proc_fdinfo>.size + 16
    var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: count)
    let actualBytes = proc_pidinfo(
        pid,
        PROC_PIDLISTFDS,
        0,
        &fds,
        Int32(count * MemoryLayout<proc_fdinfo>.size)
    )
    guard actualBytes > 0 else { return false }
    let actualCount = Int(actualBytes) / MemoryLayout<proc_fdinfo>.size
    let expectedLoopback = inet_addr("127.0.0.1")

    for i in 0..<actualCount where fds[i].proc_fdtype == PROX_FDTYPE_SOCKET {
        var sinfo = socket_fdinfo()
        let sz = proc_pidfdinfo(
            pid,
            fds[i].proc_fd,
            PROC_PIDFDSOCKETINFO,
            &sinfo,
            Int32(MemoryLayout<socket_fdinfo>.size)
        )
        guard sz == Int32(MemoryLayout<socket_fdinfo>.size),
              sinfo.psi.soi_kind == SOCKINFO_TCP else {
            continue
        }
        let tcp = sinfo.psi.soi_proto.pri_tcp
        let lport = UInt16(bigEndian: UInt16(truncatingIfNeeded: tcp.tcpsi_ini.insi_lport))
        let fport = UInt16(bigEndian: UInt16(truncatingIfNeeded: tcp.tcpsi_ini.insi_fport))
        let laddr = tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr
        let faddr = tcp.tcpsi_ini.insi_faddr.ina_46.i46a_addr4.s_addr
        if lport == localPort && fport == remotePort && laddr == expectedLoopback && faddr == expectedLoopback {
            return true
        }
    }
    return false
}

private func allocateEphemeralLoopbackListener() throws -> (fd: Int32, port: UInt16) {
    let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else {
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "socket() failed (errno \(errno))"]
        )
    }
    var reuse: Int32 = 1
    _ = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = 0
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")

    let bindRC = withUnsafePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
            Darwin.bind(fd, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard bindRC == 0, Darwin.listen(fd, 16) == 0 else {
        let err = errno
        _ = Darwin.close(fd)
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(err),
            userInfo: [NSLocalizedDescriptionKey: "bind/listen on 127.0.0.1:0 failed (errno \(err))"]
        )
    }
    var boundAddr = sockaddr_in()
    var boundLen = socklen_t(MemoryLayout<sockaddr_in>.size)
    let nameRC = withUnsafeMutablePointer(to: &boundAddr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
            Darwin.getsockname(fd, saPtr, &boundLen)
        }
    }
    guard nameRC == 0 else {
        let err = errno
        _ = Darwin.close(fd)
        throw NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(err),
            userInfo: [NSLocalizedDescriptionKey: "getsockname failed (errno \(err))"]
        )
    }
    return (fd, UInt16(bigEndian: boundAddr.sin_port))
}

private func allocateFreeLoopbackPort(excluding: UInt16) throws -> UInt16 {
    for _ in 0..<32 {
        let (fd, port) = try allocateEphemeralLoopbackListener()
        _ = Darwin.close(fd)
        if port != excluding && port > 0 {
            return port
        }
    }
    throw NSError(
        domain: "SEKeyProxy",
        code: 32,
        userInfo: [NSLocalizedDescriptionKey: "Failed to allocate free loopback port"]
    )
}

private func runMigrateFromLegacy(args: [String]) -> Int32 {
    disableDebuggerAttachment()

    var service: String?
    var account = kDefaultAccount
    var legacyBinary: String?
    var force = false

    var i = 0
    while i < args.count {
        switch args[i] {
        case "--service":
            i += 1
            if i < args.count { service = args[i] }
        case "--account":
            i += 1
            if i < args.count { account = args[i] }
        case "--legacy-binary":
            i += 1
            if i < args.count { legacyBinary = args[i] }
        case "--force":
            force = true
        default:
            writeStderr("Unknown migrate-from-legacy argument: \(args[i])")
            return 2
        }
        i += 1
    }

    guard let svc = service, !svc.isEmpty, let legBinRaw = legacyBinary, !legBinRaw.isEmpty else {
        writeStderr(
            "usage: se-key-proxy migrate-from-legacy --service <service> [--account <account>] --legacy-binary <path> [--force]"
        )
        return 2
    }

    guard SecureEnclave.isAvailable else {
        writeStderr("Secure Enclave is not available on this Mac.")
        return 1
    }

    let legSegments = legBinRaw.split(separator: "/", omittingEmptySubsequences: true)
    guard legBinRaw.hasPrefix("/"), !legSegments.contains(".."), !legSegments.contains(".") else {
        writeStderr("Refusing relative or traversal --legacy-binary path: \(legBinRaw)")
        return 2
    }
    let legBin = "/" + legSegments.joined(separator: "/")
    var legSt = stat()
    guard Darwin.lstat(legBin, &legSt) == 0,
          (legSt.st_mode & S_IFMT) == S_IFREG,
          (legSt.st_uid == geteuid() || legSt.st_uid == 0),
          (legSt.st_mode & 0o022) == 0 else {
        writeStderr("--legacy-binary must be a non-symlink regular file owned by current uid or root without group/world write permissions: \(legBin)")
        return 1
    }

    do {
        let dir = try resolveEnvelopeDirectory(createIfMissing: true)
        let stem = envelopeStem(service: svc, account: account)

        var preflightSnapshot: (envSha: String?, stateSha: String?) = (nil, nil)
        var alreadyMigratedEnv: SealedEnvelope? = nil

        try withStemLock(dir: dir, stem: stem) {
            preflightSnapshot = try readStemSnapshot(dir: dir, stem: stem)
            if !force {
                if preflightSnapshot.envSha != nil {
                    alreadyMigratedEnv = try loadEnvelope(
                        service: svc,
                        account: account,
                        checkSEPNonInteractive: true
                    )
                    return
                }
                if let stRec = try loadStateRecord(dir: dir, stem: stem) {
                    if stRec.state == "deleted" {
                        throw NSError(
                            domain: "SEKeyProxy",
                            code: 33,
                            userInfo: [
                                NSLocalizedDescriptionKey:
                                    "Refusing automatic migration for '\(svc)': envelope was explicitly deleted (pass --force to re-import from legacy Keychain)."
                            ]
                        )
                    }
                    throw NSError(
                        domain: "SEKeyProxy",
                        code: 33,
                        userInfo: [
                            NSLocalizedDescriptionKey:
                                "Refusing automatic migration for '\(svc)': envelope file is missing after prior '\(stRec.state)' state (pass --force to recover from legacy Keychain or run './scripts/se-key seal')."
                        ]
                    )
                }
            }
        }

        if let existing = alreadyMigratedEnv {
            printJSON([
                "status": "already_migrated",
                "service": svc,
                "account": account,
                "key_fingerprint": existing.key_fingerprint,
                "created_at": existing.created_at,
                "envelope_sha256": existing.envelope_sha256,
            ])
            return 0
        }

        // Verify legacy helper status before starting proxy
        let statusProc = Process()
        statusProc.executableURL = URL(fileURLWithPath: legBin)
        statusProc.arguments = ["status", "--service", svc, "--account", account]
        let statusErrPipe = Pipe()
        statusProc.standardOutput = Pipe()
        statusProc.standardError = statusErrPipe
        try statusProc.run()
        statusProc.waitUntilExit()
        guard statusProc.terminationStatus == 0 else {
            let errData = statusErrPipe.fileHandleForReading.readDataToEndOfFile()
            let errText = String(data: errData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            writeStderr("Legacy helper reported no accessible envelope for '\(svc)': \(errText)")
            return 1
        }

        signal(SIGPIPE, SIG_IGN)
        let (collectorListenFD, upPort) = try allocateEphemeralLoopbackListener()
        defer { _ = Darwin.close(collectorListenFD) }
        let proxyPort = try allocateFreeLoopbackPort(excluding: upPort)

        let sessionToken = "se-session-" + randomHexBytes(32)
        let collectorNonce = randomHexBytes(32)

        var tokPipe: [Int32] = [-1, -1]
        var readyPipe: [Int32] = [-1, -1]
        guard Darwin.pipe(&tokPipe) == 0, Darwin.pipe(&readyPipe) == 0 else {
            writeStderr("pipe() failed during migration setup")
            return 1
        }
        defer {
            for fd in [tokPipe[0], tokPipe[1], readyPipe[0], readyPipe[1]] where fd >= 0 {
                _ = Darwin.close(fd)
            }
        }

        guard let tokData = (sessionToken + "\n").data(using: .utf8),
              writeAllToFD(tokPipe[1], data: tokData) else {
            writeStderr("Failed writing session token to migration pipe")
            return 1
        }
        _ = Darwin.close(tokPipe[1])
        tokPipe[1] = -1

        var fileActions: posix_spawn_file_actions_t? = nil
        posix_spawn_file_actions_init(&fileActions)
        defer { posix_spawn_file_actions_destroy(&fileActions) }
        posix_spawn_file_actions_addclose(&fileActions, collectorListenFD)
        posix_spawn_file_actions_addclose(&fileActions, readyPipe[0])

        let childArgs = [
            legBin,
            "proxy",
            "--service", svc,
            "--account", account,
            "--listen-host", "127.0.0.1",
            "--listen-port", String(proxyPort),
            "--upstream-url", "http://127.0.0.1:\(upPort)/v1",
            "--upstream-pid", String(getpid()),
            "--allowed-model", "migrate",
            "--max-chat-requests", "1",
            "--ttl-seconds", "30",
            "--session-token-fd", String(tokPipe[0]),
            "--ready-fd", String(readyPipe[1]),
        ]
        var cArgs: [UnsafeMutablePointer<CChar>?] = childArgs.map { strdup($0) }
        cArgs.append(nil)
        defer {
            for ptr in cArgs where ptr != nil { free(ptr) }
        }

        var envPairs = [
            "PATH=/usr/bin:/bin",
            "HOME=\(NSHomeDirectory())",
        ]
        #if SE_KEY_TESTING
        if let testEnvDir = ProcessInfo.processInfo.environment["FREE_INFERENCE_SE_ENVELOPE_DIR"] {
            envPairs.append("FREE_INFERENCE_SE_ENVELOPE_DIR=\(testEnvDir)")
        }
        if let mockDir = ProcessInfo.processInfo.environment["FREE_INFERENCE_TEST_MOCK_STATE_DIR"] {
            envPairs.append("FREE_INFERENCE_TEST_MOCK_STATE_DIR=\(mockDir)")
        }
        #endif
        var cEnv: [UnsafeMutablePointer<CChar>?] = envPairs.map { strdup($0) }
        cEnv.append(nil)
        defer {
            for ptr in cEnv where ptr != nil { free(ptr) }
        }

        var childPID: pid_t = 0
        let spawnRC = posix_spawn(&childPID, legBin, &fileActions, nil, &cArgs, &cEnv)
        _ = Darwin.close(tokPipe[0])
        tokPipe[0] = -1
        _ = Darwin.close(readyPipe[1])
        readyPipe[1] = -1

        guard spawnRC == 0, childPID > 1 else {
            writeStderr("posix_spawn failed for legacy helper (rc=\(spawnRC))")
            return 1
        }
        defer {
            if childPID > 1 {
                _ = Darwin.kill(childPID, SIGTERM)
                var status: Int32 = 0
                for _ in 0..<20 {
                    if Darwin.waitpid(childPID, &status, WNOHANG) == childPID {
                        childPID = 0
                        break
                    }
                    usleep(25_000)
                }
                if childPID > 1 {
                    _ = Darwin.kill(childPID, SIGKILL)
                    _ = Darwin.waitpid(childPID, &status, 0)
                    childPID = 0
                }
            }
        }

        guard let childStart = inspectProcessStartTimes(pid: childPID) else {
            writeStderr("Could not inspect start time for spawned legacy helper pid=\(childPID)")
            return 1
        }

        // Wait for readiness signal on readyPipe[0] (up to 60s for interactive Touch ID)
        setNonBlocking(readyPipe[0])
        let readyDeadline = DispatchTime.now().uptimeNanoseconds + 60_000_000_000
        var readyBuf = Data()
        var isReady = false
        while DispatchTime.now().uptimeNanoseconds < readyDeadline {
            var pfd = pollfd(fd: readyPipe[0], events: Int16(POLLIN), revents: 0)
            let prc = Darwin.poll(&pfd, 1, 100)
            if prc > 0 {
                var tmp = [UInt8](repeating: 0, count: 512)
                let n = Darwin.read(readyPipe[0], &tmp, tmp.count)
                if n > 0 {
                    readyBuf.append(contentsOf: tmp[0..<n])
                    if let txt = String(data: readyBuf, encoding: .utf8), txt.contains("\"ready\"") {
                        isReady = true
                        break
                    }
                } else if n == 0 {
                    break
                }
            }
            var wstatus: Int32 = 0
            if Darwin.waitpid(childPID, &wstatus, WNOHANG) == childPID {
                childPID = 0
                break
            }
        }
        guard isReady else {
            writeStderr("Legacy helper did not become ready within 60s during migration")
            return 1
        }

        // Connect to legacy proxy and send GET /v1/models?nonce=<collectorNonce>
        let reqFD = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard reqFD >= 0 else {
            writeStderr("socket() failed for migration client")
            return 1
        }
        defer { _ = Darwin.close(reqFD) }
        var proxyAddr = sockaddr_in()
        proxyAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        proxyAddr.sin_family = sa_family_t(AF_INET)
        proxyAddr.sin_port = proxyPort.bigEndian
        proxyAddr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let connRC = withUnsafePointer(to: &proxyAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.connect(reqFD, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connRC == 0 else {
            writeStderr("connect() to legacy proxy failed (errno \(errno))")
            return 1
        }
        let reqStr =
            "GET /v1/models?nonce=\(collectorNonce) HTTP/1.1\r\n" +
            "Host: 127.0.0.1:\(proxyPort)\r\n" +
            "Authorization: Bearer \(sessionToken)\r\n" +
            "Accept: application/json\r\n" +
            "Connection: close\r\n\r\n"
        guard let reqData = reqStr.data(using: .utf8), writeAllToFD(reqFD, data: reqData) else {
            writeStderr("Failed sending request to legacy proxy")
            return 1
        }

        // Accept and authenticate upstream connection on collectorListenFD
        setNonBlocking(collectorListenFD)
        let collectDeadline = DispatchTime.now().uptimeNanoseconds + 10_000_000_000
        var collectedSecret = Data()
        defer { bestEffortZero(&collectedSecret) }
        let expectedPath1 = "/v1/models?nonce=\(collectorNonce)"
        let expectedPath2 = "/models?nonce=\(collectorNonce)"

        while DispatchTime.now().uptimeNanoseconds < collectDeadline && collectedSecret.isEmpty {
            var pfd = pollfd(fd: collectorListenFD, events: Int16(POLLIN), revents: 0)
            let prc = Darwin.poll(&pfd, 1, 100)
            if prc <= 0 { continue }

            var peerAddr = sockaddr_in()
            var peerLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let connFD = withUnsafeMutablePointer(to: &peerAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                    Darwin.accept(collectorListenFD, saPtr, &peerLen)
                }
            }
            if connFD < 0 { continue }
            defer { _ = Darwin.close(connFD) }

            let peerPort = UInt16(bigEndian: peerAddr.sin_port)
            let peerIP = peerAddr.sin_addr.s_addr
            guard peerIP == inet_addr("127.0.0.1"),
                  verifyChildOwnsOutboundTCPConnection(
                      pid: childPID,
                      expectedStartSec: childStart.startSec,
                      expectedStartUsec: childStart.startUsec,
                      localPort: peerPort,
                      remotePort: upPort
                  ) else {
                continue
            }

            // Read HTTP headers from authenticated legacy child socket
            var hdrBuf = Data()
            defer { bestEffortZero(&hdrBuf) }
            let hdrSep = Data([0x0D, 0x0A, 0x0D, 0x0A])
            let readLimit = DispatchTime.now().uptimeNanoseconds + 3_000_000_000
            setNonBlocking(connFD)
            while DispatchTime.now().uptimeNanoseconds < readLimit && hdrBuf.count < 16384 {
                if hdrBuf.range(of: hdrSep) != nil { break }
                var p = pollfd(fd: connFD, events: Int16(POLLIN), revents: 0)
                if Darwin.poll(&p, 1, 50) > 0 {
                    var chunk = [UInt8](repeating: 0, count: 1024)
                    defer {
                        for idx in 0..<chunk.count { chunk[idx] = 0 }
                    }
                    let n = Darwin.read(connFD, &chunk, chunk.count)
                    if n > 0 {
                        hdrBuf.append(contentsOf: chunk[0..<n])
                    } else if n == 0 {
                        break
                    }
                }
            }
            guard let sepRange = hdrBuf.range(of: hdrSep) else {
                continue
            }
            let headerData = hdrBuf.subdata(in: 0..<sepRange.lowerBound)
            let crlf = Data([0x0D, 0x0A])
            guard let firstLineEnd = headerData.range(of: crlf),
                  let reqLine = String(data: headerData.subdata(in: 0..<firstLineEnd.lowerBound), encoding: .utf8) else {
                continue
            }
            let reqParts = reqLine.split(separator: " ")
            guard reqParts.count >= 2,
                  reqParts[0] == "GET",
                  (reqParts[1] == expectedPath1 || reqParts[1] == expectedPath2) else {
                continue
            }

            // Scan header lines for Authorization: Bearer <secret> in raw Data
            var cursor = firstLineEnd.upperBound
            let authPrefix = Data("authorization:".utf8)
            let bearerPrefix = Data("bearer ".utf8)
            var extracted = Data()
            defer { bestEffortZero(&extracted) }

            while cursor < headerData.count {
                let lineEnd: Int
                let nextCursor: Int
                if let r = headerData.range(of: crlf, options: [], in: cursor..<headerData.count) {
                    lineEnd = r.lowerBound
                    nextCursor = r.upperBound
                } else {
                    lineEnd = headerData.count
                    nextCursor = headerData.count
                }
                if lineEnd - cursor >= authPrefix.count {
                    var prefixSlice = headerData.subdata(in: cursor..<(cursor + authPrefix.count))
                    for idx in 0..<prefixSlice.count {
                        if prefixSlice[idx] >= 0x41 && prefixSlice[idx] <= 0x5A {
                            prefixSlice[idx] += 32
                        }
                    }
                    if prefixSlice == authPrefix {
                        var valSlice = headerData.subdata(in: (cursor + authPrefix.count)..<lineEnd)
                        defer { bestEffortZero(&valSlice) }
                        var trimmedVal = trimASCIIWhitespaceAndZero(&valSlice)
                        defer { bestEffortZero(&trimmedVal) }
                        if trimmedVal.count > bearerPrefix.count {
                            var bCheck = trimmedVal.subdata(in: 0..<bearerPrefix.count)
                            for idx in 0..<bCheck.count {
                                if bCheck[idx] >= 0x41 && bCheck[idx] <= 0x5A {
                                    bCheck[idx] += 32
                                }
                            }
                            if bCheck == bearerPrefix {
                                var rawBearer = trimmedVal.subdata(in: bearerPrefix.count..<trimmedVal.count)
                                extracted = trimASCIIWhitespaceAndZero(&rawBearer)
                                break
                            }
                        }
                    }
                }
                cursor = nextCursor
            }

            guard !extracted.isEmpty else {
                continue
            }
            collectedSecret = Data(extracted)
            let okResp =
                "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/json\r\n" +
                "Content-Length: 28\r\n" +
                "Connection: close\r\n\r\n" +
                "{\"object\":\"list\",\"data\":[]}\n"
            if let okData = okResp.data(using: .utf8) {
                _ = writeAllToFD(connFD, data: okData)
            }
            break
        }

        guard !collectedSecret.isEmpty else {
            writeStderr("Failed to collect authenticated secret from legacy helper")
            return 1
        }

        let publishedEnv = try withStemLock(dir: dir, stem: stem) { () -> SealedEnvelope in
            let currentSnapshot = try readStemSnapshot(dir: dir, stem: stem)
            guard currentSnapshot.envSha == preflightSnapshot.envSha,
                  currentSnapshot.stateSha == preflightSnapshot.stateSha else {
                throw NSError(
                    domain: "SEKeyProxy",
                    code: 34,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            "Aborted migration: concurrent seal or delete modified envelope state while migration was in flight"
                    ]
                )
            }
            return try sealAndPublishEnvelopeLocked(
                dir: dir,
                stem: stem,
                service: svc,
                account: account,
                secretData: collectedSecret,
                stateLabel: "migrated"
            )
        }

        printJSON([
            "status": "migrated",
            "service": svc,
            "account": account,
            "key_fingerprint": publishedEnv.key_fingerprint,
            "created_at": publishedEnv.created_at,
            "envelope_sha256": publishedEnv.envelope_sha256,
            "access_control": "biometryCurrentSet",
        ])
        return 0
    } catch {
        writeStderr("migrate-from-legacy failed: \(error.localizedDescription)")
        return 1
    }
}

private func extractUnderlyingErrorCodes(_ error: Error) -> [(domain: String, code: Int)] {
    var result: [(String, Int)] = []
    var current: NSError? = error as NSError
    while let err = current {
        result.append((err.domain, err.code))
        if let underlying = err.userInfo[NSUnderlyingErrorKey] as? NSError {
            current = underlying
        } else {
            current = nil
        }
    }
    return result
}

private func isValidPinnedHTTPSURL(_ url: URL) -> Bool {
    guard (url.scheme ?? "").lowercased() == "https" else { return false }
    if url.user != nil || url.password != nil { return false }
    if let p = url.port, p != 443 { return false }
    guard let rawHost = url.host?.lowercased(), !rawHost.isEmpty else { return false }
    if rawHost.hasPrefix(".") || rawHost.hasSuffix(".") { return false }
    if rawHost == "localhost" || rawHost.hasSuffix(".localhost") || rawHost.hasSuffix(".local") {
        return false
    }
    if rawHost.contains(":") || rawHost.contains("[") || rawHost.contains("]") {
        return false
    }
    let labels = rawHost.split(separator: ".", omittingEmptySubsequences: false)
    if labels.count < 2 || labels.contains(where: { $0.isEmpty }) {
        return false
    }
    // Reject all-numeric or hex IPv4 forms (e.g. 127.0.0.1, 10.0.0.1, 127.1, 2130706433, 0x7f.1)
    let allNumericOrHex = labels.allSatisfy { label in
        if label.hasPrefix("0x") {
            let hexPart = label.dropFirst(2)
            return !hexPart.isEmpty && hexPart.allSatisfy({ $0.isHexDigit })
        }
        return label.allSatisfy({ $0.isNumber })
    }
    if allNumericOrHex {
        return false
    }
    return true
}

private func runSelftest() -> Int32 {
    do {
        // 1. Software ECIES round-trip + tamper checks (always executed first)
        let softPriv = P256.KeyAgreement.PrivateKey()
        let testSecret = Data("selftest-ecies-secret-9981".utf8)
        let svc = "free-inference.selftest"
        let (softEphPub, softCombined) = try sealPayloadWithPublicKey(
            secret: testSecret,
            recipientPublicKeyX963: softPriv.publicKey.x963Representation,
            service: svc
        )
        let softEphPubKey = try P256.KeyAgreement.PublicKey(x963Representation: softEphPub)
        let softShared = try softPriv.sharedSecretFromKeyAgreement(with: softEphPubKey)
        let opened = try unsealPayloadWithSharedSecret(
            sharedSecret: softShared,
            ephemeralPubX963: softEphPub,
            combinedCiphertext: softCombined,
            service: svc
        )
        guard opened == testSecret else {
            writeStderr("selftest failed: software ECIES round-trip mismatch")
            return 1
        }

        // Wrong service AAD must fail
        var wrongServiceRejected = false
        do {
            _ = try unsealPayloadWithSharedSecret(
                sharedSecret: softShared,
                ephemeralPubX963: softEphPub,
                combinedCiphertext: softCombined,
                service: "free-inference.other-service"
            )
        } catch {
            wrongServiceRejected = true
        }
        guard wrongServiceRejected else {
            writeStderr("selftest failed: wrong service AAD was not rejected")
            return 1
        }

        // Flipped ciphertext byte must fail
        var tampered = softCombined
        tampered[tampered.count - 1] ^= 0xFF
        var tamperRejected = false
        do {
            _ = try unsealPayloadWithSharedSecret(
                sharedSecret: softShared,
                ephemeralPubX963: softEphPub,
                combinedCiphertext: tampered,
                service: svc
            )
        } catch {
            tamperRejected = true
        }
        guard tamperRejected else {
            writeStderr("selftest failed: tampered ciphertext was not rejected")
            return 1
        }

        // Verify trimASCIIWhitespaceAndZero trims ASCII whitespace and zeros the raw buffer in place
        var rawSecretSample = Data("  \t\r\nsk-test-secret-value\n\t  ".utf8)
        let trimmedSecretSample = trimASCIIWhitespaceAndZero(&rawSecretSample)
        guard
            trimmedSecretSample == Data("sk-test-secret-value".utf8),
            rawSecretSample.allSatisfy({ $0 == 0 })
        else {
            writeStderr("selftest failed: trimASCIIWhitespaceAndZero did not trim and zero raw buffer")
            return 1
        }

        // R2-F4: Verify remainingConnectSliceMs boundary and crossed-deadline cases never underflow
        guard
            remainingConnectSliceMs(nowNs: 1_000_000_000, connectLimitNs: 1_050_000_000) == 50,
            remainingConnectSliceMs(nowNs: 1_000_000_000, connectLimitNs: 2_000_000_000) == 100,
            remainingConnectSliceMs(nowNs: 1_050_000_000, connectLimitNs: 1_050_000_000) == nil,
            remainingConnectSliceMs(nowNs: 1_050_000_001, connectLimitNs: 1_050_000_000) == nil,
            remainingConnectSliceMs(nowNs: UInt64.max, connectLimitNs: 0) == nil
        else {
            writeStderr("selftest failed: remainingConnectSliceMs boundary check failed")
            return 1
        }

        // R2-F3: The race between reading clientFD and calling shutdown(clientFD, SHUT_RDWR) vs.
        // closeClientSocket() retiring clientFD = -1 is eliminated structurally by holding `lock` across
        // both the check and `Darwin.shutdown`. Here we verify `cancel_after_close_noop`: calling
        // cancelAndShutdownSocket() after closeClientSocket() and descriptor reuse is a no-op.
        var sp1: [Int32] = [-1, -1]
        var sp2: [Int32] = [-1, -1]
        guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &sp1) == 0 else {
            writeStderr("selftest failed: socketpair sp1 failed")
            return 1
        }
        let targetFD = sp1[0]
        let peer1FD = sp1[1]
        let raceDelegate = StreamingForwardDelegate(clientFD: targetFD, timeoutSeconds: 1)
        raceDelegate.closeClientSocket() // Closes targetFD and retires clientFD = -1 under lock
        _ = Darwin.close(peer1FD)

        guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &sp2) == 0 else {
            writeStderr("selftest failed: socketpair sp2 failed")
            return 1
        }
        if sp2[0] != targetFD {
            _ = Darwin.dup2(sp2[0], targetFD)
            _ = Darwin.close(sp2[0])
            sp2[0] = targetFD
        }
        // Verify cancelAndShutdownSocket() after closeClientSocket() and fd reuse is a no-op
        raceDelegate.cancelAndShutdownSocket()
        let pingByte: [UInt8] = [0x42]
        var pongByte: [UInt8] = [0x00]
        let wrotePing = Darwin.write(targetFD, pingByte, 1)
        let readPong = Darwin.read(sp2[1], &pongByte, 1)
        _ = Darwin.close(targetFD)
        _ = Darwin.close(sp2[1])
        guard wrotePing == 1, readPong == 1, pongByte[0] == 0x42 else {
            writeStderr("selftest failed: cancelAndShutdownSocket() affected reused descriptor")
            return 1
        }

        // Track 2: Deterministic offline metering, lexical JSON, SSE, raw-buffer pool, and 128-bit arithmetic selftests
        func scanStr(_ s: String) -> UsageScanState {
            let arr = Array(s.utf8)
            return arr.withUnsafeBufferPointer { scanTopLevelUsageJSON($0) }
        }
        guard scanStr("{\"choices\":[{\"text\":\"hi\"}],\"us\\u0061ge\":{\"prompt_tokens\":100,\"completion_tokens\":25,\"prompt_tokens_details\":{\"cached_tokens\":40}}}")
            == .valid(ParsedTokenUsage(promptTokens: 100, cachedPromptTokens: 40, completionTokens: 25)),
              scanStr("{\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"cached_prompt_tokens\":3,\"cached_tokens\":3}}")
            == .valid(ParsedTokenUsage(promptTokens: 10, cachedPromptTokens: 3, completionTokens: 5)),
              scanStr("{\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"cached_prompt_tokens\":3,\"cached_tokens\":4}}") == .invalid,
              scanStr("{\"usage\":{\"prompt_tokens\":10,\"prompt_tokens\":12,\"completion_tokens\":5}}") == .invalid,
              scanStr("{\"usage\":{\"prompt_tokens\":10.0,\"completion_tokens\":5}}") == .invalid,
              scanStr("{\"usage\":{\"prompt_tokens\":1e2,\"completion_tokens\":5}}") == .invalid,
              scanStr("{\"usage\":{\"prompt_tokens\":true,\"completion_tokens\":5}}") == .invalid,
              scanStr("{\"usage\":{\"prompt_tokens\":0,\"completion_tokens\":0}}")
            == .valid(ParsedTokenUsage(promptTokens: 0, cachedPromptTokens: 0, completionTokens: 0)) else {
            writeStderr("selftest failed: lexical JSON usage scanner self-check failed")
            return 1
        }
        // 128-bit exact half-microdollar check: 1000 tokens * $0.0005/1M = 500_000 pico = 0.5 microdollar
        let halfMicroPico = UInt128Pair.mul64(1000, 500)
        let displayMicro = halfMicroPico.addingClamped(UInt128Pair(hi: 0, lo: 500_000)).divMod1000000().quotient.clampedInt64(max: kMaxWireMicroUsd)
        let cap1MicroPico = UInt128Pair.mul64(1, 1_000_000)
        guard displayMicro == 1, halfMicroPico < cap1MicroPico,
              halfMicroPico.addingClamped(halfMicroPico) >= cap1MicroPico else {
            writeStderr("selftest failed: 128-bit half-microdollar arithmetic check failed")
            return 1
        }
        // Pool hard ceiling + non-COW replacement check
        let testPool = ObserverMemoryPool(limitBytes: 600)
        let rb = OwnedRawBuffer(pool: testPool, maxBytes: 1024)
        let chunk300 = [UInt8](repeating: 0x41, count: 300)
        let ok1 = chunk300.withUnsafeBufferPointer { rb.append(bytes: $0.baseAddress!, length: $0.count) }
        // Growing from 300 -> 600 requires reserving 600 while 300 is charged (= 900 > 600), so must fail without exceeding 600!
        let ok2 = chunk300.withUnsafeBufferPointer { rb.append(bytes: $0.baseAddress!, length: $0.count) }
        let peakDuring = testPool.stats().peak
        rb.free()
        let afterFree = testPool.stats().current
        guard ok1 && !ok2 && peakDuring <= 600 && afterFree == 0 else {
            writeStderr("selftest failed: OwnedRawBuffer pool ceiling/release check failed")
            return 1
        }
        // SSE multi-line + bare colonless trailing data EOF + post-detach no-op + status-line & UTF-8 checks
        let ssePool = ObserverMemoryPool(limitBytes: 131_072)
        let sseObs = ChatUsageObserver(pool: ssePool)
        sseObs.markUpstreamRequestWritten()
        sseObs.onHeaders(status: 200, contentType: "text/event-stream")
        sseObs.onChunk(Data("data: {\"usage\":\ndata: {\"prompt_tokens\":12,\"completion_tokens\":8}}\n\ndata\n".utf8))
        sseObs.markTransportComplete()
        let sseOut = sseObs.detachAndFinalize(forceIncomplete: false)
        // Late callbacks after detachAndFinalize must remain strict no-ops with zero pool reservation
        sseObs.onHeaders(status: 200, contentType: "application/json")
        sseObs.onChunk(Data("{\"usage\":{\"prompt_tokens\":99,\"completion_tokens\":99}}".utf8))
        sseObs.markTransportComplete()
        let badUtf8Val: [UInt8] = Array("{\"choices\":\"".utf8) + [0xFF] + Array("\",\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}".utf8)
        let badUtf8Key: [UInt8] = Array("{\"k".utf8) + [0xFF] + Array("\":1,\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}".utf8)
        let goodUtf8Val: [UInt8] = Array("{\"choices\":\"caf\u{00E9}\u{1F680}\",\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}".utf8)
        let badValRes = badUtf8Val.withUnsafeBufferPointer { scanTopLevelUsageJSON($0) }
        let badKeyRes = badUtf8Key.withUnsafeBufferPointer { scanTopLevelUsageJSON($0) }
        let goodValRes = goodUtf8Val.withUnsafeBufferPointer { scanTopLevelUsageJSON($0) }
        guard sseOut.usageState == .invalid && ssePool.stats().current == 0,
              parseHTTPStatusLineBytes(Array("HTTP/1.1 200".utf8)) == nil,
              parseHTTPStatusLineBytes(Array("HTTP/1.1 200 ".utf8)) == 200,
              badValRes == .invalid && badKeyRes == .invalid,
              goodValRes == .valid(ParsedTokenUsage(promptTokens: 10, cachedPromptTokens: 0, completionTokens: 5)) else {
            writeStderr("selftest failed: SSE/post-detach/status-line/UTF-8 self-check failed")
            return 1
        }

        let laContext = LAContext()
        var bioErr: NSError?
        let canEvalBio = laContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &bioErr)
        if !SecureEnclave.isAvailable || !canEvalBio {
            printJSON([
                "status": "skipped",
                "skipped": true,
                "secure_enclave_available": SecureEnclave.isAvailable,
                "biometrics_available": canEvalBio,
                "software_ecies_roundtrip_ok": true,
                "wrong_service_aad_rejected": true,
                "tampered_ciphertext_rejected": true,
                "connect_deadline_underflow_protected": true,
                "cancel_after_close_noop": true,
                "reason": bioErr?.localizedDescription ?? "Secure Enclave or Touch ID unavailable",
            ])
            return kSkipExitCode
        }

        // 2. Ephemeral in-memory Secure Enclave .biometryCurrentSet behavioral test (never written to Keychain)
        var cfErr: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &cfErr
        ) else {
            writeStderr("selftest failed: SecAccessControlCreateWithFlags error")
            return 1
        }

        let sePriv = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
        let seBlob = sePriv.dataRepresentation
        let (seEphPub, seCombined) = try sealPayloadWithPublicKey(
            secret: testSecret,
            recipientPublicKeyX963: sePriv.publicKey.x963Representation,
            service: svc
        )

        // Attempt unseal with interactionNotAllowed = true and reuseDuration = 0
        let nonInteractiveCtx = LAContext()
        nonInteractiveCtx.interactionNotAllowed = true
        nonInteractiveCtx.touchIDAuthenticationAllowableReuseDuration = 0

        var unsealBlockedWithoutInteraction = false
        var blockErrorDescription = ""
        var blockErrorDomain = ""
        var blockErrorCode = 0
        let allowedBlockDomainCodes: [(domain: String, code: Int)] = [
            ("com.apple.LocalAuthentication", -1004), // kLAErrorNotInteractive
            (NSOSStatusErrorDomain, -25308),          // errSecInteractionNotAllowed
            (NSOSStatusErrorDomain, -25293),          // errSecAuthFailed
        ]
        do {
            let loadedKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: seBlob,
                authenticationContext: nonInteractiveCtx
            )
            let ephKey = try P256.KeyAgreement.PublicKey(x963Representation: seEphPub)
            let seShared = try loadedKey.sharedSecretFromKeyAgreement(with: ephKey)
            _ = try unsealPayloadWithSharedSecret(
                sharedSecret: seShared,
                ephemeralPubX963: seEphPub,
                combinedCiphertext: seCombined,
                service: svc
            )
        } catch {
            let chain = extractUnderlyingErrorCodes(error)
            if let matched = chain.first(where: { item in
                allowedBlockDomainCodes.contains(where: { $0.domain == item.domain && $0.code == item.code })
            }) {
                unsealBlockedWithoutInteraction = true
                blockErrorDomain = matched.domain
                blockErrorCode = matched.code
                blockErrorDescription = error.localizedDescription
            } else {
                writeStderr(
                    "selftest failed: unexpected error during non-interactive unseal: \(error.localizedDescription) (codes=\(chain))"
                )
                return 1
            }
        }

        guard unsealBlockedWithoutInteraction else {
            writeStderr("selftest failed: Secure Enclave key unsealed with interactionNotAllowed=true!")
            return 1
        }

        printJSON([
            "status": "passed",
            "secure_enclave_available": true,
            "biometrics_available": true,
            "software_ecies_roundtrip_ok": true,
            "wrong_service_aad_rejected": true,
            "tampered_ciphertext_rejected": true,
            "connect_deadline_underflow_protected": true,
            "cancel_after_close_noop": true,
            "se_blob_bytes": seBlob.count,
            "unseal_blocked_without_interaction": true,
            "block_error_domain": blockErrorDomain,
            "block_error_code": blockErrorCode,
            "block_error": blockErrorDescription,
        ])
        return 0
    } catch {
        writeStderr("selftest failed with unexpected error: \(error.localizedDescription)")
        return 1
    }
}

private func runProxy(args: [String]) -> Int32 {
    disableDebuggerAttachment()

    var service: String?
    var account = kDefaultAccount
    var listenHost = "127.0.0.1"
    var listenPort: UInt16?
    var upstreamURLStr: String?
    var allowedModel: String?
    var sessionTokenFD: Int32?
    var readyFD: Int32?
    var upstreamPID: pid_t?
    var sessionTokenFile: String?
    var maxChatRequests = 50
    var maxRequestBytes = 262144
    var maxTokensCap = 0
    var ttlSeconds = 3600
    var controlSocket: String?
    var streamTimeoutSeconds = 300
    var defaultChatParamsRaw: String? = nil
    var priceInputRaw: String? = nil
    var priceOutputRaw: String? = nil
    var priceCachedInputRaw: String? = nil
    var maxActualUsdRaw: String? = nil
    var forceURLSession = false
    #if SE_KEY_TESTING
    var testEphemeralKeyFD: Int32?
    var testRenewalFD: Int32?
    var testPublicationFault = 0
    #endif

    var i = 0
    while i < args.count {
        switch args[i] {
        case "--service":
            i += 1
            if i < args.count { service = args[i] }
        case "--account":
            i += 1
            if i < args.count { account = args[i] }
        case "--listen-host":
            i += 1
            if i < args.count { listenHost = args[i] }
        case "--listen-port":
            i += 1
            if i < args.count, let p = UInt16(args[i]), p > 0 { listenPort = p }
        case "--upstream-url":
            i += 1
            if i < args.count { upstreamURLStr = args[i] }
        case "--allowed-model":
            i += 1
            if i < args.count { allowedModel = args[i] }
        case "--session-token-fd":
            i += 1
            if i < args.count, let fd = Int32(args[i]) { sessionTokenFD = fd }
        case "--ready-fd":
            i += 1
            if i < args.count, let fd = Int32(args[i]) { readyFD = fd }
        case "--upstream-pid":
            i += 1
            if i < args.count, let pid = Int32(args[i]) { upstreamPID = pid }
        case "--session-token-file":
            i += 1
            if i < args.count { sessionTokenFile = args[i] }
        case "--control-socket":
            i += 1
            if i < args.count { controlSocket = args[i] }
        case "--max-chat-requests":
            i += 1
            guard i < args.count, let v = Int(args[i]), v >= 1 && v <= kMaxChatRequestsLimit else {
                writeStderr("Invalid value for --max-chat-requests: must be an integer in 1...\(kMaxChatRequestsLimit)")
                return 2
            }
            maxChatRequests = v
        case "--max-request-bytes":
            i += 1
            if i < args.count, let v = Int(args[i]), v > 0 { maxRequestBytes = v }
        case "--max-tokens-cap":
            i += 1
            if i < args.count, let v = Int(args[i]), v >= 0 { maxTokensCap = v }
        case "--ttl-seconds":
            i += 1
            if i < args.count, let v = Int(args[i]), v > 0 { ttlSeconds = v }
        case "--stream-timeout-seconds":
            i += 1
            if i < args.count, let v = Int(args[i]), v > 0 { streamTimeoutSeconds = v }
        case "--default-chat-params-json":
            i += 1
            guard i < args.count else {
                writeStderr("Missing value for --default-chat-params-json")
                return 2
            }
            defaultChatParamsRaw = args[i]
        case "--price-input-per-m":
            i += 1
            guard i < args.count else {
                writeStderr("Missing value for --price-input-per-m")
                return 2
            }
            priceInputRaw = args[i]
        case "--price-output-per-m":
            i += 1
            guard i < args.count else {
                writeStderr("Missing value for --price-output-per-m")
                return 2
            }
            priceOutputRaw = args[i]
        case "--price-cached-input-per-m":
            i += 1
            guard i < args.count else {
                writeStderr("Missing value for --price-cached-input-per-m")
                return 2
            }
            priceCachedInputRaw = args[i]
        case "--max-actual-usd":
            i += 1
            guard i < args.count else {
                writeStderr("Missing value for --max-actual-usd")
                return 2
            }
            maxActualUsdRaw = args[i]
        default:
            #if SE_KEY_TESTING
            if args[i] == "--test-ephemeral-key-fd" {
                i += 1
                if i < args.count, let fd = Int32(args[i]) {
                    testEphemeralKeyFD = fd
                    i += 1
                    continue
                }
            } else if args[i] == "--test-renewal-fd" {
                i += 1
                if i < args.count, let fd = Int32(args[i]) {
                    testRenewalFD = fd
                    i += 1
                    continue
                }
            } else if args[i] == "--test-publication-fault" {
                i += 1
                if i < args.count, let fault = Int(args[i]), (1...2).contains(fault) {
                    testPublicationFault = fault
                    i += 1
                    continue
                }
            } else if args[i] == "--test-force-urlsession" {
                forceURLSession = true
                i += 1
                continue
            }
            #endif
            writeStderr("Unknown proxy argument: \(args[i])")
            return 2
        }
        i += 1
    }

    guard
        let svc = service, !svc.isEmpty,
        let lPort = listenPort,
        let upStr = upstreamURLStr,
        let upURL = URL(string: upStr),
        let model = allowedModel, !model.isEmpty,
        let tokFD = sessionTokenFD
    else {
        writeStderr("Missing required proxy arguments")
        return 2
    }

    guard listenHost == "127.0.0.1" else {
        writeStderr("Refusing to bind se-key-proxy to non-loopback host '\(listenHost)'")
        return 2
    }
    guard (1...86400).contains(ttlSeconds) else {
        writeStderr("Session window must be between 1 and 86400 seconds")
        return 2
    }

    var defaultChatParams: [String: Any] = [:]
    if let rawDefaults = defaultChatParamsRaw {
        do {
            defaultChatParams = try parseAndValidateDefaultChatParams(rawJSON: rawDefaults)
        } catch {
            writeStderr("Invalid --default-chat-params-json: \(error.localizedDescription)")
            return 2
        }
    }

    var pricingRates: PricingRates? = nil
    let anyPricingFlag = (priceInputRaw != nil || priceOutputRaw != nil || priceCachedInputRaw != nil)
    if anyPricingFlag {
        guard let inRaw = priceInputRaw, let outRaw = priceOutputRaw else {
            writeStderr("Both --price-input-per-m and --price-output-per-m are required whenever pricing flags are provided")
            return 2
        }
        guard let inMicro = parseDecimalMicroUsd(inRaw, minMicro: 0, maxMicro: kMaxPriceMicroUsdPerM) else {
            writeStderr("Invalid --price-input-per-m '\(inRaw)': must be a decimal in 0...10000 with at most 6 fractional digits")
            return 2
        }
        guard let outMicro = parseDecimalMicroUsd(outRaw, minMicro: 0, maxMicro: kMaxPriceMicroUsdPerM) else {
            writeStderr("Invalid --price-output-per-m '\(outRaw)': must be a decimal in 0...10000 with at most 6 fractional digits")
            return 2
        }
        let cachedMicro: Int64
        if let cRaw = priceCachedInputRaw {
            guard let cm = parseDecimalMicroUsd(cRaw, minMicro: 0, maxMicro: kMaxPriceMicroUsdPerM) else {
                writeStderr("Invalid --price-cached-input-per-m '\(cRaw)': must be a decimal in 0...10000 with at most 6 fractional digits")
                return 2
            }
            cachedMicro = cm
        } else {
            cachedMicro = inMicro
        }
        pricingRates = PricingRates(
            inputMicroPerM: inMicro,
            outputMicroPerM: outMicro,
            cachedInputMicroPerM: cachedMicro
        )
    }

    var maxActualMicroUsd: Int64? = nil
    if let capRaw = maxActualUsdRaw {
        guard pricingRates != nil else {
            writeStderr("--max-actual-usd requires --price-input-per-m and --price-output-per-m")
            return 2
        }
        guard maxTokensCap > 0 else {
            writeStderr("--max-actual-usd requires --max-tokens-cap > 0 so per-request output tokens are clamped")
            return 2
        }
        guard let capMicro = parseDecimalMicroUsd(capRaw, minMicro: 1, maxMicro: kMaxActualMicroUsdLimit) else {
            writeStderr("Invalid --max-actual-usd '\(capRaw)': must be a decimal in 0.000001...100000 with at most 6 fractional digits")
            return 2
        }
        maxActualMicroUsd = capMicro
    }

    let scheme = (upURL.scheme ?? "").lowercased()
    let upHost = (upURL.host ?? "").lowercased()
    let isValidLoopbackHTTP = (scheme == "http" && upHost == "127.0.0.1" && upURL.port != nil && upURL.user == nil && upURL.password == nil)
    let isValidPinnedHTTPS = isValidPinnedHTTPSURL(upURL)
    guard isValidLoopbackHTTP || isValidPinnedHTTPS else {
        writeStderr("Invalid --upstream-url '\(upStr)': must be http://127.0.0.1:<port>/v1 or https://<public-host>/v1")
        return 2
    }

    // F1: For loopback HTTP upstreams, require --upstream-pid and verify kernel socket ownership
    var verifiedBinding: UpstreamProcessBinding? = nil
    if isValidLoopbackHTTP {
        guard let upid = upstreamPID, upid > 1, upid != getpid() else {
            writeStderr("Loopback HTTP --upstream-url requires a valid --upstream-pid (<pid> > 1)")
            return 2
        }
        let upPort = UInt16(upURL.port!)
        guard let binding = waitForUpstreamBinding(pid: upid, port: upPort, timeoutSeconds: 10.0) else {
            writeStderr("Upstream process pid=\(upid) does not own a non-SO_REUSEPORT listening TCP socket on 127.0.0.1:\(upPort)")
            return 1
        }
        verifiedBinding = binding
    }

    let sessionToken: Data
    do {
        let raw = try readAllFromFD(tokFD)
        let trimmed = String(data: raw, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        sessionToken = Data(trimmed.utf8)
        guard sessionToken.count >= 16 else {
            writeStderr("Session token read from --session-token-fd is too short")
            return 1
        }
    } catch {
        writeStderr("Failed to read session token fd: \(error.localizedDescription)")
        return 1
    }

    // Ignore SIGPIPE early so a broken readiness pipe returns EPIPE instead of killing us before cleanup
    signal(SIGPIPE, SIG_IGN)

    // Unseal API key from Keychain + Secure Enclave (or test fd in SE_KEY_TESTING build)
    var unsealedKeyData: Data
    do {
        #if SE_KEY_TESTING
        if let testFD = testEphemeralKeyFD {
            let raw = try readAllFromFD(testFD)
            let trimmed = String(data: raw, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            unsealedKeyData = Data(trimmed.utf8)
        } else {
            unsealedKeyData = try unsealFromKeychainAndSecureEnclave(
                service: svc,
                account: account,
                upstreamURL: upURL,
                allowedModel: model,
                maxChatRequests: maxChatRequests,
                ttlSeconds: ttlSeconds
            )
        }
        #else
        unsealedKeyData = try unsealFromKeychainAndSecureEnclave(
            service: svc,
            account: account,
            upstreamURL: upURL,
            allowedModel: model,
            maxChatRequests: maxChatRequests,
            ttlSeconds: ttlSeconds
        )
        #endif
    } catch {
        writeStderr("Secure Enclave unseal failed: \(error.localizedDescription)")
        return 1
    }

    // Bind listening socket on 127.0.0.1:lPort before signaling readyFD
    let sockFD = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard sockFD >= 0 else {
        bestEffortZero(&unsealedKeyData)
        writeStderr("socket() failed: errno=\(errno)")
        return 1
    }
    var reuse: Int32 = 1
    _ = setsockopt(sockFD, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = lPort.bigEndian
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")

    let bindRC = withUnsafePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
            Darwin.bind(sockFD, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard bindRC == 0 else {
        _ = Darwin.close(sockFD)
        bestEffortZero(&unsealedKeyData)
        writeStderr("bind(127.0.0.1:\(lPort)) failed: errno=\(errno)")
        return 1
    }
    guard Darwin.listen(sockFD, 32) == 0 else {
        _ = Darwin.close(sockFD)
        bestEffortZero(&unsealedKeyData)
        writeStderr("listen() failed: errno=\(errno)")
        return 1
    }

    #if SE_KEY_TESTING
    let testKeyForRenewal = unsealedKeyData
    #endif
    let authorizeRenewal: (Int) throws -> Data = { seconds in
        #if SE_KEY_TESTING
        if let authFD = testRenewalFD {
            var decision: UInt8 = 0
            guard Darwin.read(authFD, &decision, 1) == 1, decision == 49 else {
                throw NSError(domain: "SessionAuthorization", code: 1)
            }
            return testKeyForRenewal
        }
        // An injected test key must never fall through to real biometric authorization.
        if testEphemeralKeyFD != nil { throw NSError(domain: "SessionAuthorization", code: 2) }
        #endif
        return try unsealFromKeychainAndSecureEnclave(service: svc, account: account,
            upstreamURL: upURL, allowedModel: model, maxChatRequests: maxChatRequests, ttlSeconds: seconds)
    }
    let server = ProxyServer(
        listenPort: lPort,
        upstreamBaseURL: upURL,
        allowedModel: model,
        sessionToken: sessionToken,
        apiKeyData: unsealedKeyData,
        maxChatRequests: maxChatRequests,
        maxRequestBytes: maxRequestBytes,
        maxTokensCap: maxTokensCap,
        streamTimeoutSeconds: streamTimeoutSeconds,
        upstreamPID: upstreamPID,
        upstreamBinding: verifiedBinding,
        forceURLSession: forceURLSession,
        sessionTokenFile: sessionTokenFile,
        defaultChatParams: defaultChatParams,
        ttlSeconds: ttlSeconds,
        pricing: pricingRates,
        maxActualMicroUsd: maxActualMicroUsd,
        renewalAuthorizer: authorizeRenewal
    )
    #if SE_KEY_TESTING
    server.testingPublicationFault = testPublicationFault
    #endif
    // SE_KEY_TESTING renewal callback holds its own synthetic-key copy only.
    if let path = controlSocket {
        do { try server.startControl(path: path) }
        catch { writeStderr("Session control initialization failed"); server.cleanupAndExit(code: 1) }
    }
    bestEffortZero(&unsealedKeyData)

    // Install SIGINT/SIGTERM and TTL dispatch sources
    signal(SIGTERM, SIG_IGN)
    signal(SIGINT, SIG_IGN)
    let sigTermSrc = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
    sigTermSrc.setEventHandler { server.cleanupAndExit(code: 0) }
    sigTermSrc.resume()

    let sigIntSrc = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
    sigIntSrc.setEventHandler { server.cleanupAndExit(code: 0) }
    sigIntSrc.resume()

    let ttlTimer = DispatchSource.makeTimerSource(queue: .global())
    ttlTimer.schedule(deadline: .now() + .milliseconds(100), repeating: .milliseconds(100))
    ttlTimer.setEventHandler {
        server.expireIfNeeded()
    }
    ttlTimer.resume()

    // F1 + Q4: Watch upstream process exit via kqueue EVFILT_PROC and re-verify binding after arming
    var upstreamProcSource: DispatchSourceProcess? = nil
    if let binding = verifiedBinding {
        let procSrc = DispatchSource.makeProcessSource(identifier: binding.pid, eventMask: .exit, queue: .global())
        procSrc.setEventHandler {
            writeStderr("Upstream process pid=\(binding.pid) exited; shutting down se-key-proxy.")
            server.cleanupAndExit(code: 1)
        }
        procSrc.resume()
        upstreamProcSource = procSrc
        // Q4: Re-verify after arming the process source in case the vendor exited during unsealing
        if !verifyUpstreamBinding(binding) {
            writeStderr("Upstream process pid=\(binding.pid) exited or changed listener during startup; shutting down.")
            server.cleanupAndExit(code: 1)
        }
    }
    _ = upstreamProcSource

    if let rfd = readyFD {
        if let readyData = "{\"status\":\"ready\",\"listen_port\":\(lPort)}\n".data(using: .utf8) {
            let wroteOk = writeAllToFD(rfd, data: readyData)
            _ = Darwin.close(rfd)
            if !wroteOk {
                writeStderr("Parent closed readiness pipe before ready signal was read; cleaning up and exiting.")
                server.cleanupAndExit(code: 1)
            }
        } else {
            _ = Darwin.close(rfd)
        }
    }

    while true {
        var clientAddr = sockaddr_in()
        var clientLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let clientFD = withUnsafeMutablePointer(to: &clientAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.accept(sockFD, saPtr, &clientLen)
            }
        }
        if clientFD < 0 {
            if errno == EINTR { continue }
            break
        }
        DispatchQueue.global(qos: .userInitiated).async {
            server.handleClient(fd: clientFD)
        }
    }

    server.cleanupAndExit(code: 0)
}

private func unsealFromKeychainAndSecureEnclave(
    service: String,
    account: String,
    upstreamURL: URL,
    allowedModel: String,
    maxChatRequests: Int,
    ttlSeconds: Int
) throws -> Data {
    let env = try loadEnvelope(service: service, account: account, checkSEPNonInteractive: false)
    guard
        env.version == kEnvelopeVersion,
        env.service == service,
        let seBlob = Data(base64Encoded: env.se_private_key_blob),
        let ephPub = Data(base64Encoded: env.ephemeral_public_key_x963),
        let combined = Data(base64Encoded: env.aes_gcm_combined)
    else {
        throw NSError(
            domain: "SEKeyProxy",
            code: 2,
            userInfo: [NSLocalizedDescriptionKey: "Invalid envelope for service '\(service)'"]
        )
    }

    let upHostPort = "\(upstreamURL.host ?? "upstream"):\(upstreamURL.port.map(String.init) ?? "443")"
    let ctx = LAContext()
    ctx.touchIDAuthenticationAllowableReuseDuration = 0
    ctx.localizedReason =
        "unlock \(service) -> \(upHostPort) (model=\(allowedModel), max_reqs=\(maxChatRequests), ttl=\(ttlSeconds)s)"

    let sePriv = try SecureEnclave.P256.KeyAgreement.PrivateKey(
        dataRepresentation: seBlob,
        authenticationContext: ctx
    )
    let ephPubKey = try P256.KeyAgreement.PublicKey(x963Representation: ephPub)
    let shared = try sePriv.sharedSecretFromKeyAgreement(with: ephPubKey)
    return try unsealPayloadWithSharedSecret(
        sharedSecret: shared,
        ephemeralPubX963: ephPub,
        combinedCiphertext: combined,
        service: service
    )
}

// MARK: - Main Entrypoint

let rawArgs = Array(CommandLine.arguments.dropFirst())
guard let subcmd = rawArgs.first else {
    writeStderr("usage: se-key-proxy <seal|status|delete|migrate-from-legacy|selftest|proxy> [options]")
    Darwin.exit(2)
}
let subArgs = Array(rawArgs.dropFirst())

switch subcmd {
case "seal":
    Darwin.exit(runSeal(args: subArgs))
case "status":
    Darwin.exit(runStatus(args: subArgs))
case "delete":
    Darwin.exit(runDelete(args: subArgs))
case "migrate-from-legacy":
    Darwin.exit(runMigrateFromLegacy(args: subArgs))
case "selftest":
    Darwin.exit(runSelftest())
case "proxy":
    Darwin.exit(runProxy(args: subArgs))
default:
    writeStderr(
        "Unknown subcommand '\(subcmd)'. Expected seal, status, delete, migrate-from-legacy, selftest, or proxy."
    )
    Darwin.exit(2)
}
