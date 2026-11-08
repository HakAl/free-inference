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

// MARK: - ECIES Envelope & Keychain

private struct SealedEnvelope: Codable {
    let version: Int
    let service: String
    let created_at: String
    let key_fingerprint: String
    let se_private_key_blob: String
    let ephemeral_public_key_x963: String
    let aes_gcm_combined: String
}

private func sealPayloadWithPublicKey(
    secret: Data,
    recipientPublicKeyX963: Data,
    service: String
) throws -> (ephemeralPubX963: Data, combinedCiphertext: Data) {
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

private func storeKeychainEnvelope(service: String, account: String, envelopeData: Data) throws {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
    SecItemDelete(query as CFDictionary)

    let addAttrs: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecAttrLabel as String: service,
        kSecValueData as String: envelopeData,
    ]
    let status = SecItemAdd(addAttrs as CFDictionary, nil)
    guard status == errSecSuccess else {
        throw NSError(
            domain: NSOSStatusErrorDomain,
            code: Int(status),
            userInfo: [NSLocalizedDescriptionKey: "SecItemAdd failed with OSStatus \(status)"]
        )
    }
}

private func loadKeychainEnvelope(service: String, account: String) throws -> SealedEnvelope {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let data = item as? Data else {
        throw NSError(
            domain: NSOSStatusErrorDomain,
            code: Int(status),
            userInfo: [NSLocalizedDescriptionKey: "Keychain entry not found for service '\(service)' (OSStatus \(status))"]
        )
    }
    return try JSONDecoder().decode(SealedEnvelope.self, from: data)
}

private func deleteKeychainEnvelope(service: String, account: String) throws -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
    let status = SecItemDelete(query as CFDictionary)
    if status == errSecSuccess {
        return true
    }
    if status == errSecItemNotFound {
        return false
    }
    throw NSError(
        domain: NSOSStatusErrorDomain,
        code: Int(status),
        userInfo: [NSLocalizedDescriptionKey: "SecItemDelete failed with OSStatus \(status)"]
    )
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

private final class StreamingForwardDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var clientFD: Int32
    let deadlineUptimeNs: UInt64
    private let sem = DispatchSemaphore(value: 0)
    private var wroteHeaders = false
    private var cancelled = false
    private var signaled = false
    private(set) var completedError: Error?

    init(clientFD: Int32, timeoutSeconds: Int) {
        self.clientFD = clientFD
        let clamped = UInt64(max(1, timeoutSeconds))
        self.deadlineUptimeNs = DispatchTime.now().uptimeNanoseconds + clamped * 1_000_000_000
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
        let ok = writeHeadersSafe(status: status, contentType: contentType)
        completionHandler(ok ? .allow : .cancel)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        if !data.isEmpty {
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

private final class ProxyServer: @unchecked Sendable {
    let listenPort: UInt16
    let upstreamBaseURL: URL
    let allowedModel: String
    let sessionToken: Data
    var apiKeyData: Data
    let maxChatRequests: Int
    let maxRequestBytes: Int
    let maxTokensCap: Int
    let streamTimeoutSeconds: Int
    let upstreamPID: pid_t?
    let upstreamBinding: UpstreamProcessBinding?
    let forceURLSession: Bool
    let sessionTokenFile: String?

    private let lock = NSLock()
    private var chatRequestsUsed = 0
    private var cleanedUp = false
    private let urlSession: URLSession

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
        sessionTokenFile: String?
    ) {
        self.listenPort = listenPort
        self.upstreamBaseURL = upstreamBaseURL
        self.allowedModel = allowedModel
        self.sessionToken = sessionToken
        self.apiKeyData = apiKeyData
        self.maxChatRequests = maxChatRequests
        self.maxRequestBytes = maxRequestBytes
        self.maxTokensCap = maxTokensCap
        self.streamTimeoutSeconds = max(1, streamTimeoutSeconds)
        self.upstreamPID = upstreamPID
        self.upstreamBinding = upstreamBinding
        self.forceURLSession = forceURLSession
        self.sessionTokenFile = sessionTokenFile

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

    func cleanupAndExit(code: Int32) -> Never {
        lock.lock()
        if !cleanedUp {
            cleanedUp = true
            bestEffortZero(&apiKeyData)
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
        let delegate = StreamingForwardDelegate(clientFD: fd, timeoutSeconds: streamTimeoutSeconds)
        defer { delegate.closeClientSocket() }

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
            sendHTTPError(
                clientFD: fd,
                status: 401,
                statusText: "Unauthorized",
                errorCode: "unauthorized",
                message: "Invalid session token"
            )
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

            // Enforce session chat request budget before forwarding
            lock.lock()
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
            chatRequestsUsed += 1
            lock.unlock()

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
                method: method,
                upstreamBaseURL: upstreamBaseURL,
                upstreamPath: upstreamPath,
                acceptHeader: acceptHeader,
                contentTypeHeader: isChatPost ? (contentTypeHeader ?? "application/json") : nil,
                outboundBody: outboundBody,
                apiKeyStr: apiKeyStr
            )
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
        task.resume()
        let finished = delegate.waitForCompletion(timeoutSeconds: Double(streamTimeoutSeconds))
        if !finished {
            delegate.cancelAndShutdownSocket()
            task.cancel()
            session.invalidateAndCancel()
            _ = delegate.waitForCompletion(timeoutSeconds: 2.0)
        } else {
            session.finishTasksAndInvalidate()
        }
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

        guard let reqHeaderData = reqHeader.data(using: .utf8),
              writeNonBlocking(upFD, data: reqHeaderData, delegate: delegate) else {
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

        guard let headerEnd = respHeaderEnd,
              let respHeaderStr = String(data: upBuf.subdata(in: 0..<headerEnd.lowerBound), encoding: .utf8) else {
            delegate.sendErrorSafe(
                status: 502,
                statusText: "Bad Gateway",
                errorCode: "upstream_error",
                message: "Malformed or oversized upstream HTTP response headers"
            )
            return
        }

        var remBuf = Data(upBuf.subdata(in: headerEnd.upperBound..<upBuf.count))
        let respLines = respHeaderStr.components(separatedBy: "\r\n")
        guard let statusLine = respLines.first else {
            delegate.sendErrorSafe(
                status: 502,
                statusText: "Bad Gateway",
                errorCode: "upstream_error",
                message: "Empty upstream status line"
            )
            return
        }
        let statusParts = statusLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard statusParts.count >= 2,
              statusParts[0].hasPrefix("HTTP/1."),
              let statusCode = Int(statusParts[1]),
              (100...599).contains(statusCode) else {
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

        for line in respLines.dropFirst() {
            if line.isEmpty { continue }
            guard let colonIdx = line.firstIndex(of: ":") else { continue }
            let hName = String(line[..<colonIdx]).trimmingCharacters(in: .whitespaces).lowercased()
            let hVal = String(line[line.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
            switch hName {
            case "content-type":
                respContentType = hVal
            case "transfer-encoding":
                if hVal.lowercased().contains("chunked") {
                    isChunked = true
                }
            case "content-length":
                if let cl = Int(hVal), cl >= 0 {
                    respContentLength = cl
                }
            default:
                // Strip Set-Cookie and all other non-essential headers
                break
            }
        }

        guard delegate.writeHeadersSafe(status: statusCode, contentType: respContentType) else {
            return
        }

        if isChunked {
            let crlf = Data([0x0D, 0x0A])
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
                guard let lineRange = remBuf.range(of: crlf),
                      let sizeLine = String(data: remBuf.subdata(in: 0..<lineRange.lowerBound), encoding: .utf8) else {
                    return
                }
                remBuf.removeSubrange(0..<lineRange.upperBound)

                let hexPart = sizeLine.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init)?.trimmingCharacters(in: .whitespaces) ?? ""
                // Cap chunk hex digits at 8 (<= 0xFFFFFFFF) and require every character to be a hex digit
                guard !hexPart.isEmpty, hexPart.count <= 8,
                      hexPart.allSatisfy({ $0.isHexDigit }),
                      let chunkSize = Int(hexPart, radix: 16), chunkSize >= 0 else {
                    return
                }

                if chunkSize == 0 {
                    // Terminal chunk: consume optional trailers up to final \r\n
                    while true {
                        if let tRange = remBuf.range(of: crlf) {
                            let trailerLen = tRange.lowerBound
                            remBuf.removeSubrange(0..<tRange.upperBound)
                            if trailerLen == 0 {
                                break
                            }
                        } else {
                            if remBuf.count > 16384 {
                                return
                            }
                            let n = readIntoBufferNonBlocking(upFD, buffer: &remBuf, delegate: delegate)
                            if n <= 0 {
                                break
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
                    return
                }
                remBuf.removeSubrange(0..<2)
            }
        } else if let cl = respContentLength {
            var remaining = cl
            if !remBuf.isEmpty {
                let take = min(remaining, remBuf.count)
                let slice = Data(remBuf.subdata(in: 0..<take))
                remBuf.removeSubrange(0..<take)
                remaining -= take
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
                if !delegate.writeSafe(chunkBuf) {
                    return
                }
            }
        } else {
            if !remBuf.isEmpty {
                if !delegate.writeSafe(remBuf) {
                    return
                }
                remBuf.removeAll()
            }
            while true {
                var chunkBuf = Data()
                let n = readIntoBufferNonBlocking(upFD, buffer: &chunkBuf, maxChunk: 16384, delegate: delegate)
                if n > 0 {
                    if !delegate.writeSafe(chunkBuf) {
                        return
                    }
                } else {
                    break
                }
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

        // CryptoKit's exported SecureEnclave.P256 key blob (sepk) requires
        // kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as the base AKS protection class
        // for [.privateKeyUsage, .biometryCurrentSet] in CLI binaries without a Data Protection
        // Keychain provisioning profile. The SE key is usable after first unlock since boot,
        // and every unseal operation requires a live Touch ID biometric match.
        var cfErr: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &cfErr
        ) else {
            writeStderr("SecAccessControlCreateWithFlags failed: \(String(describing: cfErr))")
            return 1
        }

        let sePriv = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
        let pubX963 = sePriv.publicKey.x963Representation
        let keyFingerprint = String(sha256Hex(pubX963).prefix(16))

        let (ephPub, combined) = try sealPayloadWithPublicKey(
            secret: secretData,
            recipientPublicKeyX963: pubX963,
            service: svc
        )

        let createdAt = isoNow()
        let envelope = SealedEnvelope(
            version: kEnvelopeVersion,
            service: svc,
            created_at: createdAt,
            key_fingerprint: keyFingerprint,
            se_private_key_blob: sePriv.dataRepresentation.base64EncodedString(),
            ephemeral_public_key_x963: ephPub.base64EncodedString(),
            aes_gcm_combined: combined.base64EncodedString()
        )
        let envelopeBytes = try JSONEncoder().encode(envelope)
        try storeKeychainEnvelope(service: svc, account: account, envelopeData: envelopeBytes)

        printJSON([
            "status": "sealed",
            "service": svc,
            "account": account,
            "key_fingerprint": keyFingerprint,
            "created_at": createdAt,
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
        let env = try loadKeychainEnvelope(service: svc, account: account)
        guard
            env.version == kEnvelopeVersion,
            env.service == svc,
            let seBlob = Data(base64Encoded: env.se_private_key_blob), !seBlob.isEmpty,
            let ephPub = Data(base64Encoded: env.ephemeral_public_key_x963),
            (try? P256.KeyAgreement.PublicKey(x963Representation: ephPub)) != nil,
            let combined = Data(base64Encoded: env.aes_gcm_combined), combined.count > 28
        else {
            writeStderr("Keychain envelope for '\(svc)' failed structural validation.")
            return 1
        }
        printJSON([
            "exists": true,
            "service": svc,
            "account": account,
            "version": env.version,
            "key_fingerprint": env.key_fingerprint,
            "created_at": env.created_at,
            "se_blob_bytes": seBlob.count,
            "ciphertext_bytes": combined.count,
        ])
        return 0
    } catch {
        printJSON([
            "exists": false,
            "service": svc,
            "account": account,
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
        let deleted = try deleteKeychainEnvelope(service: svc, account: account)
        printJSON([
            "deleted": deleted,
            "service": svc,
            "account": account,
        ])
        return 0
    } catch {
        writeStderr("delete failed: \(error.localizedDescription)")
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
    var streamTimeoutSeconds = 300
    var forceURLSession = false
    #if SE_KEY_TESTING
    var testEphemeralKeyFD: Int32?
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
        case "--max-chat-requests":
            i += 1
            if i < args.count, let v = Int(args[i]), v > 0 { maxChatRequests = v }
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
        default:
            #if SE_KEY_TESTING
            if args[i] == "--test-ephemeral-key-fd" {
                i += 1
                if i < args.count, let fd = Int32(args[i]) {
                    testEphemeralKeyFD = fd
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
        sessionTokenFile: sessionTokenFile
    )
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
    ttlTimer.schedule(deadline: .now() + .seconds(ttlSeconds))
    ttlTimer.setEventHandler {
        writeStderr("se-key-proxy session TTL (\(ttlSeconds)s) expired; shutting down.")
        server.cleanupAndExit(code: 0)
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
    let env = try loadKeychainEnvelope(service: service, account: account)
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
            userInfo: [NSLocalizedDescriptionKey: "Invalid Keychain envelope for service '\(service)'"]
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
    writeStderr("usage: se-key-proxy <seal|status|delete|selftest|proxy> [options]")
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
case "selftest":
    Darwin.exit(runSelftest())
case "proxy":
    Darwin.exit(runProxy(args: subArgs))
default:
    writeStderr("Unknown subcommand '\(subcmd)'. Expected seal, status, delete, selftest, or proxy.")
    Darwin.exit(2)
}
