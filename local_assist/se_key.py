from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SWIFT_SOURCE_PATH = ROOT / "tools" / "se_key_proxy" / "main.swift"
BIN_DIR = ROOT / "bin"
RELEASE_BINARY_PATH = BIN_DIR / "se-key-proxy"
TEST_BINARY_PATH = BIN_DIR / "se-key-proxy-test"
LEGACY_BINARY_PATH = BIN_DIR / ".se-key-proxy-legacy"
STAMP_PATH = BIN_DIR / ".se-key-proxy.stamp"

EXPECTED_SWIFT_SOURCE_SHA256 = "0b549dce5ee1cba2d772714bd02558b0313f0d5b154163b594e408c6ac412e18"
EXPECTED_LEGACY_BINARY_SHA256 = "012f4414ad3c9889915aaf9318e77d28d145b3a973ecf190fe7b017342fe04c2"
DEFAULT_ENVELOPE_ACCOUNT = "free-inference"
SKIP_EXIT_CODE = 77
SESSION_TOKEN_REDACT_RE = re.compile(r"se-session-[A-Za-z0-9_-]{16,}")
SESSION_TOKEN_BYTES_RE = re.compile(rb"se-session-[A-Za-z0-9_-]{16,}")
DEFAULT_REDACT_TEXT_FILENAMES = frozenset({
    "output.json",
    "promptfoo.log",
    "events.jsonl",
    "stderr.log",
})
DEFAULT_EXCLUDED_DIR_NAMES = frozenset({
    "huggingface",
    ".npm",
})


def redact_and_count_session_tokens(text: str) -> tuple[str, int]:
    """Scrub ephemeral se-session-* tokens and return (scrubbed_text, redaction_count)."""
    return SESSION_TOKEN_REDACT_RE.subn("[REDACTED_SESSION_TOKEN]", text)


def redact_session_tokens(text: str) -> str:
    """Scrub ephemeral se-session-* tokens from logs and run artifacts."""
    scrubbed, _ = redact_and_count_session_tokens(text)
    return scrubbed


def _stream_count_token_matches(fpath: Path, chunk_size: int = 1048576, overlap: int = 256) -> tuple[int, int]:
    """Stream a file in chunks to count se-session-* matches without loading it whole into memory.

    Returns (bytes_scanned, match_count).
    """
    bytes_scanned = 0
    matched_spans: set[tuple[int, int]] = set()
    tail = b""
    tail_offset = 0
    with fpath.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            buf = tail + chunk
            buf_start = tail_offset
            bytes_scanned += len(chunk)
            for m in SESSION_TOKEN_BYTES_RE.finditer(buf):
                abs_start = buf_start + m.start()
                abs_end = buf_start + m.end()
                # If a match reaches the very end of buf and chunk was full, it might continue in next chunk;
                # overlapping by 256 bytes will see the full token on the next iteration starting at abs_start.
                matched_spans.add((abs_start, abs_end))
            if len(buf) > overlap:
                tail = buf[-overlap:]
                tail_offset = bytes_scanned - overlap
            else:
                tail = buf
                tail_offset = buf_start
    # Deduplicate prefix matches that were extended across a chunk boundary
    final_starts: dict[int, int] = {}
    for s, e in matched_spans:
        if s not in final_starts or e > final_starts[s]:
            final_starts[s] = e
    return bytes_scanned, len(final_starts)


def scan_and_redact_directory_tokens(
    roots: list[Path],
    redact_filenames: set[str] | frozenset[str] = DEFAULT_REDACT_TEXT_FILENAMES,
    excluded_dir_names: set[str] | frozenset[str] = DEFAULT_EXCLUDED_DIR_NAMES,
) -> dict[str, Any]:
    """Scan all regular files under roots for se-session-* tokens.

    Redacts in-place only known UTF-8 text logs (redact_filenames) and never modifies
    SQLite databases or other files in-place. Returns a manifest dict suitable for
    metrics.json / summary.json.
    """
    files_scanned = 0
    bytes_scanned = 0
    redactions_applied = 0
    matches_found = 0
    remaining_matches = 0
    files_skipped: list[dict[str, str]] = []
    excluded_dirs: list[dict[str, str]] = []
    matched_files: list[str] = []
    missing_roots: list[str] = []

    unique_roots: list[Path] = []
    seen_root_strs: set[str] = set()
    for r in roots:
        rs = str(r)
        if rs not in seen_root_strs:
            seen_root_strs.add(rs)
            unique_roots.append(r)

    for root in unique_roots:
        if not root.exists():
            missing_roots.append(str(root))
            continue

        def _on_walk_error(exc: OSError) -> None:
            bad_path = getattr(exc, "filename", None) or str(root)
            files_skipped.append({"path": str(bad_path), "reason": f"walk_error: {exc}"})

        for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=_on_walk_error):
            dirnames.sort()
            is_top_home_root = Path(dirpath) == root and root.name == ".home"
            kept_dirs: list[str] = []
            for dname in dirnames:
                dpath = Path(dirpath) / dname
                if is_top_home_root and dname in excluded_dir_names:
                    excluded_dirs.append({"path": str(dpath), "reason": "excluded_dir_name"})
                    continue
                try:
                    dst = os.lstat(dpath)
                except OSError as exc:
                    files_skipped.append({"path": str(dpath), "reason": f"lstat_error: {exc}"})
                    continue
                if stat.S_ISLNK(dst.st_mode):
                    excluded_dirs.append({"path": str(dpath), "reason": "symlink_dir"})
                    continue
                kept_dirs.append(dname)
            dirnames[:] = kept_dirs

            for fname in sorted(filenames):
                fpath = Path(dirpath) / fname
                try:
                    st = os.lstat(fpath)
                except OSError as exc:
                    files_skipped.append({"path": str(fpath), "reason": f"lstat_error: {exc}"})
                    continue
                if not stat.S_ISREG(st.st_mode):
                    files_skipped.append({"path": str(fpath), "reason": "non_regular_file"})
                    continue

                if fname in redact_filenames:
                    try:
                        raw = fpath.read_bytes()
                    except OSError as exc:
                        files_skipped.append({"path": str(fpath), "reason": f"read_error: {exc}"})
                        continue
                    files_scanned += 1
                    bytes_scanned += len(raw)
                    raw_matches = len(SESSION_TOKEN_BYTES_RE.findall(raw))
                    if raw_matches == 0:
                        continue
                    matches_found += raw_matches
                    matched_files.append(str(fpath))
                    try:
                        decoded = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        remaining_matches += raw_matches
                        continue
                    scrubbed, count = redact_and_count_session_tokens(decoded)
                    if count > 0:
                        try:
                            fpath.write_text(scrubbed, encoding="utf-8")
                            redactions_applied += count
                        except OSError:
                            remaining_matches += raw_matches
                            continue
                    rem = len(SESSION_TOKEN_BYTES_RE.findall(fpath.read_bytes()))
                    remaining_matches += rem
                else:
                    try:
                        file_bytes, raw_matches = _stream_count_token_matches(fpath)
                    except OSError as exc:
                        files_skipped.append({"path": str(fpath), "reason": f"read_error: {exc}"})
                        continue
                    files_scanned += 1
                    bytes_scanned += file_bytes
                    if raw_matches > 0:
                        matches_found += raw_matches
                        remaining_matches += raw_matches
                        matched_files.append(str(fpath))

    return {
        "roots": [str(r) for r in unique_roots],
        "missing_roots": missing_roots,
        "excluded_dirs": excluded_dirs,
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "files_skipped": files_skipped,
        "matches_found": matches_found,
        "redactions_applied": redactions_applied,
        "remaining_unredacted_matches": remaining_matches,
        "matched_files": matched_files,
    }


class SEKeyIntegrityError(Exception):
    """Raised when the Secure Enclave helper source, build stamp, or binary fails integrity checks."""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def get_swiftc_version() -> str:
    try:
        cp = subprocess.run(
            ["swiftc", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except Exception as exc:
        raise SEKeyIntegrityError(f"Could not query 'swiftc --version': {exc}") from exc
    first_line = (cp.stdout.splitlines() or [""])[0].strip()
    if not first_line:
        raise SEKeyIntegrityError("swiftc --version returned empty output")
    return first_line


def verify_swift_source(source_path: Path | None = None) -> str:
    src = source_path or SWIFT_SOURCE_PATH
    if not src.is_file() or src.is_symlink():
        raise SEKeyIntegrityError(f"Swift source not found or is a symlink: {src}")
    actual = sha256_file(src)
    if actual != EXPECTED_SWIFT_SOURCE_SHA256:
        raise SEKeyIntegrityError(
            f"Swift source drift detected in {src}: expected SHA-256 {EXPECTED_SWIFT_SOURCE_SHA256}, got {actual}"
        )
    return actual


def verify_root_owned_binary_and_ancestors(binary_path: Path | str) -> None:
    raw_str = str(binary_path)
    if not os.path.isabs(raw_str):
        raise SEKeyIntegrityError(
            f"FREE_INFERENCE_SE_PROXY_BIN must be an absolute path: {binary_path}"
        )
    raw_segments = [seg for seg in raw_str.replace("\\", "/").split("/") if seg]
    if any(seg in (".", "..") for seg in raw_segments):
        raise SEKeyIntegrityError(
            f"Refusing dot-segment traversal in FREE_INFERENCE_SE_PROXY_BIN: {binary_path}"
        )
    current = Path(os.path.normpath(raw_str))
    visited: list[Path] = []
    while True:
        visited.append(current)
        if current.parent == current:
            break
        current = current.parent

    for idx, path in enumerate(visited):
        try:
            st = os.lstat(path)
        except OSError as exc:
            if idx == 0:
                raise SEKeyIntegrityError(
                    f"FREE_INFERENCE_SE_PROXY_BIN does not exist or is not a regular file: {binary_path}"
                ) from exc
            raise SEKeyIntegrityError(f"Could not stat {path}: {exc}") from exc
        if stat.S_ISLNK(st.st_mode):
            if idx == 0:
                raise SEKeyIntegrityError(
                    f"Refusing symlinked FREE_INFERENCE_SE_PROXY_BIN: {binary_path}"
                )
            raise SEKeyIntegrityError(f"Path component {path} is a symlink")
        if idx == 0 and not stat.S_ISREG(st.st_mode):
            raise SEKeyIntegrityError(
                f"FREE_INFERENCE_SE_PROXY_BIN does not exist or is not a regular file: {binary_path}"
            )
        if st.st_uid != 0:
            raise SEKeyIntegrityError(
                f"Path component {path} must be owned by root (uid=0), got uid={st.st_uid}"
            )
        if (st.st_mode & 0o022) != 0:
            raise SEKeyIntegrityError(
                f"Path component {path} must not be group- or world-writable (mode={oct(st.st_mode & 0o777)})"
            )
    if Path(raw_str).resolve() != Path(os.path.normpath(raw_str)):
        raise SEKeyIntegrityError(
            f"Canonical path mismatch for FREE_INFERENCE_SE_PROXY_BIN: {binary_path}"
        )


def _compile_and_install_binary_atomically(
    swiftc_args: list[str],
    dest_bin: Path,
    target_dir: Path,
) -> str:
    """Compile and codesign into a temporary staging file, then atomically replace dest_bin.

    Never writes or re-signs dest_bin in-place, so any running process mapped from the
    previous inode on macOS keeps its open vnode and code-signature pages intact.
    """
    fd, tmp_str = tempfile.mkstemp(prefix=".se-key-proxy-build-", dir=str(target_dir))
    os.close(fd)
    tmp_path = Path(tmp_str)
    try:
        subprocess.run(
            [*swiftc_args, "-o", str(tmp_path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        subprocess.run(
            ["codesign", "-f", "-s", "-", "--options", "runtime", str(tmp_path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        os.chmod(tmp_path, 0o755)
        digest = sha256_file(tmp_path)
        os.replace(str(tmp_path), str(dest_bin))
        return digest
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def build_se_key_proxy(
    *,
    include_test_binary: bool = False,
    source_path: Path | None = None,
    bin_dir: Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    src = source_path or SWIFT_SOURCE_PATH
    source_sha = verify_swift_source(src)
    swiftc_ver = get_swiftc_version()

    target_dir = bin_dir or BIN_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    release_bin = target_dir / "se-key-proxy"
    test_bin = target_dir / "se-key-proxy-test"
    stamp_file = target_dir / ".se-key-proxy.stamp"

    reuse_existing_release = False
    if not force and release_bin.is_file() and stamp_file.is_file():
        try:
            verify_se_key_proxy_binary(
                source_path=src,
                stamp_path=stamp_file,
                binary_path=release_bin,
                env={},
            )
            reuse_existing_release = True
        except SEKeyIntegrityError:
            reuse_existing_release = False

    if reuse_existing_release:
        release_sha = sha256_file(release_bin)
    else:
        legacy_bin = target_dir / ".se-key-proxy-legacy"
        if release_bin.is_file() and not release_bin.is_symlink():
            try:
                current_rel_sha = sha256_file(release_bin)
            except OSError as exc:
                raise SEKeyIntegrityError(
                    f"Failed to read existing release binary {release_bin} before build: {exc}"
                ) from exc
            if current_rel_sha == EXPECTED_LEGACY_BINARY_SHA256:
                backup_valid = False
                if legacy_bin.is_symlink() or (legacy_bin.exists() and not legacy_bin.is_file()):
                    raise SEKeyIntegrityError(
                        f"Refusing to replace legacy se-key-proxy release at {release_bin}: "
                        f"existing backup path {legacy_bin} is not a regular file."
                    )
                if legacy_bin.is_file():
                    try:
                        if (
                            sha256_file(legacy_bin) == EXPECTED_LEGACY_BINARY_SHA256
                            and os.access(legacy_bin, os.X_OK)
                        ):
                            backup_valid = True
                    except OSError:
                        backup_valid = False
                if not backup_valid:
                    tmp_leg: Path | None = None
                    try:
                        fd_leg, tmp_leg_str = tempfile.mkstemp(
                            prefix=".se-key-proxy-leg-", dir=str(target_dir)
                        )
                        tmp_leg = Path(tmp_leg_str)
                        data_bytes = release_bin.read_bytes()
                        with os.fdopen(fd_leg, "wb") as leg_handle:
                            leg_handle.write(data_bytes)
                            leg_handle.flush()
                            os.fsync(leg_handle.fileno())
                        os.chmod(tmp_leg, 0o755)
                        os.replace(str(tmp_leg), str(legacy_bin))
                        if (
                            not legacy_bin.is_file()
                            or legacy_bin.is_symlink()
                            or sha256_file(legacy_bin) != EXPECTED_LEGACY_BINARY_SHA256
                            or not os.access(legacy_bin, os.X_OK)
                        ):
                            raise SEKeyIntegrityError(
                                f"Failed to verify preserved legacy binary at {legacy_bin} before replacing {release_bin}."
                            )
                    except OSError as exc:
                        raise SEKeyIntegrityError(
                            f"Refusing to replace legacy se-key-proxy release at {release_bin}: "
                            f"failed to preserve verified backup at {legacy_bin}: {exc}"
                        ) from exc
                    finally:
                        if tmp_leg is not None and tmp_leg.exists():
                            try:
                                tmp_leg.unlink()
                            except OSError:
                                pass
        release_sha = _compile_and_install_binary_atomically(
            ["swiftc", "-O", str(src)],
            release_bin,
            target_dir,
        )

    test_sha: str | None = None
    if include_test_binary:
        test_sha = _compile_and_install_binary_atomically(
            ["swiftc", "-O", "-D", "SE_KEY_TESTING", str(src)],
            test_bin,
            target_dir,
        )

    stamp_data = {
        "source_sha256": source_sha,
        "swiftc_version": swiftc_ver,
        "binary_sha256": release_sha,
    }
    if not reuse_existing_release:
        s_fd, s_tmp_str = tempfile.mkstemp(prefix=".se-key-proxy-stamp-", dir=str(target_dir))
        s_tmp_path = Path(s_tmp_str)
        try:
            with os.fdopen(s_fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(stamp_data, indent=2, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(s_tmp_path, 0o644)
            os.replace(str(s_tmp_path), str(stamp_file))
        finally:
            if s_tmp_path.exists():
                try:
                    s_tmp_path.unlink()
                except OSError:
                    pass
    return {
        **stamp_data,
        "release_binary": str(release_bin),
        "test_binary": str(test_bin) if include_test_binary else None,
        "test_binary_sha256": test_sha,
        "stamp_file": str(stamp_file),
    }


def verify_se_key_proxy_binary(
    *,
    source_path: Path | None = None,
    stamp_path: Path | None = None,
    binary_path: Path | None = None,
    env: dict[str, str] | None = None,
) -> Path:
    """Verify source, build stamp, and release binary without auto-rebuilding."""
    src = source_path or SWIFT_SOURCE_PATH
    source_sha = verify_swift_source(src)
    swiftc_ver = get_swiftc_version()

    st_file = stamp_path or STAMP_PATH
    if not st_file.is_file():
        raise SEKeyIntegrityError(
            f"Build stamp not found at {st_file}. Run './scripts/se-key build' first."
        )
    try:
        stamp = json.loads(st_file.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SEKeyIntegrityError(f"Invalid build stamp at {st_file}: {exc}") from exc

    if not isinstance(stamp, dict):
        raise SEKeyIntegrityError(f"Expected JSON object in build stamp {st_file}")
    if stamp.get("source_sha256") != source_sha:
        raise SEKeyIntegrityError(
            f"Build stamp source_sha256 mismatch in {st_file}: stamp has {stamp.get('source_sha256')}, "
            f"expected {source_sha}. Run './scripts/se-key build'."
        )
    if stamp.get("swiftc_version") != swiftc_ver:
        raise SEKeyIntegrityError(
            f"Build stamp swiftc_version mismatch in {st_file}: stamp has '{stamp.get('swiftc_version')}', "
            f"current toolchain is '{swiftc_ver}'. Run './scripts/se-key build' and re-seal Keychain items."
        )
    expected_bin_sha = stamp.get("binary_sha256")
    if not isinstance(expected_bin_sha, str) or len(expected_bin_sha) != 64:
        raise SEKeyIntegrityError(f"Build stamp {st_file} is missing a valid 64-hex binary_sha256")

    effective_env = env if env is not None else os.environ
    override_bin = effective_env.get("FREE_INFERENCE_SE_PROXY_BIN", "").strip()
    if binary_path is not None:
        target_bin = binary_path
        if override_bin:
            verify_root_owned_binary_and_ancestors(override_bin)
            verify_root_owned_binary_and_ancestors(target_bin)
            target_bin = target_bin.resolve()
    elif override_bin:
        verify_root_owned_binary_and_ancestors(override_bin)
        target_bin = Path(override_bin).resolve()
    else:
        target_bin = RELEASE_BINARY_PATH

    if target_bin.name == "se-key-proxy-test":
        raise SEKeyIntegrityError("Refusing to use test binary 'se-key-proxy-test' as release proxy")
    if not target_bin.is_file() or target_bin.is_symlink():
        raise SEKeyIntegrityError(
            f"Release binary not found or is a symlink at {target_bin}. Run './scripts/se-key build' first."
        )

    actual_bin_sha = sha256_file(target_bin)
    if actual_bin_sha != expected_bin_sha:
        raise SEKeyIntegrityError(
            f"Binary SHA-256 mismatch for {target_bin}: stamp expected {expected_bin_sha}, got {actual_bin_sha}"
        )
    cs = subprocess.run(
        ["codesign", "-v", "--strict", str(target_bin)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if cs.returncode != 0:
        raise SEKeyIntegrityError(
            f"codesign verification failed for {target_bin}: {(cs.stderr or cs.stdout).strip()}"
        )
    return target_bin.resolve()


def ensure_envelope_available_or_migrate(
    service: str,
    *,
    account: str = DEFAULT_ENVELOPE_ACCOUNT,
    se_proxy_bin: Path | None = None,
    legacy_bin: Path | None = None,
    force: bool = False,
    run_cmd: Any = subprocess.run,
) -> tuple[bool, str, dict[str, Any] | None]:
    """Verify file-backed envelope availability or migrate from legacy Keychain helper.

    Discovery order:
    1. When force=False, check new file-backed `se-key-proxy status` first (never touches Keychain).
       If exit 0, return (True, "ready", payload).
    2. If lifecycle_state != "none" (e.g. "deleted", "sealed", "migrated"), do not auto-migrate;
       fail closed so deliberate deletions or prior states are never auto-overwritten.
    3. Only when lifecycle_state == "none" (or force=True), check `legacy_bin` status first and
       then invoke `se-key-proxy migrate-from-legacy` so raw key custody stays inside the
       PT_DENY_ATTACH Swift helper.
    """
    target_bin = se_proxy_bin if se_proxy_bin is not None else verify_se_key_proxy_binary()
    status_payload: dict[str, Any] | None = None

    if not force:
        st_cp = run_cmd(
            [str(target_bin), "status", "--service", service, "--account", account],
            capture_output=True,
            text=True,
            check=False,
        )
        raw_out = (st_cp.stdout or "").strip()
        if raw_out:
            try:
                parsed = json.loads(raw_out)
                if isinstance(parsed, dict):
                    status_payload = parsed
            except json.JSONDecodeError:
                status_payload = None

        if st_cp.returncode == 0 and isinstance(status_payload, dict) and status_payload.get("exists") is True:
            return True, "ready", status_payload

        lifecycle_state = (
            str(status_payload.get("lifecycle_state") or "none")
            if isinstance(status_payload, dict)
            else "unknown"
        )
        if lifecycle_state != "none":
            err_detail = (
                str(status_payload.get("error") or "")
                if isinstance(status_payload, dict)
                else (st_cp.stderr or st_cp.stdout or "").strip()
            )
            return (
                False,
                f"Envelope for '{service}' is not available (lifecycle_state='{lifecycle_state}': {err_detail}). "
                f"Run './scripts/se-key store {service}' to seal a key or './scripts/se-key migrate {service} --force' to re-import from legacy Keychain.",
                status_payload,
            )

    leg_path = legacy_bin if legacy_bin is not None else LEGACY_BINARY_PATH
    if not leg_path.is_file() or leg_path.is_symlink():
        return (
            False,
            f"No sealed envelope found for '{service}'. Run './scripts/se-key store {service}' first.",
            status_payload,
        )
    if legacy_bin is None:
        actual_leg_sha = sha256_file(leg_path)
        if actual_leg_sha != EXPECTED_LEGACY_BINARY_SHA256:
            return (
                False,
                f"Legacy Keychain helper at {leg_path} failed SHA-256 verification "
                f"(expected {EXPECTED_LEGACY_BINARY_SHA256}, got {actual_leg_sha}). "
                f"Run './scripts/se-key store {service}' to seal your API key directly.",
                status_payload,
            )

    leg_st = run_cmd(
        [str(leg_path), "status", "--service", service, "--account", account],
        capture_output=True,
        text=True,
        check=False,
    )
    if leg_st.returncode != 0:
        return (
            False,
            f"No sealed envelope found for '{service}'. Run './scripts/se-key store {service}' first.",
            status_payload,
        )

    mig_cmd = [
        str(target_bin),
        "migrate-from-legacy",
        "--service",
        service,
        "--account",
        account,
        "--legacy-binary",
        str(leg_path.resolve()),
    ]
    if force:
        mig_cmd.append("--force")

    mig_cp = run_cmd(
        mig_cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    mig_out = (mig_cp.stdout or "").strip()
    mig_payload: dict[str, Any] | None = None
    if mig_out:
        try:
            parsed_mig = json.loads(mig_out)
            if isinstance(parsed_mig, dict):
                mig_payload = parsed_mig
        except json.JSONDecodeError:
            mig_payload = None

    if mig_cp.returncode == 0 and isinstance(mig_payload, dict):
        mig_status = str(mig_payload.get("status") or "migrated")
        return True, mig_status, mig_payload

    mig_err = (mig_cp.stderr or mig_cp.stdout or "migration failed").strip()
    return False, f"Legacy Keychain envelope migration failed for '{service}': {mig_err}", mig_payload
