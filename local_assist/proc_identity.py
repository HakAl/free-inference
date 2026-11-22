"""Darwin proc_pidinfo start-time identity, 3-way Seatbelt discriminator, and r9 Section 6.4 reap (P1)."""
from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import struct
import sys
import time
from typing import Any


PROC_ALL_PIDS = 1
PROC_PIDTBSDINFO = 3
PROC_PIDTBSDINFO_SIZE = 136

SRUN = 2
SSTOP = 4
SZOMB = 5

SANDBOX_FILTER_NONE = 0
SANDBOX_FILTER_GLOBAL_NAME = 2
SANDBOX_CHECK_NO_REPORT = 0x40000000

WORKER_TAG_RE = re.compile(r"^[0-9a-f]{32}$")
MANIFEST_SCHEMA_VERSION = 1


class ProcBsdInfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


def _load_darwin_handles() -> tuple[Any, Any, Any] | tuple[None, None, None]:
    if sys.platform != "darwin":
        return None, None, None
    if ctypes.sizeof(ProcBsdInfo) != PROC_PIDTBSDINFO_SIZE:
        return None, None, None
    arch = platform.machine().lower()
    if arch not in ("arm64", "aarch64", "x86_64"):
        return None, None, None
    try:
        lib_proc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        lib_sb_none = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        lib_sb_var = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)

        lib_proc.proc_listpids.restype = ctypes.c_int
        lib_proc.proc_listpids.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        lib_proc.proc_pidinfo.restype = ctypes.c_int
        lib_proc.proc_pidinfo.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        lib_proc.sysctl.restype = ctypes.c_int
        lib_proc.sysctl.argtypes = [
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]

        lib_sb_none.sandbox_check.restype = ctypes.c_int
        lib_sb_none.sandbox_check.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]

        lib_sb_var.sandbox_check.restype = ctypes.c_int
        if arch in ("arm64", "aarch64"):
            # Apple darwinpcs ARM64 variadic ABI: fixed x0..x7 occupy slots 1..8, first variadic arg at [sp, #0] (slot 9).
            lib_sb_var.sandbox_check.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint32,
                ctypes.c_uint64,
                ctypes.c_uint64,
                ctypes.c_uint64,
                ctypes.c_uint64,
                ctypes.c_uint64,
                ctypes.c_char_p,
            ]
        else:
            lib_sb_var.sandbox_check.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint32,
                ctypes.c_char_p,
            ]
        return lib_proc, lib_sb_none, lib_sb_var
    except Exception:
        return None, None, None


_DARWIN_LIB, _DARWIN_SB_NONE, _DARWIN_SB_VAR = _load_darwin_handles()
_IS_ARM64 = platform.machine().lower() in ("arm64", "aarch64")


def list_all_pids() -> tuple[list[int], bool]:
    if _DARWIN_LIB is None:
        return [], False
    try:
        ctypes.set_errno(0)
        est_bytes = _DARWIN_LIB.proc_listpids(PROC_ALL_PIDS, 0, None, 0)
        if est_bytes <= 0:
            return [], False
        cap_count = max(1024, (est_bytes // ctypes.sizeof(ctypes.c_int)) * 2 + 256)
        arr_type = ctypes.c_int * cap_count
        buf = arr_type()
        ctypes.set_errno(0)
        used_bytes = _DARWIN_LIB.proc_listpids(
            PROC_ALL_PIDS,
            0,
            ctypes.byref(buf),
            ctypes.sizeof(buf),
        )
        if used_bytes < 0:
            return [], False
        n = min(cap_count, used_bytes // ctypes.sizeof(ctypes.c_int))
        pids = sorted({int(buf[i]) for i in range(n) if int(buf[i]) > 1})
        return pids, True
    except Exception:
        return [], False


def _raw_proc_pidinfo(pid: int) -> tuple[int, int, ProcBsdInfo]:
    info = ProcBsdInfo()
    if _DARWIN_LIB is None:
        return -1, errno.ENOSYS, info
    ctypes.set_errno(0)
    nb = int(
        _DARWIN_LIB.proc_pidinfo(
            int(pid),
            PROC_PIDTBSDINFO,
            0,
            ctypes.byref(info),
            PROC_PIDTBSDINFO_SIZE,
        )
    )
    err = int(ctypes.get_errno())
    return nb, err, info


def _read_sysctl_kinfo_proc_64_unchecked(pid: int) -> tuple[str, dict[str, Any] | None]:
    """Read raw 648-byte Darwin kinfo_proc via sysctl(KERN_PROC_PID) and validate structural fields."""
    if _DARWIN_LIB is None or ctypes.sizeof(ctypes.c_void_p) != 8:
        return "error", None
    mib = (ctypes.c_int * 4)(1, 14, 1, int(pid))  # CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1
    buf = ctypes.create_string_buffer(648)
    sz = ctypes.c_size_t(648)
    ctypes.set_errno(0)
    rc = int(_DARWIN_LIB.sysctl(mib, 4, buf, ctypes.byref(sz), None, 0))
    if rc != 0:
        err = int(ctypes.get_errno())
        return ("absent", None) if err == errno.ESRCH else ("error", None)
    if sz.value == 0:
        return "absent", None
    if sz.value != 648:
        return "error", None
    raw = buf.raw
    tv_sec, tv_usec = struct.unpack_from("<qi", raw, 0)
    p_stat = int(raw[36])
    p_pid = int(struct.unpack_from("<i", raw, 40)[0])
    cr_uid = int(struct.unpack_from("<I", raw, 420)[0])
    e_pgid = int(struct.unpack_from("<i", raw, 564)[0])
    if (
        p_pid != int(pid)
        or p_stat not in (1, 2, 3, 4, 5)
        or tv_sec <= 0
        or not (0 <= tv_usec < 1_000_000)
        or e_pgid < 0
    ):
        return "error", None
    payload = {
        "pid": p_pid,
        "ppid": 0,
        "uid": cr_uid,
        "pgid": e_pgid,
        "status": p_stat,
        "start_tvsec": int(tv_sec),
        "start_tvusec": int(tv_usec),
    }
    if p_stat == SZOMB:
        return "zombie", payload
    return "alive", payload


def _calibrate_darwin_sysctl_kinfo_proc() -> bool:
    """Verify at startup that kinfo_proc offsets agree with proc_pidinfo(os.getpid()) before enabling fallback."""
    if _DARWIN_LIB is None or ctypes.sizeof(ctypes.c_void_p) != 8:
        return False
    my_pid = os.getpid()
    raw = _raw_proc_pidinfo(my_pid)
    if len(raw) != 3:
        return False
    nb, _err, pbi = raw
    if nb != PROC_PIDTBSDINFO_SIZE:
        return False
    st_k, info_k = _read_sysctl_kinfo_proc_64_unchecked(my_pid)
    if st_k != "alive" or info_k is None:
        return False
    return (
        int(info_k["pid"]) == int(pbi.pbi_pid) == my_pid
        and int(info_k["uid"]) == int(pbi.pbi_uid)
        and int(info_k["pgid"]) == int(pbi.pbi_pgid)
        and int(info_k["start_tvsec"]) == int(pbi.pbi_start_tvsec)
        and int(info_k["start_tvusec"]) == int(pbi.pbi_start_tvusec)
    )


_SYSCTL_KINFO_CALIBRATED: bool = _calibrate_darwin_sysctl_kinfo_proc()


def _sysctl_kinfo_proc_64(pid: int) -> tuple[str, dict[str, Any] | None]:
    """Calibrated fallback to sysctl(KERN_PROC_PID) when proc_pidinfo returns ESRCH/EPERM."""
    if not _SYSCTL_KINFO_CALIBRATED:
        return "error", None
    return _read_sysctl_kinfo_proc_64_unchecked(pid)


def read_proc_bsdinfo(pid: int) -> tuple[str, dict[str, Any] | None]:
    """Return ('alive' | 'zombie' | 'absent' | 'error', info_dict_or_none)."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return "error", None
    if _DARWIN_LIB is None:
        return "error", None
    raw = _raw_proc_pidinfo(pid)
    if len(raw) == 2:
        # Support test mocks patching _raw_proc_pidinfo to (nb, err).
        nb, err = raw
        info = ProcBsdInfo()
    else:
        nb, err, info = raw
    if nb <= 0:
        if err in (0, errno.ESRCH):
            return _sysctl_kinfo_proc_64(pid)
        if err == errno.EPERM:
            st_k, info_k = _sysctl_kinfo_proc_64(pid)
            if st_k == "absent":
                return "absent", None
            if info_k is not None and int(info_k["uid"]) != os.geteuid():
                return st_k, info_k
            return "error", None
        return "error", None
    if nb != PROC_PIDTBSDINFO_SIZE:
        return "error", None
    status = int(info.pbi_status)
    payload = {
        "pid": int(info.pbi_pid),
        "ppid": int(info.pbi_ppid),
        "uid": int(info.pbi_uid),
        "pgid": int(info.pbi_pgid),
        "status": status,
        "start_tvsec": int(info.pbi_start_tvsec),
        "start_tvusec": int(info.pbi_start_tvusec),
    }
    if status == SZOMB:
        return "zombie", payload
    return "alive", payload


def _sandbox_check_none(pid: int) -> tuple[int, int]:
    if _DARWIN_LIB is None or _DARWIN_SB_NONE is None:
        return -1, errno.ENOSYS
    ctypes.set_errno(0)
    rc = int(_DARWIN_SB_NONE.sandbox_check(int(pid), None, SANDBOX_FILTER_NONE | SANDBOX_CHECK_NO_REPORT))
    return rc, int(ctypes.get_errno())


def _sandbox_check_mach_lookup(pid: int, global_name: bytes) -> tuple[int, int]:
    if _DARWIN_LIB is None or _DARWIN_SB_VAR is None:
        return -1, errno.ENOSYS
    flags = SANDBOX_FILTER_GLOBAL_NAME | SANDBOX_CHECK_NO_REPORT
    ctypes.set_errno(0)
    if _IS_ARM64:
        rc = int(
            _DARWIN_SB_VAR.sandbox_check(
                int(pid),
                b"mach-lookup",
                flags,
                0,
                0,
                0,
                0,
                0,
                global_name,
            )
        )
    else:
        rc = int(_DARWIN_SB_VAR.sandbox_check(int(pid), b"mach-lookup", flags, global_name))
    return rc, int(ctypes.get_errno())


def pid_matches_worker_tag(pid: int, worker_tag: str) -> tuple[bool, bool]:
    """Evaluate 3-way Section 6.4 Seatbelt discriminator. Returns (matched, query_ok).

    Note: on XNU, sandbox_check(zomb_pid, NULL, SANDBOX_FILTER_NONE) returns 1 even for an
    unsandboxed zombie child; the subsequent worker-allow / worker-deny queries cleanly
    discriminate it as (False, True) without false positives.
    """
    if not isinstance(worker_tag, str) or not WORKER_TAG_RE.fullmatch(worker_tag):
        return False, False
    if _DARWIN_LIB is None:
        return False, False

    r0, _ = _sandbox_check_none(pid)
    if r0 < 0:
        st, _ = read_proc_bsdinfo(pid)
        return (False, True) if st == "absent" else (False, False)
    if r0 != 1:
        return False, True

    allow_name = f"org.free-inference.worker-allow.{worker_tag}".encode("ascii")
    r_allow, _ = _sandbox_check_mach_lookup(pid, allow_name)
    if r_allow < 0:
        st, _ = read_proc_bsdinfo(pid)
        return (False, True) if st == "absent" else (False, False)
    if r_allow != 0:
        return False, True

    deny_name = f"org.free-inference.worker-deny.{worker_tag}".encode("ascii")
    r_deny, _ = _sandbox_check_mach_lookup(pid, deny_name)
    if r_deny < 0:
        st, _ = read_proc_bsdinfo(pid)
        return (False, True) if st == "absent" else (False, False)
    if r_deny != 1:
        return False, True

    return True, True


def _send_signal(pid: int, sig: int) -> None:
    os.kill(pid, sig)


def _after_stopped_reverify_hook(_pid: int) -> None:
    """Test seam for injecting third-party actions between post-SSTOP re-verification and SIGKILL."""
    return None


def _is_exact_nonneg_int(val: Any) -> bool:
    return type(val) is int and val >= 0


def _is_exact_pos_int(val: Any) -> bool:
    return type(val) is int and val > 0


def load_and_validate_worker_manifest(manifest_path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not manifest_path.is_absolute():
        return None, f"Manifest path must be absolute: {manifest_path}"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(manifest_path), flags)
    except OSError as exc:
        return None, f"Cannot open worker manifest '{manifest_path}': {exc}"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, f"Worker manifest '{manifest_path}' is not a regular file."
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            return None, f"Worker manifest '{manifest_path}' is not owned by uid {os.geteuid()}."
        if (stat.S_IMODE(st.st_mode) & 0o077) != 0:
            return None, f"Worker manifest '{manifest_path}' has group/other permissions ({stat.S_IMODE(st.st_mode):04o})."
        if st.st_size <= 0 or st.st_size > 262_144:
            return None, f"Worker manifest '{manifest_path}' has invalid size ({st.st_size})."
        raw = os.read(fd, 262_145)
        if len(raw) > 262_144:
            return None, f"Worker manifest '{manifest_path}' exceeds maximum size."
    except OSError as exc:
        return None, f"Failed reading worker manifest '{manifest_path}': {exc}"
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"Invalid JSON in worker manifest '{manifest_path}': {exc}"
    if not isinstance(obj, dict):
        return None, "Worker manifest root must be a JSON object."

    if type(obj.get("schema_version")) is not int or obj["schema_version"] != MANIFEST_SCHEMA_VERSION:
        return None, f"Unsupported manifest schema_version: {obj.get('schema_version')!r}"
    run_token = obj.get("run_token")
    if not isinstance(run_token, str) or not run_token.strip():
        return None, "Worker manifest missing non-empty run_token."
    l_pid = obj.get("launcher_pid")
    l_pgid = obj.get("launcher_pgid")
    if not _is_exact_pos_int(l_pid) or not _is_exact_pos_int(l_pgid) or l_pid != l_pgid:
        return None, "Worker manifest requires exact positive integer launcher_pid == launcher_pgid."
    if not _is_exact_nonneg_int(obj.get("launcher_start_tvsec")) or not _is_exact_nonneg_int(
        obj.get("launcher_start_tvusec")
    ):
        return None, "Worker manifest requires exact integer launcher_start_tvsec and launcher_start_tvusec."
    worker_tag = obj.get("worker_tag")
    if not isinstance(worker_tag, str) or not WORKER_TAG_RE.fullmatch(worker_tag):
        return None, "Worker manifest requires 32-hex worker_tag."

    children = obj.get("children")
    if not isinstance(children, list):
        return None, "Worker manifest 'children' must be a list."
    for idx, child in enumerate(children):
        if not isinstance(child, dict):
            return None, f"Worker manifest children[{idx}] must be an object."
        if not _is_exact_pos_int(child.get("pid")):
            return None, f"Worker manifest children[{idx}].pid must be a positive integer."
        if not _is_exact_nonneg_int(child.get("start_tvsec")) or not _is_exact_nonneg_int(
            child.get("start_tvusec")
        ):
            return (
                None,
                f"Worker manifest children[{idx}] requires exact integer start_tvsec and start_tvusec.",
            )
    return obj, None


def _emit_changed_hands_diagnostic(pid: int, reason: str) -> str:
    print(f"[reap-worker] changed_hands pid={pid} reason={reason}", file=sys.stderr)
    return "changed_hands"


def _handle_changed_hands(
    pid: int,
    initial_info: dict[str, Any],
    stop_deadline: float,
) -> str:
    """Implement r9 Section 6.4 changed-hands disposition with guaranteed per-event stderr logging."""
    rep_start = (int(initial_info["start_tvsec"]), int(initial_info["start_tvusec"]))
    cur_st = "alive"
    cur_info: dict[str, Any] | None = initial_info

    while True:
        if cur_st == "error":
            return "error"
        if cur_st == "absent":
            return _emit_changed_hands_diagnostic(pid, "disappeared")
        if cur_st == "zombie":
            return _emit_changed_hands_diagnostic(pid, "zombie")
        assert cur_info is not None
        if (int(cur_info["start_tvsec"]), int(cur_info["start_tvusec"])) != rep_start:
            return _emit_changed_hands_diagnostic(pid, "changed_again")
        if int(cur_info["status"]) == SSTOP:
            st_re, info_re = read_proc_bsdinfo(pid)
            if st_re == "error":
                return "error"
            if (
                st_re == "alive"
                and info_re is not None
                and (int(info_re["start_tvsec"]), int(info_re["start_tvusec"])) == rep_start
            ):
                try:
                    _send_signal(pid, signal.SIGCONT)
                except ProcessLookupError:
                    pass
                except OSError:
                    return "error"
                return _emit_changed_hands_diagnostic(pid, "resumed_stopped_replacement")
            return _emit_changed_hands_diagnostic(pid, "reread_mismatch_or_gone")

        if time.monotonic() >= stop_deadline:
            return _emit_changed_hands_diagnostic(pid, "never_stopped")
        time.sleep(0.002)
        cur_st, cur_info = read_proc_bsdinfo(pid)


def _stop_verify_and_kill_pid(
    pid: int,
    expected_start: tuple[int, int],
    *,
    worker_tag: str | None,
    stop_timeout_sec: float = 0.25,
) -> str:
    """Return 'killed' | 'exited' | 'changed_hands' | 'error' per r9 Section 6.4."""
    try:
        _send_signal(pid, signal.SIGSTOP)
    except ProcessLookupError:
        return "exited"
    except OSError as exc:
        print(f"[reap-worker] SIGSTOP failed on pid={pid}: {exc}", file=sys.stderr)
        return "error"

    stop_deadline = time.monotonic() + max(0.01, float(stop_timeout_sec))
    while True:
        st, info = read_proc_bsdinfo(pid)
        if st == "error":
            return "error"
        if st == "absent":
            return "exited"
        if st == "zombie":
            if info is None or "start_tvsec" not in info or "start_tvusec" not in info:
                return "error"
            z_start = (int(info["start_tvsec"]), int(info["start_tvusec"]))
            if z_start != expected_start:
                return _emit_changed_hands_diagnostic(pid, "zombie")
            if worker_tag is not None:
                _, q_ok_z = pid_matches_worker_tag(pid, worker_tag)
                if not q_ok_z:
                    return "error"
            return "exited"
        assert info is not None
        actual_start = (int(info["start_tvsec"]), int(info["start_tvusec"]))
        if actual_start != expected_start:
            return _handle_changed_hands(pid, info, stop_deadline)

        if int(info["status"]) == SSTOP:
            st_v, info_v = read_proc_bsdinfo(pid)
            if st_v == "error":
                return "error"
            if st_v == "absent":
                return "exited"
            if st_v == "zombie":
                if info_v is None or "start_tvsec" not in info_v or "start_tvusec" not in info_v:
                    return "error"
                zv_start = (int(info_v["start_tvsec"]), int(info_v["start_tvusec"]))
                if zv_start != expected_start:
                    return _emit_changed_hands_diagnostic(pid, "zombie")
                if worker_tag is not None:
                    _, q_ok_zv = pid_matches_worker_tag(pid, worker_tag)
                    if not q_ok_zv:
                        return "error"
                return "exited"
            assert info_v is not None
            verify_start = (int(info_v["start_tvsec"]), int(info_v["start_tvusec"]))
            if verify_start != expected_start:
                return _handle_changed_hands(pid, info_v, stop_deadline)
            if int(info_v["status"]) != SSTOP:
                if time.monotonic() >= stop_deadline:
                    print(
                        f"[reap-worker] matched pid={pid} left SSTOP and exceeded stop deadline.",
                        file=sys.stderr,
                    )
                    return "error"
                time.sleep(0.002)
                continue

            if worker_tag is not None:
                matched_v, q_ok_v = pid_matches_worker_tag(pid, worker_tag)
                if not q_ok_v:
                    print(
                        f"[reap-worker] post-SSTOP worker_tag query failed on pid={pid} (matched={matched_v}, ok={q_ok_v}).",
                        file=sys.stderr,
                    )
                    return "error"
                if not matched_v:
                    st_after, info_after = read_proc_bsdinfo(pid)
                    if st_after == "error":
                        return "error"
                    if st_after == "absent":
                        return "exited"
                    if st_after == "zombie":
                        if info_after is None or "start_tvsec" not in info_after or "start_tvusec" not in info_after:
                            return "error"
                        za_start = (int(info_after["start_tvsec"]), int(info_after["start_tvusec"]))
                        if za_start != expected_start:
                            return _emit_changed_hands_diagnostic(pid, "zombie")
                        return "exited"
                    assert info_after is not None
                    after_start = (int(info_after["start_tvsec"]), int(info_after["start_tvusec"]))
                    if after_start != expected_start:
                        return _handle_changed_hands(pid, info_after, stop_deadline)
                    print(
                        f"[reap-worker] post-SSTOP worker_tag re-verification failed on pid={pid} (matched={matched_v}, ok={q_ok_v}).",
                        file=sys.stderr,
                    )
                    return "error"

            _after_stopped_reverify_hook(pid)
            try:
                _send_signal(pid, signal.SIGKILL)
            except ProcessLookupError:
                return "exited"
            except OSError as exc:
                print(f"[reap-worker] SIGKILL failed on pid={pid}: {exc}", file=sys.stderr)
                return "error"
            return "killed"

        if time.monotonic() >= stop_deadline:
            print(
                f"[reap-worker] matched pid={pid} was never observed in SSTOP within {stop_timeout_sec}s.",
                file=sys.stderr,
            )
            return "error"
        time.sleep(0.002)


def reap_worker_from_manifest(
    manifest_path: str | Path,
    *,
    reap_timeout_sec: float = 10.0,
    stop_timeout_sec: float = 0.25,
) -> int:
    """Execute Section 6.4 race-safe worker reap. Returns 0 when confirmed empty, 1 on any error/survivor/changed_hands."""
    mpath = Path(manifest_path)
    manifest, err = load_and_validate_worker_manifest(mpath)
    if err is not None or manifest is None:
        print(f"[reap-worker] {err or 'Invalid manifest.'}", file=sys.stderr)
        return 1

    self_pid = os.getpid()
    my_uid = os.geteuid()
    worker_tag: str = manifest["worker_tag"]
    recorded_targets: list[tuple[int, tuple[int, int]]] = []

    l_pid = int(manifest["launcher_pid"])
    if l_pid != self_pid:
        recorded_targets.append(
            (l_pid, (int(manifest["launcher_start_tvsec"]), int(manifest["launcher_start_tvusec"])))
        )
    for child in manifest["children"]:
        c_pid = int(child["pid"])
        if c_pid != self_pid:
            recorded_targets.append(
                (c_pid, (int(child["start_tvsec"]), int(child["start_tvusec"])))
            )

    deadline = time.monotonic() + max(0.05, float(reap_timeout_sec))
    changed_hands_any = False
    consecutive_empty = 0

    while time.monotonic() < deadline:
        found_any = False

        # 1. Check recorded launcher + direct children by exact microsecond start-time pair.
        for rec_pid, rec_start in recorded_targets:
            st_r, info_r = read_proc_bsdinfo(rec_pid)
            if st_r == "error":
                print(f"[reap-worker] proc_pidinfo failed on recorded pid={rec_pid}.", file=sys.stderr)
                return 1
            if st_r in ("absent", "zombie"):
                continue
            assert info_r is not None
            if int(info_r["uid"]) != my_uid:
                continue
            if (int(info_r["start_tvsec"]), int(info_r["start_tvusec"])) != rec_start:
                # Reused PID before stop: send nothing!
                continue
            outcome_r = _stop_verify_and_kill_pid(
                rec_pid,
                rec_start,
                worker_tag=None,
                stop_timeout_sec=stop_timeout_sec,
            )
            if outcome_r == "error":
                return 1
            if outcome_r == "changed_hands":
                changed_hands_any = True
            found_any = True

        # 2. Full same-UID kernel Seatbelt worker_tag sweep.
        pids, list_ok = list_all_pids()
        if not list_ok:
            print("[reap-worker] proc_listpids failed.", file=sys.stderr)
            return 1

        for pid in pids:
            if pid == self_pid or pid <= 1:
                continue
            st1, info1 = read_proc_bsdinfo(pid)
            if st1 == "error":
                print(f"[reap-worker] proc_pidinfo failed on pid={pid}.", file=sys.stderr)
                return 1
            if st1 == "absent":
                continue
            assert info1 is not None
            if int(info1["uid"]) != my_uid:
                continue
            if st1 == "zombie":
                _, q_ok_z = pid_matches_worker_tag(pid, worker_tag)
                if not q_ok_z:
                    print(f"[reap-worker] sandbox_check failed on zombie pid={pid}.", file=sys.stderr)
                    return 1
                continue

            start1 = (int(info1["start_tvsec"]), int(info1["start_tvusec"]))
            matched, q_ok = pid_matches_worker_tag(pid, worker_tag)
            if not q_ok:
                print(f"[reap-worker] sandbox_check failed on pid={pid}.", file=sys.stderr)
                return 1
            if not matched:
                # Non-matching process: sent nothing!
                continue

            st2, info2 = read_proc_bsdinfo(pid)
            if st2 == "error":
                print(f"[reap-worker] post-query proc_pidinfo failed on pid={pid}.", file=sys.stderr)
                return 1
            if st2 in ("absent", "zombie"):
                found_any = True
                continue
            assert info2 is not None
            start2 = (int(info2["start_tvsec"]), int(info2["start_tvusec"]))
            if start2 != start1:
                # Replaced before SIGSTOP: send nothing, force fresh enumeration.
                found_any = True
                continue

            outcome = _stop_verify_and_kill_pid(
                pid,
                start1,
                worker_tag=worker_tag,
                stop_timeout_sec=stop_timeout_sec,
            )
            if outcome == "error":
                return 1
            if outcome == "changed_hands":
                changed_hands_any = True
            found_any = True

        if not found_any:
            consecutive_empty += 1
            if consecutive_empty >= 2:
                if changed_hands_any:
                    print(
                        "[reap-worker] sweep completed with changed_hands event(s); withholding clean exit.",
                        file=sys.stderr,
                    )
                    return 1
                return 0
            time.sleep(0.015)
        else:
            consecutive_empty = 0
            time.sleep(0.02)

    print(
        f"[reap-worker] timed out after {reap_timeout_sec}s before two consecutive empty enumerations.",
        file=sys.stderr,
    )
    return 1
