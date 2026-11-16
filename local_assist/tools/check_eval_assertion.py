from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, TypedDict

from ..errors import LocalAssistError, ModelOutputMalformed
from ..logging import caller_context, log_call


JOB = "check_eval_assertion"
REQUESTED_MODEL = "deterministic-node-sandbox"
ALLOWED_ASSERTION_TYPES = {"javascript", "regex", "icontains", "is-json"}
MAX_ASSERTION_VALUE_BYTES = 8_192
MAX_CANDIDATES_PER_SIDE = 20
MAX_CANDIDATE_BYTES = 16_384
MAX_STDIN_PAYLOAD_BYTES = 262_144
MAX_STREAM_BYTES = 65_536
WALL_CLOCK_TIMEOUT_SECONDS = 2.0


class CheckEvalAssertionResult(TypedDict):
    passed: bool
    assertion_type: str
    passing_checked: int
    failing_checked: int
    false_rejects: list[dict[str, Any]]
    false_accepts: list[dict[str, Any]]
    runtime_errors: list[dict[str, Any]]


_RUNNER_JS = r"""
"use strict";
const vm = require("node:vm");
const MAX_OUT_BYTES = 65536;

function compileJsAssertion(expr) {
  try {
    return new vm.Script("(\n" + expr + "\n)", { filename: "assertion.js" });
  } catch (err1) {
    if (!(err1 instanceof SyntaxError)) {
      throw err1;
    }
    if (/\breturn\b/.test(expr)) {
      return new vm.Script("(() => {\n" + expr + "\n})()", { filename: "assertion.js" });
    }
    return new vm.Script(expr, { filename: "assertion.js" });
  }
}

function evalSingle(type, value, compiledScript, compiledRegex, candidate) {
  if (type === "icontains") {
    return String(candidate).toLowerCase().includes(String(value).toLowerCase());
  }
  if (type === "is-json") {
    try {
      JSON.parse(String(candidate));
      return true;
    } catch (_e) {
      return false;
    }
  }
  if (type === "regex") {
    const ctx = Object.create(null);
    ctx.re = compiledRegex;
    ctx.out = String(candidate);
    vm.createContext(ctx, { codeGeneration: { strings: false, wasm: false } });
    return Boolean(
      vm.runInContext("re.test(out)", ctx, {
        timeout: 200,
        microtaskMode: "afterEvaluate",
      })
    );
  }
  if (type === "javascript") {
    const ctx = Object.create(null);
    ctx.output = String(candidate);
    ctx.context = Object.freeze(Object.create(null));
    vm.createContext(ctx, { codeGeneration: { strings: false, wasm: false } });
    const raw = compiledScript.runInContext(ctx, {
      timeout: 200,
      microtaskMode: "afterEvaluate",
    });
    if (raw !== null && (typeof raw === "object" || typeof raw === "function") && typeof raw.then === "function") {
      throw new Error("Async/Promise assertions are not supported; return a synchronous boolean.");
    }
    if (raw !== null && typeof raw === "object" && typeof raw.pass === "boolean") {
      return raw.pass;
    }
    return Boolean(raw);
  }
  throw new Error("Unsupported assertion type: " + String(type));
}

const chunks = [];
let totalIn = 0;
process.stdin.on("data", (chunk) => {
  totalIn += chunk.length;
  if (totalIn > 262144) {
    process.exit(2);
  }
  chunks.push(chunk);
});

process.stdin.on("end", () => {
  let req;
  try {
    req = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch (e) {
    const msg = JSON.stringify({ syntax_error: "Invalid runner input JSON: " + String(e && e.message || e) });
    process.stdout.write(msg, () => process.exit(0));
    return;
  }

  const mode = req.mode || "eval";
  const type = String((req.assertion && req.assertion.type) || "");
  const value = String((req.assertion && req.assertion.value) || "");

  let compiledScript = null;
  let compiledRegex = null;
  try {
    if (type === "javascript") {
      compiledScript = compileJsAssertion(value);
    } else if (type === "regex") {
      compiledRegex = new RegExp(value);
    }
  } catch (compileErr) {
    const outObj = {
      syntax_ok: false,
      syntax_error: String((compileErr && compileErr.message) || compileErr),
      false_rejects: [],
      false_accepts: [],
      runtime_errors: [
        {
          group: "compile",
          index: -1,
          error: String((compileErr && compileErr.message) || compileErr),
        },
      ],
    };
    const outStr = JSON.stringify(outObj);
    process.stdout.write(outStr.slice(0, MAX_OUT_BYTES), () => process.exit(0));
    return;
  }

  if (mode === "syntax") {
    const outStr = JSON.stringify({ syntax_ok: true, syntax_error: null });
    process.stdout.write(outStr, () => process.exit(0));
    return;
  }

  const falseRejects = [];
  const falseAccepts = [];
  const runtimeErrors = [];

  const passing = Array.isArray(req.passing_outputs) ? req.passing_outputs : [];
  const failing = Array.isArray(req.failing_outputs) ? req.failing_outputs : [];

  for (let i = 0; i < passing.length; i++) {
    const sample = String(passing[i]);
    try {
      const ok = evalSingle(type, value, compiledScript, compiledRegex, sample);
      if (!ok) {
        falseRejects.push({ index: i, preview: sample.slice(0, 160) });
      }
    } catch (err) {
      runtimeErrors.push({
        group: "passing_outputs",
        index: i,
        error: String((err && err.message) || err).slice(0, 300),
      });
    }
  }

  for (let j = 0; j < failing.length; j++) {
    const sample = String(failing[j]);
    try {
      const ok = evalSingle(type, value, compiledScript, compiledRegex, sample);
      if (ok) {
        falseAccepts.push({ index: j, preview: sample.slice(0, 160) });
      }
    } catch (err) {
      runtimeErrors.push({
        group: "failing_outputs",
        index: j,
        error: String((err && err.message) || err).slice(0, 300),
      });
    }
  }

  const resultObj = {
    syntax_ok: true,
    false_rejects: falseRejects,
    false_accepts: falseAccepts,
    runtime_errors: runtimeErrors,
  };
  let serialized = JSON.stringify(resultObj);
  if (Buffer.byteLength(serialized, "utf8") > MAX_OUT_BYTES) {
    serialized = JSON.stringify({
      syntax_ok: true,
      false_rejects: falseRejects.slice(0, 5),
      false_accepts: falseAccepts.slice(0, 5),
      runtime_errors: [
        ...runtimeErrors.slice(0, 5),
        { group: "executor", index: -1, error: "Assertion report truncated to 65536-byte cap." },
      ],
    });
  }
  process.stdout.write(serialized, () => process.exit(0));
});
"""


def _seatbelt_escape(raw: str) -> str:
    return raw.replace("\\", "\\\\").replace('"', '\\"')


def _build_assertion_seatbelt_profile(node_real: str) -> str:
    escaped_node = _seatbelt_escape(node_real)
    denied_roots = (
        "/Users",
        "/System/Volumes/Data/Users",
        "/Volumes",
        "/private/tmp",
        "/tmp",
        "/private/var/folders",
        "/var/folders",
        "/private/etc/ssh",
    )
    reallow_clauses: list[str] = []
    node_path = Path(node_real)
    if any(node_real.startswith(root + "/") for root in denied_roots):
        for rd_op in ("file-read*", "file-read-data"):
            reallow_clauses.append(f'(allow {rd_op} (literal "{escaped_node}"))')
            reallow_clauses.append(
                f'(allow {rd_op} (literal "{_seatbelt_escape(str(node_path.parent))}"))'
            )
            if node_path.parent.name == "bin":
                parent_root = node_path.parent.parent
                reallow_clauses.append(
                    f'(allow {rd_op} (literal "{_seatbelt_escape(str(parent_root))}"))'
                )
                sibling_lib = parent_root / "lib"
                if sibling_lib.is_dir():
                    reallow_clauses.append(
                        f'(allow {rd_op} (subpath "{_seatbelt_escape(str(sibling_lib))}"))'
                    )

    reallow_node_clause = ("\n" + "\n".join(reallow_clauses)) if reallow_clauses else ""
    deny_subpaths = "\n  ".join(f'(subpath "{_seatbelt_escape(r)}")' for r in denied_roots)
    return (
        "(version 1)\n"
        "(allow default)\n"
        "(deny network*)\n"
        "(deny file-write*)\n"
        '(allow file-write* (literal "/dev/null"))\n'
        "(deny process-fork)\n"
        "(deny process-exec)\n"
        f'(allow process-exec (literal "{escaped_node}"))\n'
        f"(deny file-read*\n  {deny_subpaths})\n"
        f"(deny file-read-data\n  {deny_subpaths})"
        f"{reallow_node_clause}\n"
    )


def _kernel_fd_matches_exact_path(fd: int, expected_path: str) -> bool:
    if sys.platform != "darwin":
        return False
    import fcntl

    f_getpath = getattr(fcntl, "F_GETPATH", 50)
    try:
        raw_buf = fcntl.fcntl(fd, f_getpath, b"\x00" * 1024)
        nul_idx = raw_buf.find(b"\x00")
        actual = (raw_buf[:nul_idx] if nul_idx >= 0 else raw_buf).decode("utf-8")
        return actual == expected_path
    except OSError:
        return False


def _is_trusted_immutable_assertion_node(node_bin: Path) -> bool:
    if not node_bin.is_absolute() or node_bin.name != "local-assist-node":
        return False
    if node_bin.parent.name != "bin":
        return False
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd: int | None = None
    try:
        uid = os.geteuid()
        fd = os.open(str(node_bin), flags)
        if not _kernel_fd_matches_exact_path(fd, str(node_bin)):
            return False
        node_st = os.fstat(fd)
        bin_st = os.lstat(node_bin.parent)
        inv_dir = node_bin.parent.parent
        inv_st = os.lstat(inv_dir)
        sibling_py = node_bin.parent / "local-assist-python"
        py_st = os.lstat(sibling_py)
        cur_py_st = os.stat(sys.executable)
    except OSError:
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    if not stat.S_ISREG(node_st.st_mode) or node_st.st_uid != uid:
        return False
    # Require immutable executable (owner/group/other write bits all 0, e.g. 0500)
    if (node_st.st_mode & 0o222) != 0:
        return False
    if bin_st.st_uid != uid or (bin_st.st_mode & 0o022) != 0:
        return False
    if inv_st.st_uid != uid or (inv_st.st_mode & 0o022) != 0:
        return False
    if not stat.S_ISREG(py_st.st_mode) or (py_st.st_mode & 0o222) != 0:
        return False
    if (py_st.st_dev, py_st.st_ino) != (cur_py_st.st_dev, cur_py_st.st_ino):
        return False
    return True


def _current_process_has_inherited_seatbelt(inv_dir: Path) -> bool:
    if sys.platform != "darwin":
        return False
    if os.environ.get("LOCAL_ASSIST_WORKER_SANDBOX") != "1":
        return False
    try:
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        libc.sandbox_check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        libc.sandbox_check.restype = ctypes.c_int
        if libc.sandbox_check(os.getpid(), None, 0) != 1:
            return False
    except OSError:
        return False

    # Confirm concrete kernel network-outbound restriction on a reserved port (9181)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        err = sock.connect_ex(("127.0.0.1", 9181))
    except OSError as exc:
        err = exc.errno or 0
    finally:
        sock.close()
    if err != errno.EPERM:
        return False

    # Confirm concrete kernel file-read denial on sibling opencode.json inside inv_dir
    oc_cfg = inv_dir / "opencode.json"
    try:
        fd = os.open(str(oc_cfg), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        os.close(fd)
        return False
    except PermissionError:
        return True
    except OSError as exc:
        return exc.errno == errno.EPERM


def _resolve_sandboxed_node_command() -> list[str]:
    dedicated_bin = os.environ.get("LOCAL_ASSIST_ASSERTION_NODE_BIN", "").strip()
    if dedicated_bin:
        p = Path(dedicated_bin)
        if p.is_symlink() or not p.is_file():
            raise LocalAssistError(
                "internal_error",
                "Configured LOCAL_ASSIST_ASSERTION_NODE_BIN is missing or is a symlink.",
                details={"bin": dedicated_bin},
            )
        if _is_trusted_immutable_assertion_node(p) and _current_process_has_inherited_seatbelt(
            p.parent.parent
        ):
            return [str(p), "--permission", "--max-old-space-size=64", "-e", _RUNNER_JS]
        node_real = str(p.resolve())
    else:
        node_found = shutil.which("node")
        if not node_found:
            for fallback in ("/opt/homebrew/bin/node", "/usr/local/bin/node"):
                if Path(fallback).is_file():
                    node_found = fallback
                    break
        if not node_found:
            raise LocalAssistError(
                "internal_error",
                "Node.js runtime not found for check_eval_assertion sandbox.",
            )
        node_real = str(Path(node_found).resolve())

    if sys.platform == "darwin":
        sb_bin = Path("/usr/bin/sandbox-exec")
        if not sb_bin.is_file():
            raise LocalAssistError(
                "internal_error",
                "macOS /usr/bin/sandbox-exec is required to isolate check_eval_assertion.",
            )
        profile = _build_assertion_seatbelt_profile(node_real)
        return [
            str(sb_bin),
            "-p",
            profile,
            node_real,
            "--permission",
            "--max-old-space-size=64",
            "-e",
            _RUNNER_JS,
        ]

    return [node_real, "--permission", "--max-old-space-size=64", "-e", _RUNNER_JS]


def _kill_process_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        pass


def _run_sandboxed_executor(
    payload_obj: dict[str, Any],
    *,
    timeout_seconds: float = WALL_CLOCK_TIMEOUT_SECONDS,
) -> tuple[int, str, str, bool, bool]:
    payload_bytes = json.dumps(payload_obj, ensure_ascii=False).encode("utf-8")
    if len(payload_bytes) > MAX_STDIN_PAYLOAD_BYTES:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "Total assertion evaluation input exceeds maximum payload size.",
            details={"max_bytes": MAX_STDIN_PAYLOAD_BYTES, "observed": len(payload_bytes)},
        )

    cmd = _resolve_sandboxed_node_command()
    safe_cwd = "/var/empty" if Path("/var/empty").is_dir() else "/"

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=safe_cwd,
        env={},
        start_new_session=True,
    )
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None

    try:
        try:
            proc.stdin.write(payload_bytes)
        except BrokenPipeError:
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

        out_fd = proc.stdout.fileno()
        err_fd = proc.stderr.fileno()
        os.set_blocking(out_fd, False)
        os.set_blocking(err_fd, False)

        out_chunks: list[bytes] = []
        err_chunks: list[bytes] = []
        out_total = 0
        err_total = 0
        open_fds = {out_fd, err_fd}
        timed_out = False
        overflowed = False
        deadline = time.monotonic() + timeout_seconds

        while open_fds:
            rem = deadline - time.monotonic()
            if rem <= 0:
                timed_out = True
                _kill_process_group(proc)
                break
            ready, _, _ = select.select(list(open_fds), [], [], min(0.05, rem))
            for fd in ready:
                try:
                    chunk = os.read(fd, 16384)
                except OSError as exc:
                    if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        continue
                    open_fds.discard(fd)
                    continue
                if not chunk:
                    open_fds.discard(fd)
                    continue
                if fd == out_fd:
                    out_total += len(chunk)
                    if out_total > MAX_STREAM_BYTES:
                        overflowed = True
                        _kill_process_group(proc)
                        open_fds.clear()
                        break
                    out_chunks.append(chunk)
                else:
                    if err_total < MAX_STREAM_BYTES:
                        keep = chunk[: MAX_STREAM_BYTES - err_total]
                        err_chunks.append(keep)
                        err_total += len(keep)

        if not timed_out and not overflowed:
            rem_wait = max(0.0, deadline - time.monotonic())
            try:
                proc.wait(timeout=rem_wait)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_process_group(proc)
    finally:
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except OSError:
                pass
        if proc.poll() is None:
            _kill_process_group(proc)

    rc = proc.returncode if proc.returncode is not None else -9
    stdout_str = b"".join(out_chunks).decode("utf-8", errors="replace")
    stderr_str = b"".join(err_chunks).decode("utf-8", errors="replace")
    return rc, stdout_str, stderr_str, timed_out, overflowed


def validate_assertion_syntax(assertion_type: str, assertion_value: str) -> tuple[bool, str | None]:
    if assertion_type not in ALLOWED_ASSERTION_TYPES:
        return False, f"Unsupported assertion type: {assertion_type!r}"
    if assertion_type in ("icontains", "is-json"):
        return True, None
    if len(assertion_value.encode("utf-8")) > MAX_ASSERTION_VALUE_BYTES:
        return False, "Assertion exceeds maximum byte length."

    rc, stdout_str, stderr_str, timed_out, overflowed = _run_sandboxed_executor(
        {
            "mode": "syntax",
            "assertion": {"type": assertion_type, "value": assertion_value},
        },
        timeout_seconds=WALL_CLOCK_TIMEOUT_SECONDS,
    )
    if timed_out:
        return False, "Assertion syntax check timed out."
    if overflowed:
        return False, "Assertion syntax check exceeded output size cap."
    if rc != 0:
        return False, (stderr_str.strip() or f"Executor exited with code {rc}.")[:300]
    try:
        parsed = json.loads(stdout_str)
    except json.JSONDecodeError:
        return False, "Executor returned malformed JSON during syntax check."
    if parsed.get("syntax_ok") is True:
        return True, None
    return False, str(parsed.get("syntax_error") or "Invalid assertion syntax.")


def validate_inputs(
    assertion: Any,
    passing_outputs: Any,
    failing_outputs: Any,
) -> dict[str, Any]:
    if not isinstance(assertion, dict):
        raise ModelOutputMalformed(
            "invalid_arguments",
            "assertion must be an object with 'type' and 'value'.",
        )
    extra_keys = set(assertion.keys()) - {"type", "value"}
    if extra_keys:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "assertion contains unsupported keys.",
            details={"unexpected": sorted(extra_keys)},
        )
    a_type = assertion.get("type")
    if not isinstance(a_type, str) or a_type not in ALLOWED_ASSERTION_TYPES:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "assertion.type must be one of javascript, regex, icontains, is-json.",
            details={"allowed": sorted(ALLOWED_ASSERTION_TYPES), "observed": a_type},
        )
    raw_val = assertion.get("value", "" if a_type == "is-json" else None)
    if a_type == "is-json":
        if raw_val is None:
            a_val = ""
        elif isinstance(raw_val, str):
            a_val = raw_val
        else:
            raise ModelOutputMalformed("invalid_arguments", "assertion.value must be a string when provided.")
    else:
        if not isinstance(raw_val, str) or not raw_val.strip():
            raise ModelOutputMalformed(
                "invalid_arguments",
                f"assertion.value must be a non-empty string for type={a_type!r}.",
            )
        a_val = raw_val

    val_bytes = len(a_val.encode("utf-8"))
    if val_bytes > MAX_ASSERTION_VALUE_BYTES:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "assertion.value exceeds maximum byte length.",
            details={"max_bytes": MAX_ASSERTION_VALUE_BYTES, "observed": val_bytes},
        )

    def _check_candidates(items: Any, label: str) -> list[str]:
        if not isinstance(items, list) or not items:
            raise ModelOutputMalformed(
                "invalid_arguments",
                f"{label} must be a non-empty list of strings (1..{MAX_CANDIDATES_PER_SIDE}).",
            )
        if len(items) > MAX_CANDIDATES_PER_SIDE:
            raise ModelOutputMalformed(
                "invalid_arguments",
                f"{label} exceeds maximum candidate count ({MAX_CANDIDATES_PER_SIDE}).",
                details={"max_items": MAX_CANDIDATES_PER_SIDE, "observed": len(items)},
            )
        out: list[str] = []
        for idx, item in enumerate(items):
            if not isinstance(item, str):
                raise ModelOutputMalformed(
                    "invalid_arguments",
                    f"{label}[{idx}] must be a string.",
                )
            b_len = len(item.encode("utf-8"))
            if b_len > MAX_CANDIDATE_BYTES:
                raise ModelOutputMalformed(
                    "invalid_arguments",
                    f"{label}[{idx}] exceeds maximum candidate size ({MAX_CANDIDATE_BYTES} bytes).",
                    details={"max_bytes": MAX_CANDIDATE_BYTES, "observed": b_len},
                )
            out.append(item)
        return out

    clean_passing = _check_candidates(passing_outputs, "passing_outputs")
    clean_failing = _check_candidates(failing_outputs, "failing_outputs")
    return {
        "assertion": {"type": a_type, "value": a_val},
        "passing_outputs": clean_passing,
        "failing_outputs": clean_failing,
    }


def run(
    assertion: Any,
    passing_outputs: Any,
    failing_outputs: Any,
) -> CheckEvalAssertionResult:
    a_type_hint = assertion.get("type") if isinstance(assertion, dict) else None
    n_pass_hint = len(passing_outputs) if isinstance(passing_outputs, list) else 0
    n_fail_hint = len(failing_outputs) if isinstance(failing_outputs, list) else 0

    with log_call(
        JOB,
        REQUESTED_MODEL,
        args={
            "assertion_type": a_type_hint,
            "n_passing": n_pass_hint,
            "n_failing": n_fail_hint,
        },
        redact_prompt=True,
    ) as call:
        try:
            t0 = time.perf_counter()
            validated = validate_inputs(assertion, passing_outputs, failing_outputs)
            a_type = validated["assertion"]["type"]
            call.args.update(
                {
                    "assertion_type": a_type,
                    "n_passing": len(validated["passing_outputs"]),
                    "n_failing": len(validated["failing_outputs"]),
                }
            )
            call.readiness_ok = True
            call.ready_ms = 0

            rc, stdout_str, stderr_str, timed_out, overflowed = _run_sandboxed_executor(
                {
                    "mode": "eval",
                    "assertion": validated["assertion"],
                    "passing_outputs": validated["passing_outputs"],
                    "failing_outputs": validated["failing_outputs"],
                },
                timeout_seconds=WALL_CLOCK_TIMEOUT_SECONDS,
            )

            false_rejects: list[dict[str, Any]] = []
            false_accepts: list[dict[str, Any]] = []
            runtime_errors: list[dict[str, Any]] = []

            if timed_out:
                runtime_errors.append(
                    {
                        "group": "executor",
                        "index": -1,
                        "error": f"Assertion execution exceeded {WALL_CLOCK_TIMEOUT_SECONDS}s wall-clock limit and was terminated.",
                    }
                )
            elif overflowed:
                runtime_errors.append(
                    {
                        "group": "executor",
                        "index": -1,
                        "error": f"Assertion execution exceeded {MAX_STREAM_BYTES}-byte output cap and was terminated.",
                    }
                )
            elif rc != 0:
                err_preview = " ".join(stderr_str.strip().split())[:300]
                runtime_errors.append(
                    {
                        "group": "executor",
                        "index": -1,
                        "error": err_preview or f"Sandboxed Node executor exited with code {rc}.",
                    }
                )
            else:
                try:
                    parsed = json.loads(stdout_str)
                except json.JSONDecodeError:
                    runtime_errors.append(
                        {
                            "group": "executor",
                            "index": -1,
                            "error": "Sandboxed Node executor returned invalid JSON.",
                        }
                    )
                else:
                    if isinstance(parsed.get("false_rejects"), list):
                        false_rejects = parsed["false_rejects"]
                    if isinstance(parsed.get("false_accepts"), list):
                        false_accepts = parsed["false_accepts"]
                    if isinstance(parsed.get("runtime_errors"), list):
                        runtime_errors = parsed["runtime_errors"]

            passed = (
                len(false_rejects) == 0
                and len(false_accepts) == 0
                and len(runtime_errors) == 0
            )
            result: CheckEvalAssertionResult = {
                "passed": passed,
                "assertion_type": a_type,
                "passing_checked": len(validated["passing_outputs"]),
                "failing_checked": len(validated["failing_outputs"]),
                "false_rejects": false_rejects,
                "false_accepts": false_accepts,
                "runtime_errors": runtime_errors,
            }
            exec_ms = int(round((time.perf_counter() - t0) * 1000))
            observed = {
                "passed": passed,
                "assertion_type": a_type,
                "n_false_rejects": len(false_rejects),
                "n_false_accepts": len(false_accepts),
                "n_runtime_errors": len(runtime_errors),
            }
            call.record_result(
                result,
                observed=observed,
                served_model=REQUESTED_MODEL,
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                latency_ms=exec_ms,
                finish_reason="stop",
            )
            return result
        except LocalAssistError as exc:
            call.record_error(exc.to_payload())
            raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate a candidate promptfoo assertion against passing and failing sample outputs inside an OS sandbox."
    )
    parser.add_argument(
        "--assertion-json",
        required=True,
        help='JSON assertion object, e.g. \'{"type": "javascript", "value": "..."}\'.',
    )
    parser.add_argument(
        "--pass-output",
        dest="passing_outputs",
        action="append",
        required=True,
        help="Sample output that MUST pass (may be repeated).",
    )
    parser.add_argument(
        "--fail-output",
        dest="failing_outputs",
        action="append",
        required=True,
        help="Sample output that MUST fail (may be repeated).",
    )
    args = parser.parse_args(argv)
    try:
        try:
            assertion_obj = json.loads(args.assertion_json)
        except json.JSONDecodeError as exc:
            raise ModelOutputMalformed("invalid_arguments", f"Invalid --assertion-json: {exc}") from exc
        with caller_context(transport="cli", client_name=f"local_assist.tools.{JOB}"):
            res = run(
                assertion=assertion_obj,
                passing_outputs=args.passing_outputs,
                failing_outputs=args.failing_outputs,
            )
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    except LocalAssistError as exc:
        print(json.dumps({"error": exc.to_payload()}, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
