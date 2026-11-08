from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from . import __version__
from .errors import LocalAssistError
from .tools.compress_context import run as compress_context
from .tools.delegate_task import run as delegate_task
from .tools.extract_fields import run as extract_fields
from .tools.propose_eval_prompts import run as propose_eval_prompts


SERVER_INFO = {"name": "local-assist-server", "version": __version__}
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_PROTOCOL_VERSIONS = (
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)

PROPOSE_EVAL_PROMPTS_SCHEMA = {
    "name": "propose_eval_prompts",
    "description": "Generate candidate promptfoo eval prompts with executable JavaScript assertions. Candidates must be externally validated across at least two models.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "category": {
                "type": "string",
                "enum": [
                    "format",
                    "reasoning",
                    "coding",
                    "long_context",
                    "instruction_following",
                    "structured_output",
                ],
                "description": "Signal category to target.",
            },
            "n": {"type": "integer", "minimum": 1, "maximum": 25, "default": 5},
        },
        "required": ["category"],
        "additionalProperties": False,
    },
}

EXTRACT_FIELDS_SCHEMA = {
    "name": "extract_fields",
    "description": "Extract structured fields from a block of text using the local model. Caller supplies a flat schema; scalar values (string/integer/number/boolean) are returned with matching JSON types or null when absent. string_list always returns an array (never null): empty array collapses 'text said no items' and 'text did not mention the list' together; add a paired boolean field if you need to distinguish those.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Source text to extract from."},
            "fields": {
                "type": "object",
                "description": "Mapping of field_name to its spec.",
                "additionalProperties": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": ["string", "integer", "number", "boolean", "string_list"],
                        },
                        "description": {"type": "string"},
                        "required": {"type": "boolean", "default": False},
                    },
                    "required": ["type", "description"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["text", "fields"],
        "additionalProperties": False,
    },
}

COMPRESS_CONTEXT_SCHEMA = {
    "name": "compress_context",
    "description": "Compress noisy context (a diff, test output, or log dump) into a structured summary that preserves action-critical facts. For kind=diff, changed_files entries are mechanically verified against diff headers in the input. Output is advisory; risks/commands/followups are model judgment, not extracted facts.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "enum": ["diff", "test_output", "logs"],
                "description": "What kind of input is being compressed.",
            },
            "text": {"type": "string", "description": "Source text to compress."},
            "focus": {
                "type": ["string", "null"],
                "description": "Optional short string describing what to emphasize.",
            },
            "max_items": {
                "type": "integer",
                "minimum": 1,
                "maximum": 50,
                "default": 10,
                "description": "Maximum length of every list field in the output.",
            },
        },
        "required": ["kind", "text"],
        "additionalProperties": False,
    },
}

DELEGATE_TASK_SCHEMA = {
    "name": "delegate_task",
    "description": "Delegate a bounded text/code generation, test-case drafting, text transformation, or focused Q&A subtask to the Rung 1 local model (qwen3-30b-a3b-2507-mlx-4bit on 127.0.0.1:8080/v1) at $0 marginal cost. Advisory only: self-reported assumptions and unverified_claims are model judgment (empty lists do not mean verified); ungrounded_identifiers is mechanically computed as a review cue. Note: any context read by a remote planner or any tool output returned to a remote planner enters that planner's data-control rung; only context_path read directly by the local tool stays off the planner's outbound prompt until the result is returned.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "enum": ["draft_code", "generate_test_cases", "transform_text", "focused_qa"],
                "description": "Bounded subtask kind.",
            },
            "instruction": {
                "type": "string",
                "maxLength": 8000,
                "description": "Bounded task instruction (1..8000 characters).",
            },
            "context": {
                "type": ["string", "null"],
                "maxLength": 32000,
                "description": "Optional inline reference context (<= 32000 characters; mutually exclusive with context_path).",
            },
            "context_path": {
                "type": ["string", "null"],
                "description": "Optional local regular-file path read directly by the tool (no '..' traversal; mutually exclusive with context).",
            },
            "constraints": {
                "type": ["array", "null"],
                "items": {"type": "string", "maxLength": 500},
                "maxItems": 20,
                "description": "Optional list of explicit rules the output must obey (<= 20 items).",
            },
            "max_tokens": {
                "type": "integer",
                "minimum": 256,
                "maximum": 2048,
                "default": 1536,
                "description": "Maximum output tokens for the local completion (256..2048).",
            },
        },
        "required": ["kind", "instruction"],
        "additionalProperties": False,
    },
}

TOOL_SCHEMAS = [
    PROPOSE_EVAL_PROMPTS_SCHEMA,
    EXTRACT_FIELDS_SCHEMA,
    COMPRESS_CONTEXT_SCHEMA,
    DELEGATE_TASK_SCHEMA,
]


def handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    msg_id = message.get("id")
    if (isinstance(method, str) and method.startswith("notifications/")) or msg_id is None:
        return None
    if method == "initialize":
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        requested_version = params.get("protocolVersion")
        negotiated_version = (
            requested_version
            if isinstance(requested_version, str) and requested_version in SUPPORTED_PROTOCOL_VERSIONS
            else DEFAULT_PROTOCOL_VERSION
        )
        return result(
            msg_id,
            {
                "protocolVersion": negotiated_version,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        )
    if method == "tools/list":
        return result(msg_id, {"tools": TOOL_SCHEMAS})
    if method == "tools/call":
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        name = params.get("name")
        args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        try:
            if name == "propose_eval_prompts":
                output = propose_eval_prompts(
                    category=str(args.get("category", "")),
                    n=int(args.get("n", 5)),
                )
            elif name == "extract_fields":
                output = extract_fields(
                    text=args.get("text"),
                    fields=args.get("fields"),
                )
            elif name == "compress_context":
                output = compress_context(
                    kind=args.get("kind"),
                    text=args.get("text"),
                    focus=args.get("focus"),
                    max_items=args.get("max_items", 10),
                )
            elif name == "delegate_task":
                output = delegate_task(
                    kind=args.get("kind"),
                    instruction=args.get("instruction"),
                    context=args.get("context"),
                    context_path=args.get("context_path"),
                    constraints=args.get("constraints"),
                    max_tokens=args.get("max_tokens", 1536),
                )
            else:
                return error(msg_id, -32601, f"Unknown tool: {name}")
            return result(
                msg_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(output, indent=2, ensure_ascii=False),
                        }
                    ],
                    "structuredContent": output,
                    "isError": False,
                },
            )
        except LocalAssistError as exc:
            payload = exc.to_payload()
            return result(
                msg_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(payload, indent=2, ensure_ascii=False),
                        }
                    ],
                    "structuredContent": payload,
                    "isError": True,
                },
            )
        except Exception as exc:
            payload = {"code": "internal_error", "message": str(exc), "details": {}}
            return result(
                msg_id,
                {
                    "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                    "structuredContent": payload,
                    "isError": True,
                },
            )
    if method == "ping":
        return result(msg_id, {})
    return error(msg_id, -32601, f"Unsupported method: {method}")


def result(msg_id: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": payload}


def error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


class JsonRpcProtocolError(ValueError):
    def __init__(self, code: int, message: str, framing: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.framing = framing


def read_message_with_framing(
    stream: Any = None,
    session_framing: str | None = None,
) -> tuple[dict[str, Any] | None, str]:
    in_stream = stream if stream is not None else sys.stdin.buffer
    effective_framing = session_framing or "content-length"

    first_line = b""
    while True:
        line = in_stream.readline()
        if line == b"":
            return None, effective_framing
        if line not in (b"\r\n", b"\n"):
            first_line = line
            break

    stripped = first_line.lstrip()
    if session_framing == "line" or (
        session_framing is None
        and (stripped.startswith((b"{", b"[")) or b":" not in first_line)
    ):
        try:
            payload = json.loads(first_line.decode("utf-8", errors="replace").strip())
        except json.JSONDecodeError as exc:
            raise JsonRpcProtocolError(-32700, f"Parse error: {exc}", "line") from exc
        if not isinstance(payload, dict):
            raise JsonRpcProtocolError(
                -32700, "Parse error: MCP JSON-RPC message must be a JSON object", "line"
            )
        return payload, "line"

    headers: dict[str, str] = {}
    key, _, value = first_line.decode("ascii", errors="replace").partition(":")
    headers[key.lower()] = value.strip()
    while True:
        line = in_stream.readline()
        if line == b"":
            return None, "content-length"
        if line in (b"\r\n", b"\n"):
            break
        key, _, value = line.decode("ascii", errors="replace").partition(":")
        headers[key.lower()] = value.strip()
    try:
        length = int(headers.get("content-length", "0"))
    except ValueError as exc:
        raise JsonRpcProtocolError(
            -32700, "Parse error: invalid Content-Length header", "content-length"
        ) from exc
    if length <= 0:
        raise JsonRpcProtocolError(
            -32700,
            "Parse error: missing or non-positive Content-Length header",
            "content-length",
        )
    body = in_stream.read(length)
    if not body or len(body) < length:
        return None, "content-length"
    try:
        payload = json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise JsonRpcProtocolError(
            -32700, f"Parse error: {exc}", "content-length"
        ) from exc
    if not isinstance(payload, dict):
        raise JsonRpcProtocolError(
            -32700,
            "Parse error: MCP JSON-RPC message must be a JSON object",
            "content-length",
        )
    return payload, "content-length"


def read_message(stream: Any = None) -> dict[str, Any] | None:
    msg, _ = read_message_with_framing(stream=stream, session_framing=None)
    return msg


def write_message(
    message: dict[str, Any],
    *,
    framing: str = "content-length",
    stream: Any = None,
) -> None:
    out_stream = stream if stream is not None else sys.stdout.buffer
    body = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if framing == "line":
        out_stream.write(body + b"\n")
    else:
        out_stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
        out_stream.write(body)
    out_stream.flush()


def serve_stdio(in_stream: Any = None, out_stream: Any = None) -> int:
    session_framing: str | None = None
    while True:
        try:
            incoming, detected_framing = read_message_with_framing(
                stream=in_stream,
                session_framing=session_framing,
            )
        except JsonRpcProtocolError as exc:
            if session_framing is None:
                session_framing = exc.framing
            write_message(
                error(None, exc.code, exc.message),
                framing=session_framing,
                stream=out_stream,
            )
            continue
        if incoming is None:
            return 0
        if session_framing is None:
            session_framing = detected_framing
        response = handle_request(incoming)
        if response is not None and incoming.get("id") is not None:
            write_message(response, framing=session_framing, stream=out_stream)


def self_test() -> int:
    print(json.dumps({"server": SERVER_INFO, "tools": [tool["name"] for tool in TOOL_SCHEMAS]}, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="local-assist MCP server")
    parser.add_argument("--self-test", action="store_true", help="Print server metadata without starting MCP stdio.")
    parser.add_argument(
        "--auto-serve",
        action="store_true",
        help="Opt in to auto-starting the cleared Rung 1 local MLX server on tool call if port 8080 is down.",
    )
    args = parser.parse_args()
    if args.auto_serve:
        os.environ["LOCAL_ASSIST_AUTO_SERVE"] = "1"
    if args.self_test:
        return self_test()
    return serve_stdio()


if __name__ == "__main__":
    raise SystemExit(main())
