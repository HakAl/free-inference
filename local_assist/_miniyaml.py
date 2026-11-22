from __future__ import annotations

import copy
import datetime
import json
import math
import re
from typing import Any


# Explicitly accepted YAML subset for stdlib-only parsing (matching PyYAML safe_load / safe_load_all):
# - Mappings, block sequences, flow sequences (when allow_flow_sequences=True),
#   block scalars (|, |-, >, >-) in both mappings and sequences, quoted scalars,
#   per-document anchors/aliases, and multi-document streams separated by column-0 `---` / `...`.
# Explicitly rejected fail-closed forms:
# - Tabs in indentation, merge keys (`<<`), tags (`!tag`), YAML directives (`%YAML`, `%TAG`),
#   unsupported block scalar indicators (`|+`, `>+`, `|2`, `>2`), inline content on `---` / `...`,
#   unfinished flow collections at document boundaries, duplicate mapping keys (when
#   reject_duplicate_keys=True), ambiguous YAML 1.1 plain scalars/keys (dates/timestamps/
#   sexagesimals/non-canonical numerics/YAML 1.1 booleans when strict_plain_scalars=True),
#   nested flow collections, and multi-line quoted scalars.

_STRICT_YAML_DATE_OR_TS_RE = re.compile(r"^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:$|[Tt \t].*)", re.ASCII)
_STRICT_CANONICAL_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$", re.ASCII)
_STRICT_SEXAGESIMAL_RE = re.compile(r"^[+-]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?$", re.ASCII)
_STRICT_YAML_NUM_BOUNDARY_RE = re.compile(
    r"^[+-]?(?:0[oOxXbB][0-9a-fA-F_]+|[0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][+-]?[0-9_]+)?|\.[0-9][0-9_]*(?:[eE][+-]?[0-9_]+)?)$",
    re.ASCII,
)
_STRICT_CANONICAL_INT_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)$", re.ASCII)
_STRICT_CANONICAL_FLOAT_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)\.[0-9]+$", re.ASCII)

_STRICT_RESERVED_LOWER = frozenset(
    {"null", "~", "true", "false", "yes", "no", "on", "off", "y", "n", ".inf", "+.inf", "-.inf", ".nan"}
)


def _split_physical_lines(text: str) -> tuple[list[str], list[bool]]:
    """Split text strictly on CRLF, LF, or CR, preserving whether each line ended with a break."""
    if not text:
        return [], []
    lines: list[str] = []
    has_nl: list[bool] = []
    start = 0
    n = len(text)
    idx = 0
    while idx < n:
        ch = text[idx]
        if ch == "\r":
            lines.append(text[start:idx])
            has_nl.append(True)
            if idx + 1 < n and text[idx + 1] == "\n":
                idx += 2
            else:
                idx += 1
            start = idx
        elif ch == "\n":
            lines.append(text[start:idx])
            has_nl.append(True)
            idx += 1
            start = idx
        else:
            idx += 1
    if start < n:
        lines.append(text[start:])
        has_nl.append(False)
    return lines, has_nl


def _json_loads_with_dup_check(text: str, *, reject_duplicate_keys: bool = False) -> Any:
    if not reject_duplicate_keys:
        return json.loads(text)

    def _no_dups(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            if k in out:
                raise ValueError(f"Duplicate JSON object key: {k!r}")
            out[k] = v
        return out

    return json.loads(text, object_pairs_hook=_no_dups)


def yaml_values_strictly_equal(a: Any, b: Any) -> bool:
    """Recursive type-aware equality (distinguishes bool vs int, int vs float, date vs str)."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        if len(a) != len(b):
            return False
        a_map = {(type(k), k): v for k, v in a.items()}
        b_map = {(type(k), k): v for k, v in b.items()}
        if len(a_map) != len(a) or len(b_map) != len(b):
            return False
        if a_map.keys() != b_map.keys():
            return False
        return all(yaml_values_strictly_equal(a_map[k], b_map[k]) for k in a_map)
    if isinstance(a, list):
        if len(a) != len(b):
            return False
        return all(yaml_values_strictly_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, float):
        if math.isnan(a) or math.isnan(b):
            return False
        return a == b
    return a == b


def safe_load(text: str) -> Any:
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except ImportError:
        stripped = text.lstrip()
        if stripped.startswith(("{", "[")):
            return json.loads(stripped)
        return _MiniYamlParser(text).parse()


def safe_dump(data: Any) -> str:
    # Always emit formatted JSON (a strict subset of YAML 1.2 accepted natively by
    # both promptfoo and PyYAML) so files written under .venv/bin/python (where PyYAML
    # is installed) remain parseable under `python3 -I` stdlib-only mode without
    # PyYAML 80-column line-wrapping or indentless-sequence incompatibilities.
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def parse_yaml_with_flow_sequences(
    text: str,
    *,
    reject_duplicate_keys: bool = False,
    strict_plain_scalars: bool = False,
) -> Any:
    stripped = text.lstrip(" \t\r\n") if strict_plain_scalars else text.lstrip()
    if stripped.startswith(("{", "[")):
        if strict_plain_scalars:
            raise ValueError(
                "Strict YAML mode rejects top-level flow/JSON documents; "
                "use block-style YAML so stdlib and PyYAML scalar resolution match identically"
            )
        return _json_loads_with_dup_check(stripped, reject_duplicate_keys=reject_duplicate_keys)
    return _MiniYamlParser(
        text,
        allow_flow_sequences=True,
        reject_duplicate_keys=reject_duplicate_keys,
        strict_plain_scalars=strict_plain_scalars,
    ).parse()


def parse_yaml_documents(
    text: str,
    *,
    allow_flow_sequences: bool = False,
    reject_duplicate_keys: bool = False,
    strict_plain_scalars: bool = False,
) -> list[Any]:
    """Parse a multi-document YAML stream separated by column-0 `---` / `...` markers."""
    return _MiniYamlParser(
        text,
        allow_flow_sequences=allow_flow_sequences,
        multi_document=True,
        reject_duplicate_keys=reject_duplicate_keys,
        strict_plain_scalars=strict_plain_scalars,
    ).parse_all()


class _MiniYamlParser:
    def __init__(
        self,
        text: str,
        *,
        allow_flow_sequences: bool = False,
        multi_document: bool = False,
        reject_duplicate_keys: bool = False,
        strict_plain_scalars: bool = False,
    ) -> None:
        if strict_plain_scalars and any(ch in text for ch in ("\u0085", "\u2028", "\u2029", "\x0b", "\x0c")):
            raise ValueError(
                "Strict YAML mode rejects non-ASCII line-break or vertical whitespace control characters"
            )
        self.raw_lines, self.line_has_newline = _split_physical_lines(text)
        self.anchors: dict[str, Any] = {}
        self.pos = 0
        self.allow_flow_sequences = allow_flow_sequences
        self.multi_document = multi_document
        self.reject_duplicate_keys = reject_duplicate_keys
        self.strict_plain_scalars = strict_plain_scalars

    def _is_ws(self, ch: str) -> bool:
        return ch in (" ", "\t") if self.strict_plain_scalars else ch.isspace()

    def _strip_ws(self, text: str) -> str:
        return text.strip(" \t") if self.strict_plain_scalars else text.strip()

    def _rstrip_ws(self, text: str) -> str:
        return text.rstrip(" \t") if self.strict_plain_scalars else text.rstrip()

    def _split_anchor_prefix(self, text: str, *, context: str) -> tuple[str, str]:
        if self.strict_plain_scalars:
            sp_idx = text.find(" ")
            if sp_idx == -1:
                anchor = text[1:]
                remainder = ""
            else:
                anchor = text[1:sp_idx]
                remainder = text[sp_idx + 1 :].lstrip(" ")
            if not anchor or not re.fullmatch(r"[A-Za-z0-9_-]+", anchor, re.ASCII):
                raise ValueError(f"Invalid YAML anchor name {anchor!r} in {context}: {text!r}")
            return anchor, remainder
        parts = text.split(None, 1)
        anchor = parts[0][1:]
        if not anchor:
            raise ValueError(f"Invalid empty YAML anchor in {context}: {text!r}")
        return anchor, (parts[1] if len(parts) > 1 else "")

    @staticmethod
    def _classify_doc_marker(raw_line: str) -> str | None:
        if raw_line.startswith("%"):
            raise ValueError(f"Unsupported YAML directive: {raw_line!r}")
        if raw_line.startswith("---"):
            rest = raw_line[3:]
            if rest == "":
                return "start"
            if rest[0] in (" ", "\t"):
                after = rest.lstrip(" ")
                if after == "" or after.startswith("#"):
                    return "start"
                if after.startswith("\t"):
                    if after.lstrip(" \t") == "" or after.lstrip(" \t").startswith("#"):
                        return "start"
                raise ValueError(f"Unsupported inline content on YAML document start marker: {raw_line!r}")
            return None
        if raw_line.startswith("..."):
            rest = raw_line[3:]
            if rest == "":
                return "end"
            if rest[0] in (" ", "\t"):
                after = rest.lstrip(" ")
                if after == "" or after.startswith("#"):
                    return "end"
                if after.startswith("\t"):
                    if after.lstrip(" \t") == "" or after.lstrip(" \t").startswith("#"):
                        return "end"
                raise ValueError(f"Unsupported trailing content on YAML document end marker: {raw_line!r}")
            return None
        return None

    def _can_start_flow_sequence_at(self, line: str, idx: int) -> bool:
        if idx == 0:
            return True
        if not self._is_ws(line[idx - 1]):
            return False
        prefix = line[:idx].rstrip(" ")
        if prefix == "-" or prefix.endswith(":"):
            return True
        if self.strict_plain_scalars:
            sp_idx = prefix.rfind(" ")
            if sp_idx != -1:
                head = prefix[:sp_idx].rstrip(" ")
                tail = prefix[sp_idx + 1 :]
                if tail.startswith("&") and re.fullmatch(r"[A-Za-z0-9_-]+", tail[1:], re.ASCII):
                    return head == "-" or head.endswith(":")
            return False
        parts = prefix.rsplit(None, 1)
        if len(parts) == 2 and parts[1].startswith("&") and len(parts[1]) > 1:
            head = parts[0].rstrip(" ")
            return head == "-" or head.endswith(":")
        return False

    def _strip_comment(self, line: str, *, in_flow_sequence: bool = False) -> str:
        in_single = False
        in_double = False
        escaped = False
        flow_depth = 1 if (self.allow_flow_sequences and in_flow_sequence) else 0
        idx = 0
        while idx < len(line):
            ch = line[idx]
            if escaped:
                escaped = False
                idx += 1
                continue
            if ch == "\\" and in_double:
                escaped = True
                idx += 1
                continue
            if in_single:
                if ch == "'":
                    if idx + 1 < len(line) and line[idx + 1] == "'":
                        idx += 2
                        continue
                    in_single = False
            elif in_double:
                if ch == '"':
                    in_double = False
            else:
                if ch == "\t":
                    raise ValueError(f"Tab characters are not allowed in YAML indentation or unquoted tokens: {line!r}")
                if self.allow_flow_sequences:
                    if ch == "[":
                        if (
                            flow_depth > 0
                            and (idx == 0 or self._is_ws(line[idx - 1]) or line[idx - 1] in ("[", ","))
                        ) or (flow_depth == 0 and self._can_start_flow_sequence_at(line, idx)):
                            flow_depth += 1
                    elif ch == "]" and flow_depth > 0:
                        flow_depth -= 1
                can_open_quote = (
                    idx == 0
                    or self._is_ws(line[idx - 1])
                    or (flow_depth > 0 and line[idx - 1] in ("[", ","))
                )
                if ch == "'" and can_open_quote:
                    in_single = True
                elif ch == '"' and can_open_quote:
                    in_double = True
                elif ch == "#" and (idx == 0 or self._is_ws(line[idx - 1])):
                    return self._rstrip_ws(line[:idx])
            idx += 1
        if in_single or in_double or escaped:
            raise ValueError(f"Unterminated or multi-line quoted scalar is not supported: {line!r}")
        return self._rstrip_ws(line)

    def _skip_ignorable(self, *, in_flow_sequence: bool = False) -> None:
        while self.pos < len(self.raw_lines):
            raw = self.raw_lines[self.pos]
            if self.multi_document and self._classify_doc_marker(raw) is not None:
                break
            if "\t" in raw[: len(raw) - len(raw.lstrip(" \t"))]:
                raise ValueError(f"Tab characters are not allowed in YAML indentation: {raw!r}")
            stripped = raw.lstrip(" ")
            if not stripped or stripped.startswith("#"):
                self.pos += 1
                continue
            content = self._strip_comment(stripped, in_flow_sequence=in_flow_sequence)
            if not content:
                self.pos += 1
                continue
            break

    def _peek(self) -> tuple[int, str] | None:
        self._skip_ignorable()
        if self.pos >= len(self.raw_lines):
            return None
        raw = self.raw_lines[self.pos]
        if self.multi_document and self._classify_doc_marker(raw) is not None:
            return None
        stripped = raw.lstrip(" ")
        indent = len(raw) - len(stripped)
        return indent, self._strip_comment(stripped)

    def parse(self) -> Any:
        peeked = self._peek()
        if peeked is None:
            return None
        node = self._parse_node(peeked[0])
        trailing = self._peek()
        if trailing is not None:
            raise ValueError(
                f"Unconsumed or out-of-indent YAML input at line {self.pos + 1}: {trailing[1]!r}"
            )
        return node

    def parse_all(self) -> list[Any]:
        docs: list[Any] = []
        while self.pos < len(self.raw_lines):
            self.anchors.clear()
            self._skip_ignorable()
            if self.pos >= len(self.raw_lines):
                break
            marker = self._classify_doc_marker(self.raw_lines[self.pos])
            if marker == "end":
                self.pos += 1
                continue
            explicit_start = False
            if marker == "start":
                explicit_start = True
                self.pos += 1
                self._skip_ignorable()
                if self.pos >= len(self.raw_lines):
                    docs.append(None)
                    break
                next_marker = self._classify_doc_marker(self.raw_lines[self.pos])
                if next_marker == "start":
                    docs.append(None)
                    continue
                if next_marker == "end":
                    docs.append(None)
                    self.pos += 1
                    continue
            peeked = self._peek()
            if peeked is None:
                if explicit_start:
                    docs.append(None)
                continue
            node = self._parse_node(peeked[0])
            trailing = self._peek()
            if trailing is not None:
                raise ValueError(
                    f"Unconsumed or out-of-indent YAML input at line {self.pos + 1}: {trailing[1]!r}"
                )
            docs.append(node)
            if self.pos < len(self.raw_lines):
                end_marker = self._classify_doc_marker(self.raw_lines[self.pos])
                if end_marker == "end":
                    self.pos += 1
        return docs

    def _parse_node(self, expected_indent: int) -> Any:
        peeked = self._peek()
        if peeked is None:
            return None
        indent, content = peeked
        if self.allow_flow_sequences and content.startswith("["):
            self.pos += 1
            return self._collect_and_parse_flow_sequence(content, indent)
        if content.startswith("- ") or content == "-":
            return self._parse_list(indent)
        return self._parse_mapping(indent)

    def _parse_list(self, list_indent: int) -> list[Any]:
        items: list[Any] = []
        while True:
            peeked = self._peek()
            if peeked is None:
                break
            indent, content = peeked
            if indent != list_indent or not (content.startswith("- ") or content == "-"):
                break
            rest = content[1:].lstrip(" ")
            self.pos += 1
            if not rest:
                next_peek = self._peek()
                if next_peek is not None and next_peek[0] > list_indent:
                    items.append(self._parse_node(next_peek[0]))
                else:
                    items.append(None)
                continue

            anchor = None
            if rest.startswith("&"):
                anchor, rest = self._split_anchor_prefix(rest, context="sequence")
                if not rest:
                    next_peek = self._peek()
                    if next_peek is not None and next_peek[0] > list_indent:
                        val = self._parse_node(next_peek[0])
                    else:
                        val = None
                    self.anchors[anchor] = val
                    items.append(val)
                    continue

            if rest in ("|", "|-", ">", ">-"):
                val = self._collect_block_scalar(rest, list_indent)
                if anchor:
                    self.anchors[anchor] = val
                items.append(val)
                continue
            if rest.startswith(("|", ">")):
                raise ValueError(f"Unsupported YAML block scalar indicator in sequence: {rest!r}")

            if self._looks_like_mapping_entry(rest):
                item_indent = list_indent + 2
                item_dict = self._parse_inline_mapping_start(rest, item_indent)
                if anchor:
                    self.anchors[anchor] = item_dict
                items.append(item_dict)
            elif self.allow_flow_sequences and rest.startswith("[") and rest != "[]":
                val = self._collect_and_parse_flow_sequence(rest, list_indent)
                if anchor:
                    self.anchors[anchor] = val
                items.append(val)
            else:
                val = self._parse_scalar(rest)
                if anchor:
                    self.anchors[anchor] = val
                items.append(val)
        return items

    def _parse_inline_mapping_start(self, first_entry: str, item_indent: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        key, val_str = self._split_kv(first_entry, strict_keys=self.strict_plain_scalars)
        result[key] = self._resolve_value(val_str, item_indent)
        while True:
            peeked = self._peek()
            if peeked is None:
                break
            indent, content = peeked
            if indent != item_indent or content.startswith("- ") or content == "-":
                break
            self.pos += 1
            k, v_str = self._split_kv(content, strict_keys=self.strict_plain_scalars)
            if self.reject_duplicate_keys and k in result:
                raise ValueError(f"Duplicate YAML mapping key: {k!r}")
            result[k] = self._resolve_value(v_str, item_indent)
        return result

    def _parse_mapping(self, map_indent: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        while True:
            peeked = self._peek()
            if peeked is None:
                break
            indent, content = peeked
            if indent != map_indent or content.startswith("- ") or content == "-":
                break
            self.pos += 1
            key, val_str = self._split_kv(content, strict_keys=self.strict_plain_scalars)
            if self.reject_duplicate_keys and key in result:
                raise ValueError(f"Duplicate YAML mapping key: {key!r}")
            result[key] = self._resolve_value(val_str, map_indent)
        return result

    def _resolve_value(self, val_str: str, parent_indent: int) -> Any:
        anchor = None
        if val_str.startswith("&"):
            anchor, val_str = self._split_anchor_prefix(val_str, context="mapping")

        if val_str in ("|", "|-", ">", ">-"):
            val = self._collect_block_scalar(val_str, parent_indent)
            if anchor:
                self.anchors[anchor] = val
            return val
        if val_str.startswith(("|", ">")):
            raise ValueError(f"Unsupported YAML block scalar indicator: {val_str!r}")

        if val_str == "":
            next_peek = self._peek()
            if next_peek is not None and (
                next_peek[0] > parent_indent
                or (
                    next_peek[0] == parent_indent
                    and (next_peek[1].startswith("- ") or next_peek[1] == "-")
                )
            ):
                val = self._parse_node(next_peek[0])
            else:
                val = None
            if anchor:
                self.anchors[anchor] = val
            return val

        if self.allow_flow_sequences and val_str.startswith("[") and val_str != "[]":
            val = self._collect_and_parse_flow_sequence(val_str, parent_indent)
            if anchor:
                self.anchors[anchor] = val
            return val

        val = self._parse_scalar(val_str)
        if anchor:
            self.anchors[anchor] = val
        return val

    def _collect_and_parse_flow_sequence(self, initial_text: str, min_indent: int) -> list[Any]:
        chunks = [initial_text]

        def _is_balanced(text: str) -> bool:
            in_single = False
            in_double = False
            escaped = False
            depth = 0
            idx = 0
            while idx < len(text):
                ch = text[idx]
                if escaped:
                    escaped = False
                    idx += 1
                    continue
                if ch == "\\" and in_double:
                    escaped = True
                    idx += 1
                    continue
                if in_single:
                    if ch == "'":
                        if idx + 1 < len(text) and text[idx + 1] == "'":
                            idx += 2
                            continue
                        in_single = False
                elif in_double:
                    if ch == '"':
                        in_double = False
                else:
                    if ch == "'":
                        in_single = True
                    elif ch == '"':
                        in_double = True
                    elif ch == "[":
                        depth += 1
                    elif ch == "]":
                        depth -= 1
                        if depth == 0:
                            trailing = self._strip_ws(text[idx + 1 :])
                            if trailing:
                                raise ValueError(
                                    f"Unexpected trailing content after YAML flow sequence: {trailing!r}"
                                )
                            return True
                        if depth < 0:
                            raise ValueError(f"Unbalanced closing bracket in YAML flow sequence: {text!r}")
                idx += 1
            if in_single or in_double or escaped:
                raise ValueError(f"Unterminated quoted string in YAML flow sequence: {text!r}")
            return False

        combined = " ".join(chunks)
        while not _is_balanced(combined):
            self._skip_ignorable(in_flow_sequence=True)
            if self.pos >= len(self.raw_lines):
                raise ValueError(f"Unterminated YAML flow sequence: {combined!r}")
            raw = self.raw_lines[self.pos]
            if self.multi_document and self._classify_doc_marker(raw) is not None:
                raise ValueError(
                    f"Unterminated YAML flow sequence before document boundary: {combined!r}"
                )
            stripped = raw.lstrip(" ")
            indent = len(raw) - len(stripped)
            if indent <= min_indent and not stripped.startswith("]"):
                raise ValueError(
                    f"Multiline YAML flow sequence line at indent {indent} must be indented beyond {min_indent}: {raw!r}"
                )
            content = self._strip_comment(stripped, in_flow_sequence=True)
            self.pos += 1
            chunks.append(content)
            combined = " ".join(chunks)

        combined = self._strip_ws(combined)
        if not (combined.startswith("[") and combined.endswith("]")):
            raise ValueError(f"Malformed YAML flow sequence: {combined!r}")
        inner = self._strip_ws(combined[1:-1])
        if not inner:
            return []

        raw_items: list[str] = []
        cur: list[str] = []
        in_single = False
        in_double = False
        escaped = False
        idx = 0
        while idx < len(inner):
            ch = inner[idx]
            if escaped:
                cur.append(ch)
                escaped = False
                idx += 1
                continue
            if ch == "\\" and in_double:
                cur.append(ch)
                escaped = True
                idx += 1
                continue
            if in_single:
                cur.append(ch)
                if ch == "'":
                    if idx + 1 < len(inner) and inner[idx + 1] == "'":
                        cur.append("'")
                        idx += 2
                        continue
                    in_single = False
            elif in_double:
                cur.append(ch)
                if ch == '"':
                    in_double = False
            else:
                if ch == "'":
                    in_single = True
                    cur.append(ch)
                elif ch == '"':
                    in_double = True
                    cur.append(ch)
                elif ch in ("[", "]", "{", "}"):
                    raise ValueError(f"Nested flow collections are not supported in YAML flow sequence: {combined!r}")
                elif ch == ",":
                    item_str = self._strip_ws("".join(cur))
                    if not item_str:
                        raise ValueError(f"Empty item before comma in YAML flow sequence: {combined!r}")
                    raw_items.append(item_str)
                    cur = []
                else:
                    cur.append(ch)
            idx += 1

        tail_str = self._strip_ws("".join(cur))
        if tail_str:
            raw_items.append(tail_str)
        elif not raw_items:
            raise ValueError(f"Empty YAML flow sequence with comma: {combined!r}")

        return [self._parse_scalar(item) for item in raw_items]

    def _collect_block_scalar(self, indicator: str, parent_indent: int) -> str:
        raw_items: list[tuple[str, bool, bool]] = []
        block_indent: int | None = None
        while self.pos < len(self.raw_lines):
            raw = self.raw_lines[self.pos]
            has_nl = self.line_has_newline[self.pos]
            if self.multi_document and self._classify_doc_marker(raw) is not None:
                break
            stripped = raw.lstrip(" ")
            if not stripped:
                raw_items.append((raw, has_nl, True))
                self.pos += 1
                continue
            indent = len(raw) - len(stripped)
            if indent <= parent_indent:
                break
            if block_indent is None:
                block_indent = indent
                for lead_raw, _, _ in raw_items:
                    if len(lead_raw) > block_indent:
                        raise ValueError(
                            f"Leading blank line in YAML block scalar is more indented ({len(lead_raw)}) "
                            f"than detected block_indent ({block_indent})"
                        )
            elif indent < block_indent:
                raise ValueError(
                    f"Under-indented continuation line in YAML block scalar at line {self.pos + 1}: "
                    f"indent {indent} < block_indent {block_indent}"
                )
            raw_items.append((raw, has_nl, False))
            self.pos += 1

        if block_indent is None:
            return ""

        block_items: list[tuple[str, bool]] = []
        for raw, has_nl, is_spaces_only in raw_items:
            if is_spaces_only:
                line_text = raw[block_indent:] if len(raw) > block_indent else ""
            else:
                line_text = raw[block_indent:]
            block_items.append((line_text, has_nl))

        while block_items and block_items[-1][0] == "":
            block_items.pop()

        if not block_items:
            return ""

        last_retained_has_nl = block_items[-1][1]
        block_lines = [line_text for line_text, _ in block_items]

        if indicator.startswith(">"):
            out_parts: list[str] = []
            prev_non_empty: str | None = None
            empty_count = 0
            for line in block_lines:
                if line == "":
                    empty_count += 1
                    continue
                if prev_non_empty is None:
                    if empty_count > 0:
                        out_parts.append("\n" * empty_count)
                    out_parts.append(line)
                else:
                    more_indented = prev_non_empty.startswith((" ", "\t")) or line.startswith((" ", "\t"))
                    if empty_count == 0:
                        out_parts.append(("\n" if more_indented else " ") + line)
                    else:
                        newlines = empty_count + (1 if more_indented else 0)
                        out_parts.append(("\n" * newlines) + line)
                prev_non_empty = line
                empty_count = 0
            joined = "".join(out_parts)
        else:
            joined = "\n".join(block_lines)

        if indicator.endswith("-"):
            return joined
        return joined + ("\n" if last_retained_has_nl else "")

    @staticmethod
    def _find_mapping_colon(text: str) -> int:
        if text.startswith(("{", "[")):
            return -1
        if text.startswith('"'):
            idx = 1
            escaped = False
            close_idx = -1
            while idx < len(text):
                ch = text[idx]
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    close_idx = idx
                    break
                idx += 1
            if close_idx == -1:
                raise ValueError(f"Unterminated double-quoted YAML key or scalar: {text!r}")
            after_quote = text[close_idx + 1 :].lstrip(" ")
            if after_quote.startswith(":"):
                colon_idx = len(text) - len(after_quote)
                after_colon = text[colon_idx + 1 :]
                if after_colon == "" or after_colon.startswith(" "):
                    return colon_idx
            return -1
        if text.startswith("'"):
            idx = 1
            close_idx = -1
            while idx < len(text):
                if text[idx : idx + 2] == "''":
                    idx += 2
                    continue
                if text[idx] == "'":
                    close_idx = idx
                    break
                idx += 1
            if close_idx == -1:
                raise ValueError(f"Unterminated single-quoted YAML key or scalar: {text!r}")
            after_quote = text[close_idx + 1 :].lstrip(" ")
            if after_quote.startswith(":"):
                colon_idx = len(text) - len(after_quote)
                after_colon = text[colon_idx + 1 :]
                if after_colon == "" or after_colon.startswith(" "):
                    return colon_idx
            return -1
        colon = text.find(":")
        if colon == -1:
            return -1
        after = text[colon + 1 :]
        return colon if (after == "" or after.startswith(" ")) else -1

    @classmethod
    def _looks_like_mapping_entry(cls, text: str) -> bool:
        return cls._find_mapping_colon(text) != -1

    @staticmethod
    def _resolve_strict_plain_token(text: str, *, is_key: bool) -> Any:
        """Unified ASCII-only strict plain resolver shared by keys and scalar values."""
        low = text.lower()
        if low in _STRICT_RESERVED_LOWER:
            if is_key:
                raise ValueError(
                    f"Unquoted YAML reserved-word mapping key {text!r} is not supported; quote it"
                )
            if text in ("null", "~", "Null", "NULL"):
                return None
            if text in ("true", "True", "TRUE"):
                return True
            if text in ("false", "False", "FALSE"):
                return False
            if low in ("yes", "no", "on", "off", "y", "n"):
                raise ValueError(f"Ambiguous YAML 1.1 boolean literal {text!r}; quote it or use true/false")
            raise ValueError(f"Unsupported YAML non-finite float literal {text!r}")

        if _STRICT_YAML_DATE_OR_TS_RE.match(text):
            if is_key:
                raise ValueError(
                    f"Unquoted YAML date or timestamp mapping key {text!r} is not supported; quote it"
                )
            if _STRICT_CANONICAL_DATE_RE.fullmatch(text):
                try:
                    return datetime.date.fromisoformat(text)
                except ValueError as exc:
                    raise ValueError(f"Invalid unquoted ISO date in YAML scalar {text!r}") from exc
            raise ValueError(
                f"Unquoted YAML 1.1 non-canonical date or timestamp scalar {text!r} is not supported; quote it"
            )

        if _STRICT_SEXAGESIMAL_RE.fullmatch(text):
            kind = "mapping key" if is_key else "scalar"
            raise ValueError(f"Unsupported sexagesimal literal in YAML {kind} {text!r}; quote it as a string")

        if _STRICT_YAML_NUM_BOUNDARY_RE.fullmatch(text):
            if is_key:
                raise ValueError(
                    f"Unquoted numeric YAML mapping key {text!r} is not supported; quote it"
                )
            if _STRICT_CANONICAL_INT_RE.fullmatch(text):
                return int(text)
            if _STRICT_CANONICAL_FLOAT_RE.fullmatch(text):
                return float(text)
            raise ValueError(f"Unsupported numeric literal format in YAML scalar: {text!r}")

        return text

    @classmethod
    def _split_kv(cls, text: str, *, strict_keys: bool = False) -> tuple[str, str]:
        colon = cls._find_mapping_colon(text)
        if colon == -1:
            raise ValueError(f"Invalid YAML mapping entry (missing mapping colon): {text!r}")
        raw_key = text[:colon].strip(" \t") if strict_keys else text[:colon].strip()
        val = text[colon + 1 :].strip(" \t") if strict_keys else text[colon + 1 :].strip()
        if raw_key.startswith('"'):
            if not (raw_key.endswith('"') and len(raw_key) >= 2):
                raise ValueError(f"Unterminated double-quoted YAML mapping key: {raw_key!r}")
            try:
                key = json.loads(raw_key)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid double-quoted YAML mapping key (non-JSON escapes such as \\x are not supported): {raw_key!r}"
                ) from exc
            if not isinstance(key, str) or not key:
                raise ValueError(f"YAML mapping key must decode to a non-empty string: {raw_key!r}")
            return key, val
        if raw_key.startswith("'"):
            if not (raw_key.endswith("'") and len(raw_key) >= 2):
                raise ValueError(f"Unterminated single-quoted YAML mapping key: {raw_key!r}")
            key = raw_key[1:-1].replace("''", "'")
            if not key:
                raise ValueError(f"YAML mapping key must not be empty: {raw_key!r}")
            return key, val
        if raw_key == "<<":
            raise ValueError("Unsupported YAML merge key '<<'; inline the mapping fields explicitly")
        if not raw_key or any(ch in raw_key for ch in ('"', "'", "{", "}", "[", "]", "&", "*", "!", "<", ">", "\t")):
            raise ValueError(f"Unsupported or malformed YAML mapping key: {raw_key!r}")
        if strict_keys:
            cls._resolve_strict_plain_token(raw_key, is_key=True)
            return raw_key, val
        if (
            raw_key.lower() in _STRICT_RESERVED_LOWER
            or re.fullmatch(r"[+-]?(?:\d[\d_]*|\d*\.\d[\d_]*|\d[\d_]*\.)", raw_key)
        ):
            raise ValueError(
                f"Unquoted YAML reserved-word or numeric mapping key {raw_key!r} is not supported; quote it"
            )
        return raw_key, val

    def _parse_scalar(self, text: str) -> Any:
        if text.startswith("*"):
            if self.strict_plain_scalars:
                alias = text[1:]
                if not re.fullmatch(r"[A-Za-z0-9_-]+", alias, re.ASCII):
                    raise ValueError(f"Invalid YAML alias syntax in scalar: {text!r}")
            else:
                alias = text[1:].strip()
            if not alias or alias not in self.anchors:
                raise ValueError(f"Unknown YAML alias in scalar: {text!r}")
            return copy.deepcopy(self.anchors[alias])
        if text.startswith("&"):
            raise ValueError(f"Unsupported YAML anchor in scalar: {text!r}")
        if text.startswith("!"):
            raise ValueError(f"Unsupported YAML tag in scalar: {text!r}")
        if text in ("=", "<<"):
            raise ValueError(f"Unsupported YAML special indicator in scalar: {text!r}")
        if text == "[]":
            return []
        if text == "{}":
            return {}
        if text.startswith(("[", "{")):
            raise ValueError(f"Unsupported YAML flow collection in scalar: {text!r}")
        if text.startswith('"'):
            if not (text.endswith('"') and len(text) >= 2):
                raise ValueError(f"Unterminated double-quoted scalar: {text!r}")
            try:
                return json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid double-quoted YAML scalar: {text!r}") from exc
        if text.startswith("'"):
            if not (text.endswith("'") and len(text) >= 2):
                raise ValueError(f"Unterminated single-quoted scalar: {text!r}")
            return text[1:-1].replace("''", "'")
        if ": " in text or text.endswith(":"):
            raise ValueError(f"Unquoted mapping colon in YAML scalar: {text!r}")
        if self.strict_plain_scalars:
            return self._resolve_strict_plain_token(text, is_key=False)
        if text in ("null", "~", "Null", "NULL"):
            return None
        if text in ("true", "True", "TRUE"):
            return True
        if text in ("false", "False", "FALSE"):
            return False
        if text.lower() in ("yes", "no", "on", "off", "y", "n"):
            raise ValueError(f"Ambiguous YAML 1.1 boolean literal {text!r}; quote it or use true/false")
        if text.lower() in (".inf", "+.inf", "-.inf", ".nan"):
            raise ValueError(f"Unsupported YAML non-finite float literal {text!r}")
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            try:
                return datetime.date.fromisoformat(text)
            except ValueError as exc:
                raise ValueError(f"Invalid unquoted ISO date in YAML scalar {text!r}") from exc
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}[Tt ].+", text):
            raise ValueError(f"Unquoted ISO timestamp in YAML scalar {text!r}; quote it as a string")
        if re.fullmatch(r"[+-]?\d+(?::[0-5]?\d)+(?:\.\d+)?", text):
            raise ValueError(f"Unsupported sexagesimal literal in YAML scalar {text!r}; quote it as a string")
        if (
            re.fullmatch(r"-?0\d+", text)
            or re.fullmatch(r"-?0[oOxXbB][0-9a-fA-F_]+", text)
            or re.fullmatch(r"[+-]?\d+(?:\.\d+)?[eE][+-]?\d+", text)
            or re.fullmatch(r"\+\d+(?:\.\d+)?", text)
            or re.fullmatch(r"[+-]?(?:\.\d+|\d+\.)", text)
            or (re.fullmatch(r"[+-]?\d[\d_]*(?:\.[\d_]+)?", text) is not None and "_" in text)
        ):
            raise ValueError(f"Unsupported numeric literal format in YAML scalar: {text!r}")
        if re.fullmatch(r"-?(?:0|[1-9]\d*)", text):
            return int(text)
        if re.fullmatch(r"-?(?:0|[1-9]\d*)\.\d+", text):
            return float(text)
        return text
