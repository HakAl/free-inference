from __future__ import annotations

import copy
import datetime
import json
import re
from typing import Any


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


def parse_yaml_with_flow_sequences(text: str) -> Any:
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        return json.loads(stripped)
    return _MiniYamlParser(text, allow_flow_sequences=True).parse()


class _MiniYamlParser:
    def __init__(self, text: str, *, allow_flow_sequences: bool = False) -> None:
        self.raw_lines = text.splitlines()
        self.anchors: dict[str, Any] = {}
        self.pos = 0
        self.allow_flow_sequences = allow_flow_sequences

    @staticmethod
    def _can_start_flow_sequence_at(line: str, idx: int) -> bool:
        if idx == 0:
            return True
        if not line[idx - 1].isspace():
            return False
        prefix = line[:idx].rstrip(" ")
        if prefix == "-" or prefix.endswith(":"):
            return True
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
                            and (idx == 0 or line[idx - 1].isspace() or line[idx - 1] in ("[", ","))
                        ) or (flow_depth == 0 and self._can_start_flow_sequence_at(line, idx)):
                            flow_depth += 1
                    elif ch == "]" and flow_depth > 0:
                        flow_depth -= 1
                can_open_quote = (
                    idx == 0
                    or line[idx - 1].isspace()
                    or (flow_depth > 0 and line[idx - 1] in ("[", ","))
                )
                if ch == "'" and can_open_quote:
                    in_single = True
                elif ch == '"' and can_open_quote:
                    in_double = True
                elif ch == "#" and (idx == 0 or line[idx - 1].isspace()):
                    return line[:idx].rstrip()
            idx += 1
        if in_single or in_double or escaped:
            raise ValueError(f"Unterminated or multi-line quoted scalar is not supported: {line!r}")
        return line.rstrip()

    def _skip_ignorable(self, *, in_flow_sequence: bool = False) -> None:
        while self.pos < len(self.raw_lines):
            raw = self.raw_lines[self.pos]
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
                parts = rest.split(None, 1)
                anchor = parts[0][1:]
                rest = parts[1] if len(parts) > 1 else ""

            if self._looks_like_mapping_entry(rest):
                item_indent = list_indent + 2
                item_dict = self._parse_inline_mapping_start(rest, item_indent)
                if anchor:
                    self.anchors[anchor] = item_dict
                items.append(item_dict)
            else:
                val = self._parse_scalar(rest)
                if anchor:
                    self.anchors[anchor] = val
                items.append(val)
        return items

    def _parse_inline_mapping_start(self, first_entry: str, item_indent: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        key, val_str = self._split_kv(first_entry)
        result[key] = self._resolve_value(val_str, item_indent)
        while True:
            peeked = self._peek()
            if peeked is None:
                break
            indent, content = peeked
            if indent != item_indent or content.startswith("- ") or content == "-":
                break
            self.pos += 1
            k, v_str = self._split_kv(content)
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
            key, val_str = self._split_kv(content)
            result[key] = self._resolve_value(val_str, map_indent)
        return result

    def _resolve_value(self, val_str: str, parent_indent: int) -> Any:
        anchor = None
        if val_str.startswith("&"):
            parts = val_str.split(None, 1)
            anchor = parts[0][1:]
            if not anchor:
                raise ValueError(f"Invalid empty YAML anchor: {val_str!r}")
            val_str = parts[1] if len(parts) > 1 else ""

        if val_str in ("|", "|-", ">", ">-"):
            val = self._collect_block_scalar(val_str, parent_indent)
            if anchor:
                self.anchors[anchor] = val
            return val

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
                            trailing = text[idx + 1 :].strip()
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

        combined = combined.strip()
        if not (combined.startswith("[") and combined.endswith("]")):
            raise ValueError(f"Malformed YAML flow sequence: {combined!r}")
        inner = combined[1:-1].strip()
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
                    item_str = "".join(cur).strip()
                    if not item_str:
                        raise ValueError(f"Empty item before comma in YAML flow sequence: {combined!r}")
                    raw_items.append(item_str)
                    cur = []
                else:
                    cur.append(ch)
            idx += 1

        tail_str = "".join(cur).strip()
        if tail_str:
            raw_items.append(tail_str)
        elif not raw_items:
            raise ValueError(f"Empty YAML flow sequence with comma: {combined!r}")

        return [self._parse_scalar(item) for item in raw_items]

    def _collect_block_scalar(self, indicator: str, parent_indent: int) -> str:
        block_lines: list[str] = []
        block_indent: int | None = None
        while self.pos < len(self.raw_lines):
            raw = self.raw_lines[self.pos]
            stripped = raw.lstrip(" ")
            if not stripped:
                block_lines.append("")
                self.pos += 1
                continue
            indent = len(raw) - len(stripped)
            if indent <= parent_indent:
                break
            if block_indent is None:
                block_indent = indent
            block_lines.append(raw[block_indent:] if len(raw) >= block_indent else stripped)
            self.pos += 1

        while block_lines and block_lines[-1] == "":
            block_lines.pop()

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
                    more_indented = prev_non_empty.startswith(" ") or line.startswith(" ")
                    if empty_count == 0:
                        out_parts.append(("\n" if more_indented else " ") + line)
                    else:
                        newlines = empty_count + (1 if more_indented else 0)
                        out_parts.append(("\n" * newlines) + line)
                prev_non_empty = line
                empty_count = 0
            joined = "".join(out_parts)
            return joined if indicator.endswith("-") else joined + "\n"
        joined = "\n".join(block_lines)
        return joined if indicator.endswith("-") else joined + "\n"

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

    @classmethod
    def _split_kv(cls, text: str) -> tuple[str, str]:
        colon = cls._find_mapping_colon(text)
        if colon == -1:
            raise ValueError(f"Invalid YAML mapping entry (missing mapping colon): {text!r}")
        raw_key = text[:colon].strip()
        val = text[colon + 1 :].strip()
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
        if (
            raw_key.lower()
            in ("null", "~", "true", "false", "yes", "no", "on", "off", "y", "n", ".inf", "+.inf", "-.inf", ".nan")
            or re.fullmatch(r"[+-]?(?:\d[\d_]*|\d*\.\d[\d_]*|\d[\d_]*\.)", raw_key)
        ):
            raise ValueError(
                f"Unquoted YAML reserved-word or numeric mapping key {raw_key!r} is not supported; quote it"
            )
        return raw_key, val

    def _parse_scalar(self, text: str) -> Any:
        if text.startswith("*"):
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
