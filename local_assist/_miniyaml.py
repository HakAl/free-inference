from __future__ import annotations

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
    try:
        import yaml  # type: ignore

        return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    except ImportError:
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


class _MiniYamlParser:
    def __init__(self, text: str) -> None:
        self.raw_lines = text.splitlines()
        self.anchors: dict[str, Any] = {}
        self.pos = 0

    @staticmethod
    def _strip_comment(line: str) -> str:
        in_single = False
        in_double = False
        escaped = False
        for idx, ch in enumerate(line):
            if escaped:
                escaped = False
                continue
            if ch == "\\" and in_double:
                escaped = True
                continue
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == "#" and not in_single and not in_double:
                if idx == 0 or line[idx - 1].isspace():
                    return line[:idx].rstrip()
        return line.rstrip()

    def _skip_ignorable(self) -> None:
        while self.pos < len(self.raw_lines):
            raw = self.raw_lines[self.pos]
            stripped = raw.lstrip(" ")
            if not stripped or stripped.startswith("#"):
                self.pos += 1
                continue
            content = self._strip_comment(stripped)
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
        return self._parse_node(peeked[0])

    def _parse_node(self, expected_indent: int) -> Any:
        peeked = self._peek()
        if peeked is None:
            return None
        indent, content = peeked
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
            val_str = parts[1] if len(parts) > 1 else ""

        if val_str in ("|", "|-", ">", ">-"):
            val = self._collect_block_scalar(val_str, parent_indent)
            if anchor:
                self.anchors[anchor] = val
            return val

        if val_str == "":
            next_peek = self._peek()
            if next_peek is not None and next_peek[0] > parent_indent:
                val = self._parse_node(next_peek[0])
            else:
                val = None
            if anchor:
                self.anchors[anchor] = val
            return val

        val = self._parse_scalar(val_str)
        if anchor:
            self.anchors[anchor] = val
        return val

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
            return " ".join(line.strip() for line in block_lines if line.strip()).strip()
        joined = "\n".join(block_lines)
        return joined if indicator.endswith("-") else joined + "\n"

    @staticmethod
    def _looks_like_mapping_entry(text: str) -> bool:
        if text.startswith(('"', "'", "{", "[")):
            return False
        colon = text.find(":")
        if colon == -1:
            return False
        after = text[colon + 1 :]
        return after == "" or after.startswith(" ")

    @staticmethod
    def _split_kv(text: str) -> tuple[str, str]:
        colon = text.find(":")
        if colon == -1:
            return text.strip(), ""
        key = text[:colon].strip()
        val = text[colon + 1 :].strip()
        return key, val

    def _parse_scalar(self, text: str) -> Any:
        if text.startswith("*"):
            alias = text[1:].strip()
            return json.loads(json.dumps(self.anchors.get(alias)))
        if text in ("null", "~", "Null", "NULL"):
            return None
        if text in ("true", "True", "TRUE"):
            return True
        if text in ("false", "False", "FALSE"):
            return False
        if text == "[]":
            return []
        if text == "{}":
            return {}
        if (text.startswith('"') and text.endswith('"')) or (
            text.startswith("{") and text.endswith("}")
        ):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                if text.startswith('"') and text.endswith('"'):
                    return text[1:-1]
        if text.startswith("'") and text.endswith("'"):
            return text[1:-1].replace("''", "'")
        if re.fullmatch(r"-?\d+", text):
            return int(text)
        if re.fullmatch(r"-?\d+\.\d+", text):
            return float(text)
        return text
