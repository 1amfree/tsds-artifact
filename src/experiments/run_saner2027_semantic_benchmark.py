#!/usr/bin/env python3
"""Run the independent finite-domain semantic benchmark for T06.

This benchmark is deliberately outside the TSDS evaluator.  A generated C
program computes final command bytes from a finite set of byte inputs; a
separate Python reference implementation computes the same transformations
and applies a bounded, explicitly documented shell-vector oracle.  The
program is not asked to execute a shell.  Consequently the outputs establish
implementation/oracle parity over the declared finite domain, not firmware
ground truth or device exploitability.

The benchmark has 48 distinct cases: six cases in each of eight semantic
families.  Four cases per family are development cases and two are held out.
The held-out split is fixed before execution and is never used to tune the
reference oracle.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCHEMA = "tsds-saner2027-independent-semantic-benchmark-v1"
SPLIT_SEED = 20260913
SOURCE_DOMAIN_SCHEMA = "tsds-finite-source-domain-v1"

# The oracle intentionally duplicates the *public vector names and bounded
# witness forms*, but does not import or call ThreatMatrixEvaluator.
VECTOR_PATTERNS: tuple[tuple[str, tuple[bytes, ...], tuple[str, ...]], ...] = (
    ("semicolon", (b";:",), ("unquoted",)),
    ("newline", (b"\n:",), ("unquoted",)),
    ("pipe", (b"|:",), ("unquoted",)),
    ("background_ampersand", (b"&:",), ("unquoted",)),
    ("backtick_substitution", (b"`:`",), ("unquoted", "double_quoted")),
    ("dollar_substitution", (b"$(:)",), ("unquoted", "double_quoted")),
    ("dollar_expansion", (b"$A",), ("unquoted", "double_quoted")),
    ("output_redirection", (b">/dev/null",), ("unquoted",)),
    ("input_redirection", (b"</dev/null",), ("unquoted",)),
    ("ifs_word_splitting", (b"${IFS}:",), ("unquoted",)),
    ("tab_word_splitting", (b"\t:",), ("unquoted",)),
)
VECTOR_IDS = tuple(row[0] for row in VECTOR_PATTERNS)


def _case(case_id: str, family: str, kind: str, **kwargs: Any) -> dict[str, Any]:
    value = {"id": case_id, "family": family, "kind": kind}
    value.update(kwargs)
    return value


CASES: tuple[dict[str, Any], ...] = (
    # Source/fixed composition.
    _case("source_direct_unquoted", "source_fixed", "parts", parts=[("literal", "echo "), ("source", "direct")]),
    _case("source_fixed_sink", "source_fixed", "parts", parts=[("literal", "echo fixed")]),
    _case("source_fixed_prefix", "source_fixed", "parts", parts=[("literal", "printf fixed && echo "), ("source", "direct")]),
    _case("source_fixed_suffix", "source_fixed", "parts", parts=[("literal", "echo "), ("source", "direct"), ("literal", " fixed")]),
    _case("source_duplicate_field", "source_fixed", "parts", parts=[("literal", "echo "), ("source", "direct"), ("literal", "-"), ("source", "direct")]),
    _case("source_single_quoted", "source_fixed", "parts", parts=[("literal", "echo '") , ("source", "direct"), ("literal", "'")]),

    # Copy, format, and wrapper operations.
    _case("copy_snprintf_16", "copy_format_wrapper", "parts", parts=[("literal", "echo "), ("source", "bounded", 16)]),
    _case("copy_bounded_4", "copy_format_wrapper", "parts", parts=[("literal", "echo "), ("source", "bounded", 4)]),
    _case("wrapper_printf_argument", "copy_format_wrapper", "parts", parts=[("literal", "printf '%s' "), ("source", "direct")]),
    _case("wrapper_append_chain", "copy_format_wrapper", "parts", parts=[("literal", "echo ["), ("source", "direct"), ("literal", "]")]),
    _case("format_two_source_fields", "copy_format_wrapper", "parts", parts=[("literal", "echo "), ("source", "direct"), ("literal", ":"), ("source", "direct")]),
    _case("copy_fixed_prefix", "copy_format_wrapper", "parts", parts=[("literal", "echo fixed-"), ("source", "direct")]),

    # Filters and escaping.
    _case("filter_alnum", "allowlist_escape", "parts", parts=[("literal", "echo "), ("source", "alnum")]),
    _case("filter_replace_meta", "allowlist_escape", "parts", parts=[("literal", "echo "), ("source", "replace_meta")]),
    _case("filter_backslash_meta", "allowlist_escape", "parts", parts=[("literal", "echo "), ("source", "backslash_meta")]),
    _case("filter_drop_shell_space", "allowlist_escape", "parts", parts=[("literal", "echo "), ("source", "drop_space")]),
    _case("filter_filename_chars", "allowlist_escape", "parts", parts=[("literal", "echo "), ("source", "filename")]),
    _case("filter_escape_meta_argument", "allowlist_escape", "parts", parts=[("literal", "printf '%s' "), ("source", "backslash_meta")]),

    # Quote, comment, and escape context.
    _case("quote_single_literal", "quote_comment", "parts", parts=[("literal", "echo '") , ("source", "direct"), ("literal", "'")]),
    _case("quote_double_literal", "quote_comment", "parts", parts=[("literal", "echo \""), ("source", "direct"), ("literal", "\"")]),
    _case("quote_single_breakout", "quote_comment", "parts", parts=[("literal", "echo '") , ("source", "direct"), ("literal", "'")]),
    _case("quote_double_breakout", "quote_comment", "parts", parts=[("literal", "echo \""), ("source", "direct"), ("literal", "\"")]),
    _case("comment_suffix", "quote_comment", "parts", parts=[("literal", "echo "), ("source", "direct"), ("literal", " #fixed")]),
    _case("backslash_prefixed_source", "quote_comment", "parts", parts=[("literal", "echo " + "\\"), ("source", "direct")]),

    # C-string and length behavior.
    _case("cstring_prefix", "length_nul", "parts", parts=[("literal", "echo "), ("source", "direct")]),
    _case("cstring_limit_2", "length_nul", "parts", parts=[("literal", "echo "), ("source", "bounded", 2)]),
    _case("cstring_limit_7", "length_nul", "parts", parts=[("literal", "echo "), ("source", "bounded", 7)]),
    _case("cstring_fixed_after_source", "length_nul", "parts", parts=[("literal", "echo "), ("source", "direct"), ("literal", " ;fixed")]),
    _case("cstring_zero_precision", "length_nul", "parts", parts=[("literal", "echo "), ("source", "bounded", 0)]),
    _case("cstring_length_guard", "length_nul", "branch", predicate="length_lt_8", then_parts=[("literal", "echo "), ("source", "direct")], else_parts=[("literal", "echo fixed")]),

    # Branch-sensitive source use.
    _case("branch_first_A_unquoted", "multi_branch", "branch", predicate="first_A", then_parts=[("literal", "echo "), ("source", "direct")], else_parts=[("literal", "echo '") , ("source", "direct"), ("literal", "'")]),
    _case("branch_first_B_unquoted_else_fixed", "multi_branch", "branch", predicate="first_B", then_parts=[("literal", "echo "), ("source", "direct")], else_parts=[("literal", "echo fixed")]),
    _case("branch_contains_pipe", "multi_branch", "branch", predicate="contains_pipe", then_parts=[("literal", "echo "), ("source", "direct")], else_parts=[("literal", "echo '") , ("source", "direct"), ("literal", "'")]),
    _case("branch_odd_length", "multi_branch", "branch", predicate="odd_length", then_parts=[("literal", "echo "), ("source", "direct")], else_parts=[("literal", "echo \""), ("source", "direct"), ("literal", "\"")]),
    _case("branch_first_semicolon", "multi_branch", "branch", predicate="first_semicolon", then_parts=[("literal", "echo "), ("source", "direct")], else_parts=[("literal", "echo fixed")]),
    _case("branch_first_dollar", "multi_branch", "branch", predicate="first_dollar", then_parts=[("literal", "echo "), ("source", "direct")], else_parts=[("literal", "printf fixed")]),

    # Source transformations and encoding.
    _case("transform_percent_decode", "source_transform_encoding", "parts", parts=[("literal", "echo "), ("source", "percent_decode")]),
    _case("transform_x_to_semicolon", "source_transform_encoding", "parts", parts=[("literal", "echo "), ("source", "x_to_semicolon")]),
    _case("transform_uppercase", "source_transform_encoding", "parts", parts=[("literal", "echo "), ("source", "uppercase")]),
    _case("transform_hex_encode", "source_transform_encoding", "parts", parts=[("literal", "echo "), ("source", "hex_encode")]),
    _case("transform_reverse", "source_transform_encoding", "parts", parts=[("literal", "echo "), ("source", "reverse")]),
    _case("transform_strip_first", "source_transform_encoding", "parts", parts=[("literal", "echo "), ("source", "strip_first")]),

    # Multiple extents and syntax that is intentionally outside the bounded
    # single-extent witness contract.
    _case("extent_two_fields_colon", "multi_extent_matrix_out", "parts", parts=[("literal", "echo "), ("source", "direct"), ("literal", ":"), ("source", "direct")]),
    _case("extent_fixed_semicolon", "multi_extent_matrix_out", "parts", parts=[("literal", "echo "), ("source", "direct"), ("literal", ";fixed")]),
    _case("extent_fixed_vector_only", "multi_extent_matrix_out", "parts", parts=[("literal", "echo fixed;:;#")]),
    _case("extent_source_fixed_source", "multi_extent_matrix_out", "parts", parts=[("literal", "echo "), ("source", "direct"), ("literal", "X"), ("source", "direct")]),
    _case("extent_fixed_command_substitution", "multi_extent_matrix_out", "parts", parts=[("literal", "echo $("), ("source", "direct"), ("literal", ")")]),
    _case("extent_quote_then_fixed_control", "multi_extent_matrix_out", "parts", parts=[("literal", "echo '") , ("source", "direct"), ("literal", "';fixed")]),
)

FAMILIES = tuple(dict.fromkeys(row["family"] for row in CASES))
if len(CASES) != 48 or len(FAMILIES) != 8 or any(sum(row["family"] == family for row in CASES) != 6 for family in FAMILIES):
    raise RuntimeError("T06 benchmark must contain 48 cases, six per family")


PAYLOADS: tuple[tuple[str, bytes], ...] = (
    ("empty", b""),
    ("safe", b"SAFE"),
    ("alnum", b"ABC123"),
    ("semicolon_witness", b":;:;#"),
    ("newline_witness", b":\n:;#"),
    ("pipe_witness", b":|:;#"),
    ("ampersand_witness", b":&:;#"),
    ("backtick_witness", b"`:`"),
    ("dollar_substitution_witness", b"$(:)"),
    ("dollar_expansion_witness", b"$A"),
    ("output_redirect_witness", b">/dev/null"),
    ("input_redirect_witness", b"</dev/null"),
    ("ifs_witness", b"${IFS}:"),
    ("tab_witness", b"\t:"),
    ("single_breakout", b"SAFE';:;#"),
    ("double_breakout", b"SAFE\";:;#"),
    ("escaped_semicolon", b"\\;:;#"),
    ("percent_encoded_semicolon", b"%3b:;#"),
    ("x_encoded_semicolon", b"x:;#"),
    ("nul_before_witness", b"SAFE\x00;:;#"),
    ("long_safe", b"ABCDEFGH1234567890"),
    ("long_witness", b"ABCDEFGH:;:;#"),
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _visible(payload: bytes) -> bytes:
    return payload.split(b"\x00", 1)[0]


def _source_transform(payload: bytes, mode: str, limit: int | None = None) -> tuple[bytes, list[int | None]]:
    source = _visible(payload)
    if mode == "direct":
        return source, list(range(len(source)))
    if mode == "bounded":
        count = min(len(source), int(limit or 0))
        return source[:count], list(range(count))
    if mode == "alnum":
        pairs = [(byte, index) for index, byte in enumerate(source) if (48 <= byte <= 57) or (65 <= byte <= 90) or (97 <= byte <= 122) or byte == 95]
        return bytes(byte for byte, _ in pairs), [index for _, index in pairs]
    shell_meta = set(b";|&$`\n\t><")
    if mode == "replace_meta":
        return bytes(95 if byte in shell_meta else byte for byte in source), list(range(len(source)))
    if mode == "backslash_meta":
        output: list[int] = []
        origins: list[int | None] = []
        for index, byte in enumerate(source):
            if byte in shell_meta:
                output.append(92)
                origins.append(index)
            output.append(byte)
            origins.append(index)
        return bytes(output), origins
    if mode == "drop_space":
        pairs = [(byte, index) for index, byte in enumerate(source) if byte not in b" \t\n\r"]
        return bytes(byte for byte, _ in pairs), [index for _, index in pairs]
    if mode == "filename":
        pairs = [(byte, index) for index, byte in enumerate(source) if (48 <= byte <= 57) or (65 <= byte <= 90) or (97 <= byte <= 122) or byte in b"._/-"]
        return bytes(byte for byte, _ in pairs), [index for _, index in pairs]
    if mode == "percent_decode":
        output: list[int] = []
        origins: list[int | None] = []
        index = 0
        while index < len(source):
            if index + 2 < len(source) and source[index] == 37:
                try:
                    value = int(source[index + 1:index + 3].decode("ascii"), 16)
                except (UnicodeDecodeError, ValueError):
                    value = None
                if value is not None:
                    output.append(value)
                    origins.append(index)
                    index += 3
                    continue
            output.append(source[index])
            origins.append(index)
            index += 1
        return bytes(output), origins
    if mode == "x_to_semicolon":
        return bytes(59 if byte == 120 else byte for byte in source), list(range(len(source)))
    if mode == "uppercase":
        return bytes(byte - 32 if 97 <= byte <= 122 else byte for byte in source), list(range(len(source)))
    if mode == "hex_encode":
        output: list[int] = []
        origins: list[int | None] = []
        digits = b"0123456789ABCDEF"
        for index, byte in enumerate(source):
            output.extend((digits[byte >> 4], digits[byte & 15]))
            origins.extend((index, index))
        return bytes(output), origins
    if mode == "reverse":
        return source[::-1], list(reversed(range(len(source))))
    if mode == "strip_first":
        return source[1:], list(range(1, len(source)))
    raise ValueError(f"unsupported source transform: {mode}")


def _predicate(payload: bytes, name: str) -> bool:
    source = _visible(payload)
    if name == "first_A":
        return bool(source) and source[0] == ord("A")
    if name == "first_B":
        return bool(source) and source[0] == ord("B")
    if name == "contains_pipe":
        return b"|" in source
    if name == "odd_length":
        return len(source) % 2 == 1
    if name == "first_semicolon":
        return bool(source) and source[0] == ord(";")
    if name == "first_dollar":
        return bool(source) and source[0] == ord("$")
    if name == "length_lt_8":
        return len(source) < 8
    raise ValueError(f"unsupported branch predicate: {name}")


def _append_parts(parts: Sequence[Sequence[Any]], payload: bytes) -> tuple[bytes, list[int | None]]:
    output = bytearray()
    origins: list[int | None] = []
    for part in parts:
        if not part:
            continue
        if part[0] == "literal":
            literal = str(part[1]).encode("latin-1")
            output.extend(literal)
            origins.extend([None] * len(literal))
        elif part[0] == "source":
            transformed, transformed_origins = _source_transform(payload, str(part[1]), part[2] if len(part) > 2 else None)
            output.extend(transformed)
            origins.extend(transformed_origins)
        else:
            raise ValueError(f"unsupported part: {part!r}")
    return bytes(output), origins


def oracle_transform(case: Mapping[str, Any], payload: bytes) -> tuple[bytes, list[int | None]]:
    if case["kind"] == "parts":
        return _append_parts(case["parts"], payload)
    if case["kind"] == "branch":
        parts = case["then_parts"] if _predicate(payload, str(case["predicate"])) else case["else_parts"]
        return _append_parts(parts, payload)
    raise ValueError(f"unsupported case kind: {case.get('kind')}")


def _lexical_positions(command: bytes) -> tuple[list[str], list[bool]]:
    contexts: list[str] = []
    escaped: list[bool] = []
    state = "unquoted"
    pending_escape = False
    for byte in command:
        contexts.append(state)
        escaped.append(pending_escape)
        if pending_escape:
            pending_escape = False
            continue
        if byte == 92 and state != "single_quoted":
            pending_escape = True
            continue
        if byte == 39:
            if state == "unquoted":
                state = "single_quoted"
            elif state == "single_quoted":
                state = "unquoted"
        elif byte == 34:
            if state == "unquoted":
                state = "double_quoted"
            elif state == "double_quoted":
                state = "unquoted"
    return contexts, escaped


def _within_one_controlled_extent(origins: Sequence[int | None], start: int, end: int) -> bool:
    if start < 0 or end > len(origins) or start >= end:
        return False
    if any(origin is None for origin in origins[start:end]):
        return False
    left = start
    while left > 0 and origins[left - 1] is not None:
        left -= 1
    right = end
    while right < len(origins) and origins[right] is not None:
        right += 1
    return left <= start and end <= right


def oracle_matrix(command: bytes, origins: Sequence[int | None]) -> dict[str, Any]:
    contexts, escaped = _lexical_positions(command)
    decisions: list[dict[str, Any]] = []
    for vector_id, patterns, active_contexts in VECTOR_PATTERNS:
        match_info: dict[str, Any] | None = None
        for pattern in patterns:
            start = 0
            while True:
                index = command.find(pattern, start)
                if index < 0:
                    break
                start = index + 1
                context = contexts[index]
                if context not in active_contexts or escaped[index]:
                    continue
                if not _within_one_controlled_extent(origins, index, index + len(pattern)):
                    continue
                match_info = {
                    "pattern_hex": pattern.hex(),
                    "command_offset": index,
                    "controlled_offsets": list(range(index, index + len(pattern))),
                    "quote_context": context,
                }
                break
            if match_info is not None:
                break
        decisions.append({
            "vector_id": vector_id,
            "decision": "VECTOR_SAT" if match_info else "MATRIX_UNSAT",
            "match": match_info,
        })
    return {
        "matrix_complete": True,
        "expected_vector_ids": list(VECTOR_IDS),
        "decisions": decisions,
        "sat_vectors": [row["vector_id"] for row in decisions if row["decision"] == "VECTOR_SAT"],
        "unsat_vectors": [row["vector_id"] for row in decisions if row["decision"] == "MATRIX_UNSAT"],
        "oracle_scope": "bounded_single_extent_grammar_complete_patterns",
    }


def _c_quote(value: str) -> str:
    encoded = json.dumps(value, ensure_ascii=True)
    return encoded


def _c_emit_parts(parts: Sequence[Sequence[Any]], indent: str = "    ") -> list[str]:
    lines: list[str] = []
    for part in parts:
        if part[0] == "literal":
            lines.append(f"{indent}append_literal(out, &pos, cap, {_c_quote(str(part[1]))});")
        elif part[0] == "source":
            mode = str(part[1])
            mode_id = {
                "direct": 0,
                "bounded": 1,
                "alnum": 2,
                "replace_meta": 3,
                "backslash_meta": 4,
                "drop_space": 5,
                "filename": 6,
                "percent_decode": 7,
                "x_to_semicolon": 8,
                "uppercase": 9,
                "hex_encode": 10,
                "reverse": 11,
                "strip_first": 12,
            }[mode]
            limit = int(part[2]) if len(part) > 2 else 0
            lines.append(f"{indent}pos = append_source(out, pos, cap, in, n, {mode_id}, {limit});")
        else:
            raise ValueError(f"unsupported C part: {part!r}")
    return lines


def _c_predicate(name: str) -> str:
    return {
        "first_A": "visible > 0 && in[0] == 'A'",
        "first_B": "visible > 0 && in[0] == 'B'",
        "contains_pipe": "contains_byte(in, visible, '|')",
        "odd_length": "(visible % 2) == 1",
        "first_semicolon": "visible > 0 && in[0] == ';'",
        "first_dollar": "visible > 0 && in[0] == '$'",
        "length_lt_8": "visible < 8",
    }[name]


def _c_case_function(index: int, case: Mapping[str, Any]) -> str:
    lines = [f"static size_t tsds_case_{index:02d}(unsigned char *out, size_t cap, const unsigned char *in, size_t n) {{", "    size_t pos = 0;", "    size_t visible = cstring_length(in, n);"]
    if case["kind"] == "parts":
        lines.extend(_c_emit_parts(case["parts"]))
    else:
        lines.append(f"    if ({_c_predicate(str(case['predicate']))}) {{")
        lines.extend(_c_emit_parts(case["then_parts"], "        "))
        lines.append("    } else {")
        lines.extend(_c_emit_parts(case["else_parts"], "        "))
        lines.append("    }")
    lines.extend(["    return pos;", "}", ""])
    return "\n".join(lines)


def build_c_source() -> str:
    functions = "\n".join(_c_case_function(index, case) for index, case in enumerate(CASES))
    dispatch = "\n".join(f"        case {index}: length = tsds_case_{index:02d}(output, sizeof(output), input, input_length); break;" for index in range(len(CASES)))
    return f'''#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t cstring_length(const unsigned char *input, size_t length) {{
    size_t index = 0;
    while (index < length && input[index] != 0) ++index;
    return index;
}}

static void append_byte(unsigned char *out, size_t *position, size_t cap, unsigned char value) {{
    if (*position < cap) out[*position] = value;
    ++(*position);
}}

static void append_literal(unsigned char *out, size_t *position, size_t cap, const char *value) {{
    for (size_t index = 0; value[index] != '\\0'; ++index) append_byte(out, position, cap, (unsigned char)value[index]);
}}

static size_t source_meta(unsigned char value) {{
    return value == ';' || value == '|' || value == '&' || value == '$' || value == '`' || value == '\\n' || value == '\\t' || value == '>' || value == '<';
}}

static size_t contains_byte(const unsigned char *input, size_t length, unsigned char value) {{
    for (size_t index = 0; index < length; ++index) if (input[index] == value) return 1;
    return 0;
}}

static int hex_value(unsigned char value) {{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}}

static size_t append_source(unsigned char *out, size_t position, size_t cap, const unsigned char *input, size_t length, int mode, size_t limit) {{
    size_t visible = cstring_length(input, length);
    if (mode == 1 && visible > limit) visible = limit;
    if (mode == 12) {{
        for (size_t index = 1; index < visible; ++index) append_byte(out, &position, cap, input[index]);
        return position;
    }}
    if (mode == 11) {{
        for (size_t index = visible; index > 0; --index) append_byte(out, &position, cap, input[index - 1]);
        return position;
    }}
    if (mode == 10) {{
        const unsigned char digits[] = "0123456789ABCDEF";
        for (size_t index = 0; index < visible; ++index) {{
            append_byte(out, &position, cap, digits[input[index] >> 4]);
            append_byte(out, &position, cap, digits[input[index] & 15]);
        }}
        return position;
    }}
    for (size_t index = 0; index < visible; ++index) {{
        unsigned char value = input[index];
        if (mode == 2 && !((value >= '0' && value <= '9') || (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || value == '_')) continue;
        if (mode == 3 && source_meta(value)) value = '_';
        if (mode == 4 && source_meta(value)) append_byte(out, &position, cap, '\\\\');
        if (mode == 5 && (value == ' ' || value == '\\t' || value == '\\n' || value == '\\r')) continue;
        if (mode == 6 && !((value >= '0' && value <= '9') || (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || value == '.' || value == '_' || value == '/' || value == '-')) continue;
        if (mode == 7 && value == '%' && index + 2 < visible) {{
            int high = hex_value(input[index + 1]);
            int low = hex_value(input[index + 2]);
            if (high >= 0 && low >= 0) {{
                append_byte(out, &position, cap, (unsigned char)((high << 4) | low));
                index += 2;
                continue;
            }}
        }}
        if (mode == 8 && value == 'x') value = ';';
        if (mode == 9 && value >= 'a' && value <= 'z') value = (unsigned char)(value - ('a' - 'A'));
        append_byte(out, &position, cap, value);
    }}
    return position;
}}

{functions}
int main(void) {{
    unsigned int case_id = 0;
    unsigned int input_id = 0;
    char encoded[2048];
    unsigned char input[1024];
    unsigned char output[8192];
    while (scanf("%u %u %2047s", &case_id, &input_id, encoded) == 3) {{
        size_t input_length = 0;
        if (strcmp(encoded, "-") != 0) {{
            size_t encoded_length = strlen(encoded);
            if ((encoded_length & 1) != 0 || encoded_length / 2 > sizeof(input)) return 4;
            for (size_t index = 0; index < encoded_length; index += 2) {{
                int high = hex_value((unsigned char)encoded[index]);
                int low = hex_value((unsigned char)encoded[index + 1]);
                if (high < 0 || low < 0) return 5;
                input[input_length++] = (unsigned char)((high << 4) | low);
            }}
        }}
        size_t length = 0;
        switch (case_id) {{
{dispatch}
            default: return 6;
        }}
        if (length > sizeof(output)) return 7;
        printf("%u %u %zu ", case_id, input_id, length);
        for (size_t index = 0; index < length; ++index) printf("%02x", output[index]);
        putchar('\\n');
    }}
    return 0;
}}
'''


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_sha256sums(root: Path) -> None:
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            rows.append(f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}")
    (root / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")


def _run(command: Sequence[str], *, cwd: Path, input_text: str | None = None, timeout: int = 120) -> dict[str, Any]:
    started = time.monotonic()
    try:
        result = subprocess.run(command, cwd=str(cwd), input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        return {"command": list(command), "status": "UNAVAILABLE", "returncode": 127, "elapsed_sec": round(time.monotonic() - started, 6), "error": str(exc)}
    except subprocess.TimeoutExpired as exc:
        return {"command": list(command), "status": "TIMEOUT", "returncode": 124, "elapsed_sec": round(time.monotonic() - started, 6), "stdout": str(exc.stdout or ""), "stderr": str(exc.stderr or "")}
    return {"command": list(command), "status": "PASS" if result.returncode == 0 else "FAIL", "returncode": result.returncode, "elapsed_sec": round(time.monotonic() - started, 6), "stdout": result.stdout, "stderr": result.stderr}


def _build_and_execute(out_dir: Path, payload_rows: Sequence[tuple[int, int, bytes]]) -> tuple[dict[str, Any], dict[tuple[int, int], bytes]]:
    build_dir = out_dir / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    source_path = build_dir / "semantic_benchmark.c"
    binary_path = build_dir / ("semantic_benchmark.exe" if os.name == "nt" else "semantic_benchmark")
    source = build_c_source()
    source_path.write_text(source, encoding="utf-8")
    compiler = shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        receipt = {"status": "UNAVAILABLE", "reason": "gcc/clang not found", "source": str(source_path)}
        return receipt, {}
    compile_receipt = _run([compiler, "-std=c11", "-O0", "-Wall", "-Wextra", str(source_path), "-o", str(binary_path)], cwd=ROOT, timeout=120)
    receipt = {"compiler": compiler, "source": str(source_path), "binary": str(binary_path), "source_sha256": _sha256_bytes(source.encode()), "compile": compile_receipt}
    if compile_receipt["status"] != "PASS" or not binary_path.is_file():
        receipt["status"] = "FAIL"
        return receipt, {}
    lines = []
    for case_index, input_index, payload in payload_rows:
        encoded = payload.hex() or "-"
        lines.append(f"{case_index} {input_index} {encoded}")
    run_receipt = _run([str(binary_path)], cwd=ROOT, input_text="\n".join(lines) + "\n", timeout=180)
    receipt["run"] = {key: value for key, value in run_receipt.items() if key not in {"stdout", "stderr"}}
    receipt["status"] = run_receipt["status"]
    receipt["stdout_sha256"] = _sha256_bytes(str(run_receipt.get("stdout", "")).encode())
    receipt["stderr"] = str(run_receipt.get("stderr", ""))[:2000]
    observed: dict[tuple[int, int], bytes] = {}
    if run_receipt["status"] == "PASS":
        for line in str(run_receipt.get("stdout", "")).splitlines():
            fields = line.split()
            if len(fields) != 4:
                receipt["status"] = "FAIL"
                receipt.setdefault("parse_errors", []).append(line)
                continue
            case_index, input_index, length, encoded = fields
            try:
                key = (int(case_index), int(input_index))
                data = bytes.fromhex(encoded)
                if len(data) != int(length):
                    raise ValueError("length mismatch")
            except (TypeError, ValueError) as exc:
                receipt["status"] = "FAIL"
                receipt.setdefault("parse_errors", []).append(f"{line}: {exc}")
                continue
            observed[key] = data
        if len(observed) != len(payload_rows):
            receipt["status"] = "FAIL"
            receipt["observed_rows"] = len(observed)
            receipt["expected_rows"] = len(payload_rows)
    return receipt, observed


def _split_manifest() -> dict[str, Any]:
    by_family: dict[str, list[dict[str, Any]]] = {family: [] for family in FAMILIES}
    for index, case in enumerate(CASES):
        by_family[case["family"]].append({"index": index, "id": case["id"]})
    development: list[int] = []
    held_out: list[int] = []
    for family_index, family in enumerate(FAMILIES):
        rows = list(by_family[family])
        random.Random(SPLIT_SEED + family_index).shuffle(rows)
        held_out.extend(row["index"] for row in rows[:2])
        development.extend(row["index"] for row in rows[2:])
    return {
        "schema": "tsds-saner2027-semantic-split-v1",
        "seed": SPLIT_SEED,
        "unit": "distinct_source_program_case",
        "development_case_count": len(development),
        "held_out_case_count": len(held_out),
        "development_indices": sorted(development),
        "held_out_indices": sorted(held_out),
        "per_family": {
            family: {
                "case_count": 6,
                "development_count": sum(index in development for index in [row["index"] for row in by_family[family]]),
                "held_out_count": sum(index in held_out for index in [row["index"] for row in by_family[family]]),
                "indices": [row["index"] for row in by_family[family]],
            }
            for family in FAMILIES
        },
        "held_out_frozen_before_execution": True,
    }


def _source_domain_manifest() -> dict[str, Any]:
    return {
        "schema": SOURCE_DOMAIN_SCHEMA,
        "encoding": "raw bytes represented as lowercase hexadecimal; '-' is empty",
        "nul_semantics": "the original program treats the first NUL as the C-string terminator",
        "payload_count": len(PAYLOADS),
        "payloads": [{"input_id": index, "name": name, "hex": payload.hex()} for index, (name, payload) in enumerate(PAYLOADS)],
        "exhaustive_scope": "only this explicitly enumerated finite set of input byte strings; no claim outside it",
    }


def _case_digest(case: Mapping[str, Any]) -> str:
    return _sha256_bytes(_canonical(case).encode())


def _make_differential_rows(split: Mapping[str, Any], shells: Sequence[str]) -> list[dict[str, Any]]:
    # The generated commands are syntax-only probes.  No shell is invoked by
    # default; explicit --shell paths are required to collect parse results.
    contexts = (
        ("unquoted", lambda payload: b": " + payload + b" :"),
        ("single_quoted", lambda payload: b": '" + payload + b"'"),
        ("double_quoted", lambda payload: b': "' + payload + b'"'),
        ("escaped", lambda payload: b": \\" + payload),
        ("comment", lambda payload: b": " + payload + b" #TSDS"),
    )
    probes: list[tuple[str, bytes]] = []
    for vector_id, patterns, _ in VECTOR_PATTERNS:
        for payload in (patterns[0], b"SAFE", b"\\" + patterns[0]):
            for context_name, builder in contexts:
                probes.append((f"{vector_id}:{context_name}:{payload.hex()}", builder(payload)))
    # Deterministic expansion to exactly 1000 development probes.  Repeating
    # a command is allowed for dialect comparison, but each row keeps the
    # source probe identity and is not counted as a distinct source program.
    base = list(probes)
    for index in range(len(base), 1000):
        probes.append(base[index % len(base)])
    rows: list[dict[str, Any]] = []
    for index, (probe_id, command) in enumerate(probes[:1000]):
        row: dict[str, Any] = {
            "probe_index": index,
            "probe_id": probe_id,
            "command_sha256": _sha256_bytes(command),
            "command_hex": command.hex(),
            "development_only": True,
            "shell_results": [],
            "status": "NOT_RUN" if not shells else "RUN",
            "claim_boundary": "syntax differential probe only; no firmware or exploit claim",
        }
        for shell in shells:
            receipt = _run([shell, "-n", "-c", command.decode("latin-1")], cwd=ROOT, timeout=5)
            row["shell_results"].append({"shell": shell, "status": receipt["status"], "returncode": receipt["returncode"], "stderr": str(receipt.get("stderr", ""))[:300]})
        if not shells:
            row["not_run_reason"] = "no --shell path supplied; target shell availability is external"
            row["status"] = "NOT_RUN"
        else:
            statuses = [str(result.get("status") or "UNKNOWN") for result in row["shell_results"]]
            if any(status in {"TIMEOUT", "UNAVAILABLE"} for status in statuses):
                row["status"] = "INCOMPLETE"
            elif all(status == "PASS" for status in statuses):
                row["status"] = "PASS"
            else:
                row["status"] = "FAIL"
        rows.append(row)
    return rows


def run_benchmark(out_dir: Path, shells: Sequence[str] = ()) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    split = _split_manifest()
    _write_json(out_dir / "split_manifest.json", split)
    _write_json(out_dir / "source_domain.json", _source_domain_manifest())
    cases_dir = out_dir / "cases"
    cases_dir.mkdir(exist_ok=True)
    case_manifest: list[dict[str, Any]] = []
    for index, case in enumerate(CASES):
        record = {"index": index, **case, "case_sha256": _case_digest(case), "role": "held_out" if index in split["held_out_indices"] else "development"}
        _write_json(cases_dir / f"{index:02d}_{case['id']}.json", record)
        case_manifest.append(record)
    _write_json(out_dir / "case_manifest.json", {"schema": SCHEMA, "cases": case_manifest})

    payload_rows = [(case_index, input_index, payload) for case_index in range(len(CASES)) for input_index, (_, payload) in enumerate(PAYLOADS)]
    native_receipt, native_outputs = _build_and_execute(out_dir, payload_rows)
    _write_json(out_dir / "native_execution_receipt.json", native_receipt)

    oracle_rows: list[dict[str, Any]] = []
    parity_counts: Counter[str] = Counter()
    existential_by_case: list[dict[str, Any]] = []
    for case_index, case in enumerate(CASES):
        observations: list[dict[str, Any]] = []
        aggregate: dict[str, list[str]] = {vector_id: [] for vector_id in VECTOR_IDS}
        for input_index, (input_name, payload) in enumerate(PAYLOADS):
            command, origins = oracle_transform(case, payload)
            profile = oracle_matrix(command, origins)
            expected_native = command
            observed_native = native_outputs.get((case_index, input_index))
            parity = "MATCH" if observed_native == expected_native else ("NOT_RUN" if observed_native is None and native_receipt.get("status") in {"UNAVAILABLE", "FAIL"} else "MISMATCH")
            parity_counts[parity] += 1
            for vector_id in profile["sat_vectors"]:
                aggregate[vector_id].append(input_name)
            observation = {
                "case_index": case_index,
                "case_id": case["id"],
                "input_index": input_index,
                "input_name": input_name,
                "input_sha256": _sha256_bytes(payload),
                "command_sha256": _sha256_bytes(command),
                "command_hex": command.hex(),
                "source_extent_count": sum(1 for index, origin in enumerate(origins) if origin is not None and (index == 0 or origins[index - 1] is None)),
                "matrix": profile,
                "native_parity": parity,
                "fixed_input_observation": input_name == "safe",
                "claim_boundary": "finite-domain original-program output and bounded oracle only",
            }
            observations.append(observation)
            oracle_rows.append(observation)
        existential = {
            "case_index": case_index,
            "case_id": case["id"],
            "family": case["family"],
            "role": "held_out" if case_index in split["held_out_indices"] else "development",
            "finite_domain_size": len(PAYLOADS),
            "vector_results": [
                {"vector_id": vector_id, "decision": "VECTOR_SAT" if aggregate[vector_id] else "MATRIX_UNSAT", "witness_input_names": aggregate[vector_id]}
                for vector_id in VECTOR_IDS
            ],
            "claim_boundary": "existential only over the declared finite source domain and single-extent bounded patterns",
        }
        existential_by_case.append(existential)
        _write_json(cases_dir / f"{case_index:02d}_{case['id']}_observations.json", {"observations": observations, "existential": existential})

    with (out_dir / "oracle_receipts.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for row in oracle_rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")
    with (out_dir / "existential_profiles.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for row in existential_by_case:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")

    vector_counts: dict[str, Counter[str]] = {vector_id: Counter() for vector_id in VECTOR_IDS}
    for row in oracle_rows:
        for decision in row["matrix"]["decisions"]:
            vector_counts[decision["vector_id"]][decision["decision"]] += 1
    coverage = {
        "schema": "tsds-saner2027-vector-coverage-v1",
        "matrix_vector_count": len(VECTOR_IDS),
        "vector_ids": list(VECTOR_IDS),
        "per_vector_finite_observations": {vector_id: dict(sorted(counts.items())) for vector_id, counts in vector_counts.items()},
        "supported_bounded_patterns": {vector_id: [pattern.hex() for pattern in patterns] for vector_id, patterns, _ in VECTOR_PATTERNS},
        "out_of_scope_syntax": ["here_document", "arithmetic_expansion", "nested_substitution", "multi_extent_witness", "locale_dependent_word_splitting"],
        "quote_contexts": ["unquoted", "single_quoted", "double_quoted"],
        "matrix_spec_note": "The benchmark binds the public 11-vector IDs but uses an independent bounded oracle; it does not import evaluator predicates.",
    }
    _write_json(out_dir / "vector_coverage.json", coverage)

    differential_rows = _make_differential_rows(split, shells)
    with (out_dir / "differential_results.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for row in differential_rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")
    shell_status_counts: dict[str, dict[str, int]] = {}
    for row in differential_rows:
        for result in row.get("shell_results") or []:
            shell = str(result.get("shell") or "")
            if not shell:
                continue
            counts = Counter(shell_status_counts.setdefault(shell, {}))
            counts[str(result.get("status") or "UNKNOWN")] += 1
            shell_status_counts[shell] = dict(sorted(counts.items()))
    differential_summary = {
        "schema": "tsds-shell-differential-probes-v1",
        "probe_count": len(differential_rows),
        "shells_requested": list(shells),
        "status_counts": dict(sorted(Counter(row["status"] for row in differential_rows).items())),
        "shell_status_counts": shell_status_counts,
        "claim_boundary": "syntax-only differential probes; NOT_RUN is preserved when no target shell is supplied",
    }
    _write_json(out_dir / "differential_summary.json", differential_summary)

    parity_summary = dict(sorted(parity_counts.items()))
    summary = {
        "schema": SCHEMA,
        "benchmark_script_sha256": _sha256_file(Path(__file__).resolve()),
        "case_count": len(CASES),
        "family_count": len(FAMILIES),
        "cases_per_family": 6,
        "development_case_count": split["development_case_count"],
        "held_out_case_count": split["held_out_case_count"],
        "payload_count": len(PAYLOADS),
        "native_rows_expected": len(payload_rows),
        "native_execution_status": native_receipt.get("status"),
        "oracle_rows": len(oracle_rows),
        "native_oracle_parity": parity_summary,
        "parity_pass": parity_counts.get("MISMATCH", 0) == 0 and parity_counts.get("NOT_RUN", 0) == 0,
        "existential_profile_count": len(existential_by_case),
        "differential_probe_count": len(differential_rows),
        "differential_status_counts": differential_summary["status_counts"],
        "held_out_not_used_for_tuning": True,
        "claim_boundary": (
            "Independent finite-domain semantic calibration. Native C execution and the reference oracle cover only the declared input set; "
            "the benchmark is not firmware ground truth, candidate-wide accuracy, or device exploitability."
        ),
    }
    _write_json(out_dir / "summary.json", summary)
    (out_dir / "README.md").write_text(
        "# T06 independent semantic benchmark\n\n"
        + summary["claim_boundary"]
        + "\n\n"
        + f"- Cases: `{summary['case_count']}` distinct source programs across `{summary['family_count']}` families.\n"
        + f"- Split: `{summary['development_case_count']}` development and `{summary['held_out_case_count']}` held out.\n"
        + f"- Finite source inputs per case: `{summary['payload_count']}`.\n"
        + f"- Native/oracle rows: `{summary['oracle_rows']}`; parity: `{parity_summary}`.\n"
        + f"- Shell differential probes: `{summary['differential_probe_count']}`; statuses: `{summary['differential_status_counts']}`.\n"
        + "- A fixed-input observation is recorded separately and is never promoted to an existential negative.\n"
        + "- Unsupported syntax is listed in `vector_coverage.json`; it is not silently treated as UNSAT.\n",
        encoding="utf-8",
    )
    _write_sha256sums(out_dir)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, default=Path("experiment_reports/saner2027_remediation_20260913_t00_t01/T06_semantic_benchmark"))
    parser.add_argument("--shell", action="append", default=[], help="Optional shell path for syntax-only -n probes; may be repeated")
    args = parser.parse_args()
    output = args.out_dir.resolve()
    if output.exists() and any(output.iterdir()):
        print(f"refusing to overwrite non-empty output: {output}", file=sys.stderr)
        return 2
    summary = run_benchmark(output, tuple(args.shell))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["native_execution_status"] == "PASS" and summary["parity_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
