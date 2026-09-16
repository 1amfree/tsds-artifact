"""Dependency-free replay of a declared source-to-sink byte trace.

This module is an admission aid for conditioned reconstruction.  It replays a
small, explicit byte-transform trace and checks the resulting C-string bytes
and source offsets against a producer-supplied expectation.  A passing replay
shows that the serialized trace is internally source-realizable; it does not
prove that the target binary executed the trace or that a firmware input can
reach it.  Those stronger claims require an instrumented original program.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

from .reconciliation_link import validate_reconciliation_link


SOURCE_REPLAY_SCHEMA = "tsds-source-realizability-replay-v1"
_HEX_DIGITS = b"0123456789ABCDEF"


class SourceReplayError(ValueError):
    """Malformed trace or unsupported operation."""


class UnsupportedTraceOperation(SourceReplayError):
    """The trace uses an operation outside this bounded replay contract."""


def _bytes_from_hex(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise SourceReplayError(f"{field}_must_be_even_length_hex")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise SourceReplayError(f"{field}_invalid_hex") from exc


def _visible_cstring(value: bytes) -> bytes:
    return value.split(b"\x00", 1)[0]


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise SourceReplayError(f"{field}_invalid_integer") from exc
    if result < minimum:
        raise SourceReplayError(f"{field}_below_minimum")
    return result


def _slice_with_origins(
    value: bytes,
    origins: Sequence[int | None],
    start: int,
    length: int | None,
) -> tuple[bytes, list[int | None]]:
    if len(value) != len(origins):
        raise SourceReplayError("value_origin_length_mismatch")
    end = len(value) if length is None else min(len(value), start + length)
    if start > len(value):
        return b"", []
    return value[start:end], list(origins[start:end])


def _input_for_step(step: Mapping[str, Any], values: Mapping[str, tuple[bytes, list[int | None]]]) -> tuple[bytes, list[int | None]]:
    step_id = str(step.get("input_step") or "")
    if not step_id or step_id not in values:
        raise SourceReplayError("input_step_missing_or_not_preceding")
    value, origins = values[step_id]
    return bytes(value), list(origins)


def _concat_parts(
    parts: Any,
    values: Mapping[str, tuple[bytes, list[int | None]]],
) -> tuple[bytes, list[int | None]]:
    if not isinstance(parts, list) or not parts:
        raise SourceReplayError("concat_parts_missing_or_empty")
    output = bytearray()
    origins: list[int | None] = []
    for index, part in enumerate(parts):
        if not isinstance(part, Mapping):
            raise SourceReplayError(f"concat_part_{index}_not_an_object")
        kind = str(part.get("kind") or "")
        if kind == "literal":
            value = _bytes_from_hex(part.get("bytes_hex"), f"concat_part_{index}")
            part_origins = [None] * len(value)
        elif kind == "step":
            step_id = str(part.get("step_id") or "")
            if not step_id or step_id not in values:
                raise SourceReplayError(f"concat_part_{index}_unknown_step")
            value, part_origins = values[step_id]
        else:
            raise SourceReplayError(f"concat_part_{index}_invalid_kind")
        output.extend(value)
        origins.extend(part_origins)
    return bytes(output), origins


def _evaluate_step(
    step: Mapping[str, Any],
    source: bytes,
    values: Mapping[str, tuple[bytes, list[int | None]]],
    source_variable: str,
) -> tuple[bytes, list[int | None]]:
    operation = str(step.get("operation") or "")
    if operation == "source":
        declared = str(step.get("source_variable") or source_variable)
        if declared != source_variable:
            raise SourceReplayError("source_variable_mismatch")
        visible = _visible_cstring(source)
        return visible, list(range(len(visible)))
    if operation == "literal":
        value = _bytes_from_hex(step.get("bytes_hex"), "literal_bytes")
        return value, [None] * len(value)
    if operation in {"copy", "truncate"}:
        value, origins = _input_for_step(step, values)
        start = _integer(step.get("start", 0), "copy_start")
        length = step.get("length")
        length_value = None if length is None else _integer(length, "copy_length")
        return _slice_with_origins(value, origins, start, length_value)
    if operation == "concat":
        return _concat_parts(step.get("parts"), values)
    if operation == "replace_byte":
        value, origins = _input_for_step(step, values)
        from_byte = _integer(step.get("from"), "replace_from", minimum=0)
        to_byte = _integer(step.get("to"), "replace_to", minimum=0)
        if from_byte > 255 or to_byte > 255:
            raise SourceReplayError("replace_byte_out_of_range")
        return bytes(to_byte if byte == from_byte else byte for byte in value), origins
    if operation == "percent_decode":
        value, input_origins = _input_for_step(step, values)
        output = bytearray()
        origins: list[int | None] = []
        index = 0
        while index < len(value):
            if index + 2 < len(value) and value[index] == ord("%"):
                try:
                    decoded = int(value[index + 1:index + 3].decode("ascii"), 16)
                except (UnicodeDecodeError, ValueError):
                    decoded = None
                if decoded is not None:
                    output.append(decoded)
                    origins.append(input_origins[index])
                    index += 3
                    continue
            output.append(value[index])
            origins.append(input_origins[index])
            index += 1
        return bytes(output), origins
    if operation == "hex_encode":
        value, input_origins = _input_for_step(step, values)
        output = bytearray()
        origins: list[int | None] = []
        for byte, origin in zip(value, input_origins):
            output.extend((_HEX_DIGITS[byte >> 4], _HEX_DIGITS[byte & 15]))
            origins.extend((origin, origin))
        return bytes(output), origins
    if operation == "reverse":
        value, origins = _input_for_step(step, values)
        return value[::-1], list(reversed(origins))
    raise UnsupportedTraceOperation(f"unsupported_operation:{operation or 'missing'}")


def replay_source_trace(trace: Mapping[str, Any] | None) -> dict[str, Any]:
    """Replay a bounded source-to-sink trace and compare declared expectations."""

    base = {
        "schema": "tsds-source-realizability-result-v1",
        "status": "INVALID",
        "source_realizable": False,
        "sink_bytes_hex": None,
        "mapping": [],
        "reasons": [],
        "claim_boundary": (
            "PASS means that the serialized byte trace reproduces the declared "
            "sink bytes and offsets. It does not prove binary execution, input "
            "reachability, or device-level exploitability."
        ),
    }
    if not isinstance(trace, Mapping):
        base["reasons"] = ["trace_missing_or_not_an_object"]
        return base
    if trace.get("schema") != SOURCE_REPLAY_SCHEMA:
        base["reasons"] = ["unsupported_source_replay_schema"]
        return base
    source_variable = str(trace.get("source_variable") or "")
    if not source_variable:
        base["reasons"] = ["source_variable_missing"]
        return base
    try:
        source = _bytes_from_hex(trace.get("source_bytes_hex"), "source_bytes")
        steps = trace.get("steps")
        if not isinstance(steps, list) or not steps:
            raise SourceReplayError("steps_missing_or_empty")
        values: dict[str, tuple[bytes, list[int | None]]] = {}
        for index, step in enumerate(steps):
            if not isinstance(step, Mapping):
                raise SourceReplayError(f"step_{index}_not_an_object")
            step_id = str(step.get("step_id") or "")
            if not step_id or step_id in values:
                raise SourceReplayError(f"step_{index}_invalid_or_duplicate_id")
            values[step_id] = _evaluate_step(step, source, values, source_variable)
        sink_step = str(trace.get("sink_step") or "")
        if not sink_step or sink_step not in values:
            raise SourceReplayError("sink_step_missing_or_unknown")
        raw_sink, raw_origins = values[sink_step]
        sink = _visible_cstring(raw_sink)
        origins = raw_origins[:len(sink)]
        mapping = [
            {"sink_offset": index, "source_offset": origin}
            for index, origin in enumerate(origins)
            if origin is not None
        ]
        base["sink_bytes_hex"] = sink.hex()
        base["mapping"] = mapping
        base["source_variable"] = source_variable
        base["sink_length"] = len(sink)
        base["source_length"] = len(_visible_cstring(source))
        expected_sink = trace.get("expected_sink_bytes_hex")
        expected_mapping = trace.get("expected_mapping")
        checks: dict[str, Any] = {
            "sink_bytes_bound": isinstance(expected_sink, str),
            "mapping_bound": isinstance(expected_mapping, list),
            "sink_bytes_match": None,
            "mapping_match": None,
        }
        if isinstance(expected_sink, str):
            expected_sink_bytes = _bytes_from_hex(expected_sink, "expected_sink_bytes")
            checks["sink_bytes_match"] = expected_sink_bytes == sink
        if isinstance(expected_mapping, list):
            normalized_expected = []
            for index, row in enumerate(expected_mapping):
                if not isinstance(row, Mapping):
                    raise SourceReplayError(f"expected_mapping_{index}_not_an_object")
                normalized_expected.append({
                    "sink_offset": _integer(row.get("sink_offset"), f"expected_mapping_{index}_sink_offset"),
                    "source_offset": _integer(row.get("source_offset"), f"expected_mapping_{index}_source_offset"),
                })
            checks["mapping_match"] = normalized_expected == mapping
        base["checks"] = checks
        if not checks["sink_bytes_bound"] or not checks["mapping_bound"]:
            base["status"] = "TRACE_ONLY"
            base["reasons"] = ["expected_sink_or_mapping_missing"]
        elif checks["sink_bytes_match"] and checks["mapping_match"]:
            base["status"] = "PASS"
            base["source_realizable"] = True
        else:
            base["status"] = "MISMATCH"
            base["reasons"] = [
                reason for reason, failed in (
                    ("expected_sink_bytes_mismatch", not checks["sink_bytes_match"]),
                    ("expected_mapping_mismatch", not checks["mapping_match"]),
                ) if failed
            ]
        return base
    except UnsupportedTraceOperation as exc:
        base["status"] = "UNSUPPORTED"
        base["reasons"] = [str(exc)]
        return base
    except SourceReplayError as exc:
        base["reasons"] = [str(exc)]
        return base


def replay_reconciliation_link(
    link: Mapping[str, Any] | None,
    trace: Mapping[str, Any] | None,
    *,
    record: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Require both serialized link consistency and exact trace replay."""

    replay = replay_source_trace(trace)
    issues = list(validate_reconciliation_link(link, record=record))
    if replay.get("status") != "PASS":
        issues.append("source_realizability_replay_not_pass")
    if isinstance(link, Mapping) and replay.get("status") == "PASS":
        # Bind the link to the replayed sink bytes, rather than accepting an
        # arbitrary well-formed digest.  This is a fixture/replay contract;
        # the program digest still requires an external binary check.
        sink_bytes_hex = replay.get("sink_bytes_hex")
        if isinstance(sink_bytes_hex, str):
            expected_sink_digest = hashlib.sha256(
                sink_bytes_hex.encode("ascii")
            ).hexdigest()
            if link.get("sink_snapshot_sha256") != expected_sink_digest:
                issues.append("source_realizability_sink_digest_does_not_match_replay")
        replay_source_variable = str(replay.get("source_variable") or "")
        source_variables = link.get("source_variables")
        if (
            replay_source_variable
            and isinstance(source_variables, list)
            and replay_source_variable not in {str(value) for value in source_variables}
        ):
            issues.append("source_realizability_source_variable_not_bound")
        link_rows = link.get("source_to_sink")
        replay_rows = replay.get("mapping")
        normalized_link = []
        mapping_parse_failed = False
        if isinstance(link_rows, list):
            for row in link_rows:
                if isinstance(row, Mapping):
                    try:
                        normalized_link.append({
                            "sink_offset": int(row.get("sink_offset")),
                            "source_offset": int(row.get("source_offset")),
                        })
                    except (TypeError, ValueError):
                        mapping_parse_failed = True
                else:
                    mapping_parse_failed = True
        else:
            mapping_parse_failed = True
        if mapping_parse_failed:
            issues.append("source_realizability_link_mapping_invalid")
        elif normalized_link != replay_rows:
            issues.append("source_realizability_mapping_does_not_match_link")
        cstring = link.get("sink_cstring")
        if isinstance(cstring, Mapping):
            try:
                if int(cstring.get("terminator_offset")) != int(replay.get("sink_length")):
                    issues.append("source_realizability_terminator_mismatch")
            except (TypeError, ValueError):
                issues.append("source_realizability_terminator_invalid")
    return {
        "schema": "tsds-source-realizability-admission-v1",
        "admitted": not issues,
        "issues": sorted(set(issues)),
        "replay": replay,
        "claim_boundary": (
            "Admission combines serialized link consistency with bounded byte "
            "trace replay; it remains weaker than execution of the original binary."
        ),
    }


__all__ = [
    "SOURCE_REPLAY_SCHEMA",
    "SourceReplayError",
    "replay_reconciliation_link",
    "replay_source_trace",
]
