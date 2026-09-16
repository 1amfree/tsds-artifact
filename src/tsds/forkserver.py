"""POSIX copy-on-write worker support for preloaded TSDS analyses."""

from __future__ import annotations

import multiprocessing
import os
import time
import traceback
from dataclasses import asdict, dataclass
from typing import Any, Callable


FORKSERVER_SCHEMA = "tsds-preloaded-fork-worker-v1"


@dataclass(frozen=True)
class ForkExecutionResult:
    ok: bool
    payload: Any
    error: str | None
    traceback: str | None
    exit_code: int | None
    timed_out: bool
    elapsed_sec: float
    backend: str
    schema: str = FORKSERVER_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def fork_available() -> bool:
    return os.name == "posix" and "fork" in multiprocessing.get_all_start_methods()


def _child_entry(
    connection: Any,
    worker: Callable[[Any], Any],
    payload: Any,
) -> None:
    try:
        value = worker(payload)
        connection.send({"ok": True, "payload": value, "error": None, "traceback": None})
    except MemoryError:
        try:
            connection.send(
                {
                    "ok": False,
                    "payload": None,
                    "error": "MemoryError",
                    "traceback": traceback.format_exc(),
                }
            )
        finally:
            raise
    except BaseException as error:  # child boundary must serialize all failures
        connection.send(
            {
                "ok": False,
                "payload": None,
                "error": f"{type(error).__name__}: {error}",
                "traceback": traceback.format_exc(),
            }
        )
    finally:
        connection.close()


def run_forked_json(
    worker: Callable[[Any], Any],
    payload: Any,
    *,
    timeout_sec: float,
) -> ForkExecutionResult:
    """Execute a callable in a fork child inheriting the parent's preloads."""

    if not fork_available():
        raise RuntimeError("POSIX fork backend is unavailable")
    started = time.monotonic()
    context = multiprocessing.get_context("fork")
    parent_connection, child_connection = context.Pipe(duplex=False)
    process = context.Process(
        target=_child_entry,
        args=(child_connection, worker, payload),
        daemon=False,
    )
    process.start()
    child_connection.close()
    deadline = started + max(0.001, float(timeout_sec))
    message = None
    # Drain the pipe before joining the child.  A full provenance artifact can
    # exceed a platform pipe buffer; joining first would leave the child blocked
    # in ``send`` while the parent waits for it to exit.
    while time.monotonic() < deadline:
        if parent_connection.poll(0.05):
            message = parent_connection.recv()
            break
        if not process.is_alive():
            break
    if message is None and parent_connection.poll(0.0):
        message = parent_connection.recv()
    timed_out = message is None and process.is_alive()
    if timed_out:
        process.terminate()
        process.join(5.0)
    else:
        process.join(max(0.001, deadline - time.monotonic()))
        if message is None and parent_connection.poll(0.2):
            message = parent_connection.recv()
    parent_connection.close()
    elapsed = round(time.monotonic() - started, 6)
    if timed_out:
        return ForkExecutionResult(
            ok=False,
            payload=None,
            error="timeout",
            traceback=None,
            exit_code=process.exitcode,
            timed_out=True,
            elapsed_sec=elapsed,
            backend="fork",
        )
    if message is None:
        return ForkExecutionResult(
            ok=False,
            payload=None,
            error="child exited without a result",
            traceback=None,
            exit_code=process.exitcode,
            timed_out=False,
            elapsed_sec=elapsed,
            backend="fork",
        )
    return ForkExecutionResult(
        ok=bool(message.get("ok")),
        payload=message.get("payload"),
        error=message.get("error"),
        traceback=message.get("traceback"),
        exit_code=process.exitcode,
        timed_out=False,
        elapsed_sec=elapsed,
        backend="fork",
    )
