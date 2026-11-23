"""App-lifetime maintenance for persisted retention and process-local file storage."""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from metaguard_api.file_routes import FileRuntime, _prune_metadata
from metaguard_api.maintenance import purge_maintenance_for_api

_DEFAULT_INTERVAL_SECONDS = 60
_MAX_INTERVAL_SECONDS = 3600
_logger = logging.getLogger(__name__)

PurgeRunner = Callable[[], int]
Clock = Callable[[], datetime]
Sleep = Callable[[float], Awaitable[None]]


def _utc_now() -> datetime:
    return datetime.now(UTC)


async def _run_blocking_to_completion[Result](
    operation: Callable[..., Result], *args: object, **kwargs: object
) -> Result:
    """Keep an in-flight thread joined when the awaiting task is cancelled."""
    operation_task = asyncio.create_task(asyncio.to_thread(operation, *args, **kwargs))
    try:
        return await asyncio.shield(operation_task)
    except asyncio.CancelledError as cancellation:
        while not operation_task.done():
            try:
                await asyncio.shield(operation_task)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        try:
            operation_task.result()
        except BaseException:
            # Shutdown cancellation is primary; retrieve any worker exception.
            pass
        raise cancellation


def _validate_interval(interval_seconds: int) -> None:
    if type(interval_seconds) is not int or not 1 <= interval_seconds <= _MAX_INTERVAL_SECONDS:
        raise ValueError("Maintenance interval must be an integer from 1 to 3600 seconds")


def _purge_process_store(file_runtime: FileRuntime, *, now: datetime) -> int:
    """Purge this API process's encrypted store and expired upload metadata."""
    deleted = file_runtime.store.purge_expired(now=now)
    with file_runtime._lock:
        _prune_metadata(file_runtime, now=now)
    return deleted


async def run_maintenance_cycle(
    purge_runner: PurgeRunner,
    file_runtime: FileRuntime | None,
    *,
    now: datetime | None,
) -> None:
    """Run persisted and process-local purges independently, with generic failures."""
    try:
        result = await _run_blocking_to_completion(purge_runner)
        if result != 0:
            _logger.warning("Scheduled persisted maintenance failed.")
    except Exception:
        # The runner may encounter secret, connection, or query errors; keep them out of logs.
        _logger.warning("Scheduled persisted maintenance failed.")

    if file_runtime is None:
        return
    if now is None:
        _logger.warning("Scheduled temporary-file maintenance clock failed.")
        return
    try:
        await _run_blocking_to_completion(_purge_process_store, file_runtime, now=now)
    except Exception:
        _logger.warning("Scheduled temporary-file maintenance failed.")


async def run_maintenance_loop(
    purge_runner: PurgeRunner = purge_maintenance_for_api,
    file_runtime: FileRuntime | None = None,
    *,
    interval_seconds: int = _DEFAULT_INTERVAL_SECONDS,
    clock: Clock = _utc_now,
    sleep: Sleep = asyncio.sleep,
) -> None:
    """Repeat app maintenance until cancelled during API lifespan shutdown.

    Every API worker runs the persisted purge independently; deleting only rows
    already expired is idempotent. The injected in-memory file store is always
    process-local and is purged only by the worker that owns that runtime.
    """
    _validate_interval(interval_seconds)
    while True:
        try:
            now = clock()
        except Exception:
            now = None
        await run_maintenance_cycle(purge_runner, file_runtime, now=now)
        await sleep(interval_seconds)
