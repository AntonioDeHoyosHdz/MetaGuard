"""Run the injected, bounded outbox dispatcher independently of file maintenance."""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from contextlib import suppress

_LOGGER = logging.getLogger(__name__)
_DISPATCH_INTERVAL_SECONDS = 5


async def run_security_alert_dispatch_loop(
    dispatch: Callable[[], object],
    *,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> None:
    """Allow an already claimed bounded batch to settle during orderly shutdown."""
    while True:
        work = asyncio.create_task(asyncio.to_thread(dispatch))
        try:
            await asyncio.shield(work)
        except asyncio.CancelledError:
            with suppress(Exception):
                await work
            raise
        except Exception:
            _LOGGER.warning("Scheduled security alert dispatch failed.")
        await sleep(_DISPATCH_INTERVAL_SECONDS)
