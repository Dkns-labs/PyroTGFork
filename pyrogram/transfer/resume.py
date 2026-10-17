import asyncio
from typing import Awaitable, Callable, Optional, Tuple, Type, TypeVar

T = TypeVar("T")


async def with_resumes(
    attempt: Callable[[], Awaitable[T]],
    *,
    resumes: int,
    delay: float,
    cap: float,
    retryable: Tuple[Type[BaseException], ...],
    give_up: Optional[Callable[[], bool]] = None,
    on_retry: Optional[Callable[[int, float, BaseException], None]] = None,
) -> T:
    """Run ``attempt()``; when it fails with a ``retryable`` error, wait (doubling, up to ``cap``)
    and run it again, at most ``resumes`` more times.

    The pool already retries a request a few times within about two seconds. That rides out a lost
    connection but not a network blip of 10-30 s, which used to fail a whole multi-GB upload on its
    first exhausted part. This is the same back-off the downloader uses when it resumes.

    ``give_up`` is polled before every wait, so a transfer that was stopped (or already failed on
    another part) does not keep sleeping and retrying. Cancellation is never swallowed.
    """
    n = 0

    while True:
        try:
            return await attempt()
        except retryable as e:
            if n >= resumes or (give_up is not None and give_up()):
                raise

            n += 1
            wait = min(delay * 2 ** (n - 1), cap)

            if on_retry is not None:
                on_retry(n, wait, e)

            await asyncio.sleep(wait)
