from __future__ import annotations

import asyncio
import functools
import platform
import socket
import typing


def log_exceptions(msg="unhandled exception in {__func__}"):
    """
    decorator that will catch all exceptions in methods and coroutine methods
    and log them with self.log

    msg will be formatted with __func__ as the called function's __qualname__ plus any
    passed arguments
    """

    def decorator(f):
        if asyncio.iscoroutinefunction(f):

            @functools.wraps(f)
            async def wrapper(self, *args, **kwargs):
                try:
                    return await f(self, *args, **kwargs)
                except Exception:
                    self.log.exception(
                        msg.format(*args, __func__=f.__qualname__, **kwargs)
                    )

        else:

            @functools.wraps(f)
            def wrapper(self, *args, **kwargs):
                try:
                    return f(self, *args, **kwargs)
                except Exception:
                    self.log.exception(
                        msg.format(*args, __func__=f.__qualname__, **kwargs)
                    )

        return wrapper

    return decorator


async def getfirstaddrinfo(
    host, port, family=0, type=0, proto=0, sock=None, flags=0, loop=None
):
    """
    retrieve sockaddr for host/port pair with given family, type, proto settings.
    return first sockaddr. raises socket.gaierror if no result was returned.
    """
    if sock is not None:
        if family != 0 or type != 0 or proto != 0:
            raise ValueError(
                "family/type/proto and sock cannot be specified at the same time"
            )
        family = sock.family
        type = sock.type
        proto = sock.proto
    if loop is None:  # pragma: nobranch
        loop = asyncio.get_event_loop()

    # QNX fails when supplying a numeric port to getaddrinfo
    # workaround: supply no port and inject it in the results instead
    # see https://github.com/afflux/pysomeip/issues/13
    no_port_in_gai = platform.system() == "QNX"
    lookup_port = None if no_port_in_gai else port

    result = await loop.getaddrinfo(
        host, lookup_port, family=family, type=type, proto=proto, flags=flags
    )

    if not result:  # pragma: nocover
        raise socket.gaierror(
            socket.EAI_NODATA, f"no address info found for {host}:{port}"
        )

    if no_port_in_gai:  # pragma: nocover
        result = result[:1] + (port,) + result[2:]

    return result[0]


T = typing.TypeVar("T")


async def wait_cancelled(task: asyncio.Task[T]) -> typing.Optional[T]:
    # I'd go with try: await task; except asyncio.CancelledError, but this can not
    # discern between task raising cancelled or this current task being cancelled.
    await asyncio.gather(task, return_exceptions=True)
    assert task.done()
    if task.cancelled():
        return None
    return task.result()
