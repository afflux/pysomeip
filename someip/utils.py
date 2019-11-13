import asyncio
import functools


def log_exceptions(msg='unhandled exception in {__func__}'):
    '''
    decorator that will catch all exceptions in methods and coroutine methods
    and log them with self.log

    msg will be formatted with __func__ as the called function's __qualname__ plus any passed
    arguments
    '''
    def decorator(f):
        if asyncio.iscoroutinefunction(f):
            @functools.wraps(f)
            async def wrapper(self, *args, **kwargs):
                try:
                    return await f(self, *args, **kwargs)
                except Exception:
                    self.log.exception(msg.format(__func__=f.__qualname__, *args, **kwargs))
        else:
            @functools.wraps(f)
            def wrapper(self, *args, **kwargs):
                try:
                    return f(self, *args, **kwargs)
                except Exception:
                    self.log.exception(msg.format(__func__=f.__qualname__, *args, **kwargs))
        return wrapper
    return decorator
