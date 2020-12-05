import asyncio
import logging
import socket
import unittest
import unittest.mock

import someip.utils as utils

logging.captureWarnings(True)
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("asyncio").setLevel(logging.WARNING)


class TestWait(unittest.IsolatedAsyncioTestCase):
    async def test_wait_cancelled(self):
        sentinel = object()
        event = asyncio.Event()

        async def f():
            await event.wait()
            return sentinel

        task = asyncio.create_task(f())
        await asyncio.sleep(0.001)
        task.cancel()

        result = await utils.wait_cancelled(task)

        self.assertIsNone(result)

    async def test_wait_caught(self):
        sentinel = object()
        event = asyncio.Event()

        async def f():
            try:
                await event.wait()
                return True
            except asyncio.CancelledError:
                return sentinel

        task = asyncio.create_task(f())
        await asyncio.sleep(0.001)
        task.cancel()

        result = await utils.wait_cancelled(task)

        self.assertEqual(result, sentinel)

    async def test_exception(self):
        class Sentinel(BaseException):
            pass

        async def f():
            try:
                raise Sentinel
            except asyncio.CancelledError:
                return None

        task = asyncio.create_task(f())
        await asyncio.sleep(0.001)
        task.cancel()

        with self.assertRaises(Sentinel):
            await utils.wait_cancelled(task)


class TestGAI(unittest.IsolatedAsyncioTestCase):
    async def test_lo4(self):
        result = await asyncio.wait_for(
            utils.getfirstaddrinfo(
                None,
                1234,
                family=socket.AF_INET,
                type=socket.SOCK_DGRAM,
                proto=socket.IPPROTO_UDP,
                flags=socket.AI_PASSIVE | socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
            ),
            0.5,
        )
        self.assertEqual(result[0], socket.AF_INET)
        self.assertEqual(result[1], socket.SOCK_DGRAM)
        self.assertEqual(result[2], socket.IPPROTO_UDP)
        self.assertEqual(result[4], ("0.0.0.0", 1234))

    async def test_lo6(self):
        result = await asyncio.wait_for(
            utils.getfirstaddrinfo(
                None,
                1234,
                family=socket.AF_INET6,
                type=socket.SOCK_DGRAM,
                proto=socket.IPPROTO_UDP,
                flags=socket.AI_PASSIVE | socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
            ),
            0.5,
        )
        self.assertEqual(result[0], socket.AF_INET6)
        self.assertEqual(result[1], socket.SOCK_DGRAM)
        self.assertEqual(result[2], socket.IPPROTO_UDP)
        self.assertEqual(result[4], ("::", 1234, 0, 0))

    async def test_lo4_sock(self):
        sock = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_DGRAM,
            proto=socket.IPPROTO_UDP,
        )
        try:
            result = await asyncio.wait_for(
                utils.getfirstaddrinfo(
                    None,
                    1234,
                    sock=sock,
                    flags=socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
                ),
                0.5,
            )
            self.assertEqual(result[0], socket.AF_INET)
            self.assertEqual(result[1], socket.SOCK_DGRAM)
            self.assertEqual(result[2], socket.IPPROTO_UDP)
            self.assertEqual(result[4], ("127.0.0.1", 1234))
        finally:
            sock.close()

    async def test_lo6_sock(self):
        sock = socket.socket(
            family=socket.AF_INET6,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
        try:
            result = await asyncio.wait_for(
                utils.getfirstaddrinfo(
                    None,
                    1234,
                    sock=sock,
                    flags=socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
                ),
                0.5,
            )
            self.assertEqual(result[0], socket.AF_INET6)
            self.assertEqual(result[1], socket.SOCK_STREAM)
            self.assertEqual(result[2], socket.IPPROTO_TCP)
            self.assertEqual(result[4], ("::1", 1234, 0, 0))
        finally:
            sock.close()

    async def test_unknown(self):
        with self.assertRaises(socket.gaierror):
            await asyncio.wait_for(
                utils.getfirstaddrinfo(
                    "unknown.example.org",
                    1234,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                    flags=socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
                ),
                0.5,
            )

    async def test_flags_and_socket(self):
        sock = socket.socket(
            family=socket.AF_INET6,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
        try:
            with self.assertRaises(ValueError):
                await asyncio.wait_for(
                    utils.getfirstaddrinfo(
                        None,
                        1234,
                        sock=sock,
                        type=socket.SOCK_STREAM,
                        proto=socket.IPPROTO_TCP,
                        flags=socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
                    ),
                    0.5,
                )
        finally:
            sock.close()


class TestLogDecorator(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.log = logging.getLogger("TESTCASE")

    @utils.log_exceptions(msg="unhandled {__func__}")
    def func(self, i):
        return 2 / i

    @utils.log_exceptions(msg="unhandled {__func__}")
    async def afunc(self, i):
        await asyncio.sleep(0)
        return 2 / i

    def test_func_ok(self):
        self.assertEqual(self.func(2), 1)

    def test_func_raised(self):
        with self.assertLogs(self.log, "ERROR") as cm:
            self.func(0)
        self.assertEqual(len(cm.output), 1)
        self.assertTrue(
            cm.output[0].startswith(
                f"ERROR:TESTCASE:unhandled {self.__class__.__name__}.func\n"
            ),
        )

    async def test_async_func_ok(self):
        self.assertEqual(await self.afunc(2), 1)

    async def test_async_func_raised(self):
        with self.assertLogs(self.log, "ERROR") as cm:
            await self.afunc(0)
        self.assertEqual(len(cm.output), 1)
        self.assertTrue(
            cm.output[0].startswith(
                f"ERROR:TESTCASE:unhandled {self.__class__.__name__}.afunc\n"
            ),
        )


if __name__ == "__main__":
    unittest.main()
