# vim:foldmethod=marker:foldlevel=0
import asyncio
import ipaddress
import itertools
import logging
import os
import socket
import struct
import sys
import typing
import unittest
import unittest.mock
from dataclasses import replace

import someip.header as hdr
import someip.config as cfg
import someip.sd as sd

logging.captureWarnings(True)
logging.basicConfig(level=logging.DEBUG)

logging.getLogger("asyncio").setLevel(logging.WARNING)
logging.getLogger("someip").setLevel(logging.WARNING)


PRECISION = 0.4 if os.environ.get("CI") == "true" else 0.2  # in seconds


def ticks(n):
    return PRECISION * n


def setUpModule():
    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


# {{{ Utilities: pack_sd and _SendTiming
def pack_sd(entries, reboot=True, unicast=True, session_id=1):
    msg = hdr.SOMEIPSDHeader(
        flag_reboot=reboot,
        flag_unicast=unicast,
        entries=tuple(entries),
    ).assign_option_indexes()

    data = hdr.SOMEIPHeader(
        service_id=hdr.SD_SERVICE,
        method_id=hdr.SD_METHOD,
        client_id=0,
        session_id=session_id,
        interface_version=hdr.SD_INTERFACE_VERSION,
        message_type=hdr.SOMEIPMessageType.NOTIFICATION,
        payload=msg.build(),
    ).build()

    return data


class _SendTiming(unittest.TestCase):
    def setup_timing(self, *mocks):
        self.send_times: typing.Dict[unittest.mock.Mock, typing.List[float]] = {}

        for mock in mocks:
            self.send_times[mock] = []
            mock.side_effect = self.record_time(mock)

        self.t_start = asyncio.get_running_loop().time()

    def record_time(self, mock):
        def _mock_side_effect(*args, **kwargs):
            self.send_times[mock].append(asyncio.get_running_loop().time())
            return unittest.mock.DEFAULT

        return _mock_side_effect

    def reset_mock(self, reset_start=False):
        for mock, send_times in self.send_times.items():
            send_times.clear()
            mock.reset_mock()
        if reset_start:
            self.t_start = asyncio.get_running_loop().time()

    def assertTiming(self, *expected):  # noqa: N802
        tdiffs = {
            m: [t - self.t_start for t in times] for m, times in self.send_times.items()
        }

        # self.assertEqual(len(self.send_times), len(expected))
        for i, (expected_td, mock, expected_call) in enumerate(expected):
            actual_call = mock.call_args_list.pop(0)
            actual_td = tdiffs[mock].pop(0)
            self.assertEqual(actual_call, expected_call, msg=f"index {i} failed")
            self.assertLess(
                abs(ticks(expected_td) - actual_td),
                PRECISION,
                msg=f"{ticks(expected_td)=} {actual_td=}",
            )

        self.assertDictEqual(
            tdiffs, {m: [] for m in tdiffs.keys()}, msg="some calls were not asserted"
        )


async def settle():
    fut: asyncio.Future[None] = asyncio.Future()
    asyncio.get_event_loop().call_soon(fut.set_result, None)
    await fut


# }}}


class TestSD(unittest.IsolatedAsyncioTestCase):
    multi_addr = ("2001:db8::1", 30490, 0, 0)
    fake_addr = ("2001:db8::2", 30490, 0, 0)

    async def _test_endpoint(self, family, host):
        sock = None
        trsp, prot = await sd.SOMEIPDatagramProtocol.create_unicast_endpoint(
            local_addr=(host, 0),
        )
        try:
            prot.message_received = unittest.mock.Mock()
            local_sockname = trsp.get_extra_info("sockname")

            message = hdr.SOMEIPHeader(
                service_id=0xDEAD,
                method_id=0xBEEF,
                client_id=0xCCCC,
                session_id=0xDDDD,
                protocol_version=1,
                interface_version=2,
                message_type=hdr.SOMEIPMessageType.REQUEST_ACK,
                return_code=hdr.SOMEIPReturnCode.E_NOT_READY,
            )
            data = b"\xde\xad\xbe\xef\x00\x00\x00\x08\xcc\xcc\xdd\xdd\x01\x02\x40\x04"

            sock = socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            addrs = await asyncio.get_event_loop().getaddrinfo(
                host,
                0,
                family=sock.family,
                type=sock.type,
                proto=sock.proto,
                flags=socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
            )
            bind_addr = addrs[0][4]
            sock.bind(bind_addr)

            sock.sendto(data, local_sockname)
            sender_sockname = sock.getsockname()
            await asyncio.sleep(0.01)
            prot.message_received.assert_called_once_with(
                message, sender_sockname, False
            )

            prot.message_received.reset_mock()

            data = b"\xde\xad\xbe\xef\x00\x00\x00\x08\xcc\xcc\xdd\xdd\x00\x02\x40\x04"
            sock.sendto(data, local_sockname)

            with self.assertLogs("someip", level="ERROR"):
                await asyncio.sleep(0.01)
            prot.message_received.assert_not_called()
        finally:
            if sock:
                sock.close()
            trsp.close()

    async def test_endpoint_v6(self):
        await self._test_endpoint(socket.AF_INET6, "::1")

    async def test_endpoint_v4(self):
        await self._test_endpoint(socket.AF_INET, "127.0.0.1")

    async def test_send_session_id(self):
        entry = cfg.Service(service_id=0x1234).create_find_entry()

        prot = sd.ServiceDiscoveryProtocol(self.multi_addr)
        _mock = prot.transport = unittest.mock.Mock()

        # session_id wraps to 1 instead of 0
        r = itertools.chain(
            range(1, 0x10000),
            range(0x100001, 0x20000),
            range(0x200001, 0x20020),
        )

        for i in r:
            prot.send_sd([entry], self.fake_addr)
            _mock.sendto.assert_called_once_with(
                pack_sd((entry,), session_id=i & 0xFFFF, reboot=i < 0x10000),
                self.fake_addr,
            )
            _mock.reset_mock()

            if i < 0x10020:
                prot.send_sd([entry])
                _mock.sendto.assert_called_once_with(
                    pack_sd((entry,), session_id=i & 0xFFFF, reboot=i < 0x10000),
                    self.multi_addr,
                )
                _mock.reset_mock()

            if i % 64 == 0:
                # yield to event loop every couple iterations
                await settle()

    async def test_no_send_empty_sd(self):
        prot = sd.ServiceDiscoveryProtocol(self.multi_addr)
        _mock = prot.transport = unittest.mock.Mock()

        prot.send_sd([])

        _mock.assert_not_called()

    @unittest.mock.patch("someip.sd.ServiceAnnouncer", spec_set=True)
    @unittest.mock.patch("someip.sd.ServiceSubscriber", spec_set=True)
    @unittest.mock.patch("someip.sd.ServiceDiscover", spec_set=True)
    async def test_sd_connection_lost(self, discover, subscribe, announce):
        prot = sd.ServiceDiscoveryProtocol(self.multi_addr)

        await settle()

        self.assertEqual(discover().method_calls, [])
        self.assertEqual(subscribe().method_calls, [])
        self.assertEqual(announce().method_calls, [])

        sentinel = object()

        with self.assertLogs("someip.sd", "ERROR") as cm:
            prot.connection_lost(sentinel)
            await settle()
        self.assertTrue(any("connection lost" in msg for msg in cm.output))

        self.assertEqual(
            discover().method_calls, [unittest.mock.call.connection_lost(sentinel)]
        )
        self.assertEqual(
            subscribe().method_calls, [unittest.mock.call.connection_lost(sentinel)]
        )
        self.assertEqual(
            announce().method_calls, [unittest.mock.call.connection_lost(sentinel)]
        )

        discover().reset_mock()
        subscribe().reset_mock()
        announce().reset_mock()

        await settle()

        self.assertEqual(discover().method_calls, [])
        self.assertEqual(subscribe().method_calls, [])
        self.assertEqual(announce().method_calls, [])

    @unittest.mock.patch("someip.sd.ServiceAnnouncer", spec_set=True)
    @unittest.mock.patch("someip.sd.ServiceSubscriber", spec_set=True)
    @unittest.mock.patch("someip.sd.ServiceDiscover", spec_set=True)
    async def test_sd_reboot(self, discover, subscribe, announce):
        prot = sd.ServiceDiscoveryProtocol(self.multi_addr)

        prot.datagram_received(
            pack_sd((), session_id=1, reboot=True), self.fake_addr, multicast=True
        )
        await settle()

        self.assertEqual(discover().method_calls, [])
        self.assertEqual(subscribe().method_calls, [])
        self.assertEqual(announce().method_calls, [])

        prot.datagram_received(
            pack_sd((), session_id=2, reboot=True), self.fake_addr, multicast=True
        )
        await settle()

        self.assertEqual(discover().method_calls, [])
        self.assertEqual(subscribe().method_calls, [])
        self.assertEqual(announce().method_calls, [])

        prot.datagram_received(
            pack_sd((), session_id=1, reboot=False), self.fake_addr, multicast=True
        )
        await settle()

        self.assertEqual(discover().method_calls, [])
        self.assertEqual(subscribe().method_calls, [])
        self.assertEqual(announce().method_calls, [])

        prot.datagram_received(
            pack_sd((), session_id=2, reboot=True), self.fake_addr, multicast=True
        )
        await settle()

        self.assertEqual(
            discover().method_calls,
            [unittest.mock.call.reboot_detected(self.fake_addr)],
        )
        self.assertEqual(
            subscribe().method_calls,
            [unittest.mock.call.reboot_detected(self.fake_addr)],
        )
        self.assertEqual(
            announce().method_calls,
            [unittest.mock.call.reboot_detected(self.fake_addr)],
        )

        discover().reset_mock()
        subscribe().reset_mock()
        announce().reset_mock()

        prot.datagram_received(
            pack_sd((), session_id=1, reboot=False), self.fake_addr, multicast=True
        )
        await settle()

        self.assertEqual(discover().method_calls, [])
        self.assertEqual(subscribe().method_calls, [])
        self.assertEqual(announce().method_calls, [])

    @unittest.mock.patch("someip.sd.ServiceAnnouncer", spec_set=True)
    @unittest.mock.patch("someip.sd.ServiceSubscriber", spec_set=True)
    @unittest.mock.patch("someip.sd.ServiceDiscover", spec_set=True)
    async def test_sd_malformed(self, discover, subscribe, announce):
        prot = sd.ServiceDiscoveryProtocol(self.multi_addr)

        msg = hdr.SOMEIPHeader(
            service_id=hdr.SD_SERVICE,
            method_id=hdr.SD_METHOD,
            client_id=0,
            session_id=1,
            interface_version=hdr.SD_INTERFACE_VERSION,
            message_type=hdr.SOMEIPMessageType.NOTIFICATION,
            payload=b"deadbeef",
        )

        prot.sd_message_received = unittest.mock.Mock()

        with self.assertLogs("someip", "ERROR"):
            prot.datagram_received(msg.build(), self.fake_addr, multicast=False)

        prot.sd_message_received.assert_not_called()

        payload = (
            b"\x40\x00\x00\x00"
            b"\x00\x00\x00\x30"
            b"\x06\x00\x00\x00\x88\x99\x66\x77\xEE\x00\x00\x00\x00\x00\x00\x10"
            b"\x01\x00\x00\x00\x55\x66\x77\x88\x99\x00\x00\x00\xde\xad\xbe\xef"
            b"\x01\x00\x00\x00\x55\x67\x77\x88\x99\x00\x00\x00\xde\xad\xbe\xef"
            b"\x00\x00\x00\x00"
        )
        msg = replace(msg, payload=payload)

        with self.assertLogs("someip", "ERROR"):
            prot.datagram_received(
                replace(msg, service_id=0x1234).build(),
                self.fake_addr,
                multicast=False,
            )

        prot.sd_message_received.assert_not_called()

        with self.assertLogs("someip", "ERROR"):
            prot.datagram_received(
                replace(msg, method_id=0x1234).build(),
                self.fake_addr,
                multicast=False,
            )

        prot.sd_message_received.assert_not_called()

        with self.assertLogs("someip", "ERROR"):
            prot.datagram_received(
                replace(msg, interface_version=12).build(),
                self.fake_addr,
                multicast=False,
            )

        prot.sd_message_received.assert_not_called()

        with self.assertLogs("someip", "ERROR"):
            prot.datagram_received(
                replace(msg, message_type=hdr.SOMEIPMessageType.REQUEST).build(),
                self.fake_addr,
                multicast=False,
            )

        prot.sd_message_received.assert_not_called()

        with self.assertLogs("someip", "ERROR"):
            prot.datagram_received(
                replace(msg, return_code=hdr.SOMEIPReturnCode.E_NOT_OK).build(),
                self.fake_addr,
                multicast=False,
            )

        prot.sd_message_received.assert_not_called()

        self.assertEqual(discover().method_calls, [])
        self.assertEqual(subscribe().method_calls, [])
        self.assertEqual(announce().method_calls, [])

    @unittest.mock.patch("someip.sd.ServiceAnnouncer", spec_set=True)
    @unittest.mock.patch("someip.sd.ServiceSubscriber", spec_set=True)
    @unittest.mock.patch("someip.sd.ServiceDiscover", spec_set=True)
    async def test_sd_entries(self, discover, subscribe, announce):
        prot = sd.ServiceDiscoveryProtocol(self.multi_addr)

        find_entry = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.FindService,
            service_id=0x5566,
            instance_id=0xFFFF,
            major_version=0xFF,
            ttl=5,
            minver_or_counter=0xFFFFFFFF,
        )

        offer_entry = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.OfferService,
            service_id=0x1111,
            instance_id=0x2222,
            major_version=1,
            ttl=0,
            minver_or_counter=0xDEADBEEF,
            options_1=(
                hdr.IPv4EndpointOption(
                    address=ipaddress.IPv4Address("254.253.252.251"),
                    l4proto=hdr.L4Protocols.UDP,
                    port=65535,
                ),
            ),
        )

        subscribe_entry = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.Subscribe,
            service_id=0xAAAA,
            instance_id=0xBBBB,
            major_version=0xCC,
            minver_or_counter=0x23333,
            ttl=1,
            options_1=(
                hdr.IPv6EndpointOption(
                    ipaddress.IPv6Address("2001:db8::2"),
                    port=1,
                    l4proto=hdr.L4Protocols.UDP,
                ),
            ),
            options_2=(hdr.SOMEIPSDConfigOption(configs=(("foo", "bar"),)),),
        )

        entries = (
            find_entry,
            offer_entry,
            subscribe_entry,
        )

        prot.datagram_received(pack_sd(entries), self.fake_addr, multicast=False)
        await settle()

        self.assertEqual(subscribe().method_calls, [])
        self.assertEqual(
            discover().method_calls,
            [unittest.mock.call.handle_offer(offer_entry, self.fake_addr)],
        )
        self.assertCountEqual(
            announce().method_calls,
            [
                unittest.mock.call.handle_findservice(
                    find_entry, self.fake_addr, False, True
                ),
                unittest.mock.call.handle_subscribe(subscribe_entry, self.fake_addr),
            ],
        )

        discover().reset_mock()
        subscribe().reset_mock()
        announce().reset_mock()

        with self.assertLogs("someip.sd", "WARNING") as cm:
            prot.datagram_received(pack_sd(entries), self.fake_addr, multicast=True)
            await settle()
        self.assertTrue(any("received over multicast" in msg for msg in cm.output))

        self.assertEqual(subscribe().method_calls, [])
        self.assertEqual(
            discover().method_calls,
            [unittest.mock.call.handle_offer(offer_entry, self.fake_addr)],
        )
        self.assertEqual(
            announce().method_calls,
            [
                unittest.mock.call.handle_findservice(
                    find_entry, self.fake_addr, True, True
                ),
            ],
        )

    async def test_sd_multicast_bad_af(self):
        with self.assertRaises(ValueError):
            await sd.ServiceDiscoveryProtocol.create_endpoints(
                family=socket.AF_IPX,
                local_addr="127.0.0.1",
                multicast_addr="224.244.224.245",
                port=30490,
                multicast_interface="lo",
            )

    async def test_sd_multicast_bad_mc_addr(self):
        with self.assertRaises(ValueError):
            await sd.ServiceDiscoveryProtocol.create_endpoints(
                family=socket.AF_INET,
                local_addr="127.0.0.1",
                multicast_addr="127.0.0.1",
                port=30490,
                multicast_interface="lo",
            )

    async def test_sd_multicast_ipv6_missing_if(self):
        with self.assertRaises(ValueError):
            await sd.ServiceDiscoveryProtocol.create_endpoints(
                family=socket.AF_INET6,
                local_addr="::1",
                multicast_addr="ff02::dead:beef%lo",
                port=30490,
            )


# {{{ ServiceDiscover OfferService
class _BaseSDDiscoveryTest(unittest.IsolatedAsyncioTestCase):
    multi_addr = ("2001:db8::1", 30490, 0, 0)
    fake_addr = ("2001:db8::2", 30490, 0, 0)
    TTL = sd.TTL_FOREVER

    async def asyncSetUp(self):  # noqa: N802
        mock_sd = unittest.mock.Mock(spec_set=["timings", "log", "send_sd"])
        mock_sd.timings = sd.Timings()
        mock_sd.log = logging.getLogger("someip.sd")
        self._mock_send_sd = mock_sd.send_sd = unittest.mock.Mock()
        self.prot = sd.ServiceDiscover(mock_sd)

        self.offer_5566 = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.OfferService,
            service_id=0x5566,
            instance_id=0x7788,
            major_version=1,
            ttl=self.TTL,
            minver_or_counter=0xDEADBEEF,
            options_1=(
                hdr.IPv4EndpointOption(
                    address=ipaddress.IPv4Address("254.253.252.251"),
                    l4proto=hdr.L4Protocols.UDP,
                    port=65535,
                ),
            ),
        )
        self.offer_5567 = replace(self.offer_5566, service_id=0x5567)
        self.cfg_offer_5566 = cfg.Service.from_offer_entry(self.offer_5566)
        self.cfg_offer_5567 = cfg.Service.from_offer_entry(self.offer_5567)

        self.stop_offer_5566 = replace(self.offer_5566, ttl=0)

        self.mock = unittest.mock.Mock()
        self.mock_single = unittest.mock.Mock()
        self.prot.watch_all_services(self.mock)
        self.prot.watch_service(cfg.Service(service_id=0x5566), self.mock_single)

        self.prot.handle_offer(self.offer_5566, self.fake_addr)
        self.prot.handle_offer(self.offer_5567, self.fake_addr)
        await settle()

        self.assertEqual(
            self.mock.service_offered.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call(self.cfg_offer_5567, self.fake_addr),
            ],
        )

        self.mock_single.service_offered.assert_called_once_with(
            self.cfg_offer_5566, self.fake_addr
        )
        self.mock.service_stopped.assert_not_called()
        self.mock_single.service_stopped.assert_not_called()

        await settle()

        self.mock.reset_mock()
        self.mock_single.reset_mock()


class TestSDDiscoveryTTLForever(_BaseSDDiscoveryTest):
    TTL = sd.TTL_FOREVER

    async def test_sd_reboot_ttl_forever(self):
        self.prot.handle_offer(self.offer_5566, self.fake_addr)
        self.prot.handle_offer(self.offer_5567, self.fake_addr)
        await settle()

        self.assertEqual(self.mock.method_calls, [])
        self.assertEqual(self.mock_single.method_calls, [])

        self.prot.reboot_detected(self.fake_addr)
        await settle()
        self.prot.handle_offer(self.offer_5566, self.fake_addr)
        self.prot.handle_offer(self.offer_5567, self.fake_addr)
        await settle()

        self.assertCountEqual(
            self.mock.method_calls[:2],
            [
                unittest.mock.call.service_stopped(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call.service_stopped(self.cfg_offer_5567, self.fake_addr),
            ],
        )
        self.assertEqual(
            self.mock.method_calls[2:],
            [
                unittest.mock.call.service_offered(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call.service_offered(self.cfg_offer_5567, self.fake_addr),
            ],
        )

        self.assertEqual(
            self.mock_single.method_calls,
            [
                unittest.mock.call.service_stopped(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call.service_offered(self.cfg_offer_5566, self.fake_addr),
            ],
        )

        # send stopoffer, should reach listener
        self.mock.reset_mock()
        self.mock_single.reset_mock()

        self.prot.handle_offer(self.stop_offer_5566, self.fake_addr)
        self.prot.handle_offer(self.offer_5567, self.fake_addr)
        await settle()

        self.assertEqual(
            self.mock.method_calls,
            [unittest.mock.call.service_stopped(self.cfg_offer_5566, self.fake_addr)],
        )
        self.assertEqual(
            self.mock_single.method_calls,
            [unittest.mock.call.service_stopped(self.cfg_offer_5566, self.fake_addr)],
        )

    async def test_sd_disconnect(self):
        self.prot.connection_lost(None)

        await settle()

        self.assertCountEqual(
            self.mock.method_calls,
            [
                unittest.mock.call.service_stopped(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call.service_stopped(self.cfg_offer_5567, self.fake_addr),
            ],
        )
        self.assertEqual(
            self.mock_single.method_calls,
            [unittest.mock.call.service_stopped(self.cfg_offer_5566, self.fake_addr)],
        )

    async def test_sd_ignore(self):
        self.prot.stop_watch_all_services(self.mock)

        await settle()
        self.assertCountEqual(
            self.mock.method_calls,
            [
                unittest.mock.call.service_stopped(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call.service_stopped(self.cfg_offer_5567, self.fake_addr),
            ],
        )

        self.mock.reset_mock()

        offer_7777 = replace(self.offer_5566, service_id=0x7777)
        self.prot.handle_offer(offer_7777, self.fake_addr)

        await settle()

        self.assertEqual(self.mock.method_calls, [])

    async def test_watch_all_while_running(self):
        newmock = unittest.mock.Mock()
        self.prot.watch_all_services(newmock)
        await settle()

        self.assertEqual(
            newmock.service_offered.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call(self.cfg_offer_5567, self.fake_addr),
            ],
        )

        newmock.service_stopped.assert_not_called()

    async def test_stop_watch_all(self):
        self.prot.stop_watch_all_services(self.mock)
        await settle()

        self.assertEqual(
            self.mock.service_stopped.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call(self.cfg_offer_5567, self.fake_addr),
            ],
        )

        self.mock.reset_mock()

        offer_5568 = replace(self.offer_5566, service_id=0x5568)
        self.prot.handle_offer(offer_5568, self.fake_addr)
        await settle()

        self.assertEqual(self.mock.method_calls, [])

    async def test_stop_watch_single(self):
        self.prot.stop_watch_service(cfg.Service(service_id=0x5566), self.mock_single)
        await settle()

        self.assertEqual(
            self.mock_single.service_stopped.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566, self.fake_addr),
            ],
        )

        self.mock_single.reset_mock()

        # clear already known services to re-trigger callbacks
        self.prot.found_services.stop_all()
        await settle()
        self.assertEqual(self.mock_single.method_calls, [])

        # after found_services.stop_all(), new offer would trigger callbacks,
        # but the listener is removed
        self.prot.handle_offer(self.offer_5566, self.fake_addr)
        await settle()
        self.assertEqual(self.mock_single.method_calls, [])

    async def test_watch_while_running(self):
        self.prot.stop_watch_all_services(self.mock)
        await settle()

        newmock = unittest.mock.Mock()
        self.prot.watch_service(cfg.Service(service_id=0x5566), newmock)
        await settle()

        self.assertEqual(
            newmock.service_offered.call_args_list,
            [unittest.mock.call(self.cfg_offer_5566, self.fake_addr)],
        )

        newmock.service_stopped.assert_not_called()

        # 0x5567 was previously monitored from watch_all_services
        # TTL is forever, so it's still in the found_services list
        # so it will immediately trigger a service_offered callback
        newmock = unittest.mock.Mock()
        self.prot.watch_service(cfg.Service(service_id=0x5567), newmock)
        await settle()

        self.assertEqual(
            newmock.service_offered.call_args_list,
            [unittest.mock.call(self.cfg_offer_5567, self.fake_addr)],
        )

        newmock.service_stopped.assert_not_called()


class TestSDDiscoveryTTL1(_BaseSDDiscoveryTest):
    TTL = 1

    async def test_sd_disconnect(self):
        self.prot.connection_lost(None)

        await settle()

        self.assertCountEqual(
            self.mock.method_calls,
            [
                unittest.mock.call.service_stopped(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call.service_stopped(self.cfg_offer_5567, self.fake_addr),
            ],
        )
        self.assertEqual(
            self.mock_single.method_calls,
            [unittest.mock.call.service_stopped(self.cfg_offer_5566, self.fake_addr)],
        )

    async def test_sd_reboot(self):
        self.prot.reboot_detected(self.fake_addr)
        await settle()
        self.prot.handle_offer(self.offer_5566, self.fake_addr)
        self.prot.handle_offer(self.offer_5567, self.fake_addr)
        await settle()

        self.assertCountEqual(
            self.mock.method_calls[:2],
            [
                unittest.mock.call.service_stopped(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call.service_stopped(self.cfg_offer_5567, self.fake_addr),
            ],
        )
        self.assertEqual(
            self.mock.method_calls[2:],
            [
                unittest.mock.call.service_offered(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call.service_offered(self.cfg_offer_5567, self.fake_addr),
            ],
        )

        self.assertEqual(
            self.mock_single.method_calls,
            [
                unittest.mock.call.service_stopped(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call.service_offered(self.cfg_offer_5566, self.fake_addr),
            ],
        )

        # wait for timeout of initial service, should not call service_stopped since
        # it was removed by reboot detection
        self.mock.reset_mock()
        self.mock_single.reset_mock()

        await asyncio.sleep(0.8)

        self.assertEqual(self.mock.method_calls, [])
        self.assertEqual(self.mock_single.method_calls, [])

    async def test_sd(self):
        self.prot.handle_offer(self.offer_5566, self.fake_addr)
        self.prot.handle_offer(self.offer_5567, self.fake_addr)
        await settle()

        self.assertEqual(self.mock.method_calls, [])
        self.assertEqual(self.mock_single.method_calls, [])

        await asyncio.sleep(1.2)

        self.assertCountEqual(
            self.mock.method_calls,
            [
                unittest.mock.call.service_stopped(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call.service_stopped(self.cfg_offer_5567, self.fake_addr),
            ],
        )

        self.assertEqual(
            self.mock_single.method_calls,
            [unittest.mock.call.service_stopped(self.cfg_offer_5566, self.fake_addr)],
        )

        self.mock.reset_mock()
        self.mock_single.reset_mock()

        self.prot.handle_offer(self.offer_5566, self.fake_addr)
        self.prot.handle_offer(self.offer_5567, self.fake_addr)
        await settle()

        self.assertEqual(
            self.mock.method_calls,
            [
                unittest.mock.call.service_offered(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call.service_offered(self.cfg_offer_5567, self.fake_addr),
            ],
        )

        self.assertEqual(
            self.mock_single.method_calls,
            [unittest.mock.call.service_offered(self.cfg_offer_5566, self.fake_addr)],
        )

        self.mock.reset_mock()
        self.mock_single.reset_mock()

        await asyncio.sleep(1.2)

        self.assertCountEqual(
            self.mock.method_calls,
            [
                unittest.mock.call.service_stopped(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call.service_stopped(self.cfg_offer_5567, self.fake_addr),
            ],
        )

        self.assertEqual(
            self.mock_single.method_calls,
            [unittest.mock.call.service_stopped(self.cfg_offer_5566, self.fake_addr)],
        )

        # service already removed by timeout detection above.
        # send stopoffer again, should not reach listener
        self.mock.reset_mock()
        self.mock_single.reset_mock()

        self.prot.handle_offer(self.stop_offer_5566, self.fake_addr)
        self.prot.handle_offer(self.offer_5567, self.fake_addr)
        await settle()

        self.assertEqual(
            self.mock.method_calls,
            [unittest.mock.call.service_offered(self.cfg_offer_5567, self.fake_addr)],
        )

        self.assertEqual(self.mock_single.method_calls, [])

    async def test_watch_all_while_running(self):
        newmock = unittest.mock.Mock()
        self.prot.watch_all_services(newmock)
        await settle()

        self.assertEqual(
            newmock.service_offered.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call(self.cfg_offer_5567, self.fake_addr),
            ],
        )

        newmock.service_stopped.assert_not_called()

    async def test_stop_watch_all(self):
        self.prot.stop_watch_all_services(self.mock)
        await settle()

        self.assertEqual(
            self.mock.service_stopped.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566, self.fake_addr),
                unittest.mock.call(self.cfg_offer_5567, self.fake_addr),
            ],
        )

        self.mock.reset_mock()

        # time out all offers
        await asyncio.sleep(1.2)

        offer_5568 = replace(self.offer_5566, service_id=0x5568)
        self.prot.handle_offer(offer_5568, self.fake_addr)
        self.prot.handle_offer(self.offer_5566, self.fake_addr)
        await settle()

        self.assertEqual(self.mock.method_calls, [])

    async def test_stop_watch_single(self):
        self.prot.stop_watch_service(cfg.Service(service_id=0x5566), self.mock_single)
        await settle()

        self.assertEqual(
            self.mock_single.service_stopped.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566, self.fake_addr),
            ],
        )

        self.mock_single.reset_mock()

        # time out all offers
        await asyncio.sleep(1.2)
        self.assertEqual(self.mock_single.method_calls, [])

        # after found_services.stop_all(), new offer would trigger callbacks,
        # but the listener is removed
        self.prot.handle_offer(self.offer_5566, self.fake_addr)
        await settle()
        self.assertEqual(self.mock_single.method_calls, [])

    async def test_watch_while_running(self):
        self.prot.stop_watch_all_services(self.mock)
        await settle()

        # 0x5566 is still monitored from watch_service(0x5566)
        newmock = unittest.mock.Mock()
        self.prot.watch_service(cfg.Service(service_id=0x5566), newmock)
        await settle()

        self.assertEqual(
            newmock.service_offered.call_args_list,
            [unittest.mock.call(self.cfg_offer_5566, self.fake_addr)],
        )

        newmock.service_stopped.assert_not_called()

        # 0x5567 is not monitored since stop_watch_all_services()
        # TTL is 1, therefore the service will expire from found_services
        await asyncio.sleep(0.6)
        self.prot.handle_offer(self.offer_5567, self.fake_addr)
        await asyncio.sleep(0.6)
        self.prot.handle_offer(self.offer_5567, self.fake_addr)
        await settle()

        newmock = unittest.mock.Mock()
        self.prot.watch_service(cfg.Service(service_id=0x5567), newmock)
        await settle()

        newmock.service_offered.assert_not_called()
        newmock.service_stopped.assert_not_called()

        self.prot.handle_offer(self.offer_5567, self.fake_addr)
        await settle()

        self.assertEqual(
            newmock.service_offered.call_args_list,
            [unittest.mock.call(self.cfg_offer_5567, self.fake_addr)],
        )

# }}}


# {{{ ServiceDiscover FindService
class TestSDFind(unittest.IsolatedAsyncioTestCase, _SendTiming):
    multi_addr = ("2001:db8::1", 30490, 0, 0)
    fake_addr = ("2001:db8::2", 30490, 0, 0)

    async def asyncSetUp(self):  # noqa: N802
        mock_sd = unittest.mock.Mock(
            spec_set=["timings", "log", "send_sd", "subscriber"]
        )
        mock_sd.timings = sd.Timings(
            INITIAL_DELAY_MIN=ticks(2),
            INITIAL_DELAY_MAX=ticks(2),
            REPETITIONS_BASE_DELAY=ticks(1),
            REPETITIONS_MAX=3,
            FIND_TTL=5,
        )
        mock_sd.log = logging.getLogger("someip.sd")
        self._mock_send_sd = mock_sd.send_sd = unittest.mock.Mock()
        self._mock_subscribe_start = mock_sd.subscriber.subscribe_eventgroup
        self._mock_subscribe_stop = mock_sd.subscriber.stop_subscribe_eventgroup
        self.prot = sd.ServiceDiscover(mock_sd)

        self.setup_timing(
            self._mock_send_sd, self._mock_subscribe_start, self._mock_subscribe_stop
        )

    async def test_send_find(self):
        mock = unittest.mock.Mock()
        self.prot.watch_service(cfg.Service(service_id=0x5566), mock)

        await self.prot.send_find_services()

        find_5566 = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.FindService,
            service_id=0x5566,
            instance_id=0xFFFF,
            major_version=0xFF,
            ttl=5,
            minver_or_counter=0xFFFFFFFF,
        )

        self.assertTiming(
            (2, self._mock_send_sd, unittest.mock.call([find_5566])),
            (3, self._mock_send_sd, unittest.mock.call([find_5566])),
            (5, self._mock_send_sd, unittest.mock.call([find_5566])),
            (9, self._mock_send_sd, unittest.mock.call([find_5566])),
        )

    async def test_send_no_finds_after_early_offer(self):
        mock = unittest.mock.Mock()
        self.prot.watch_service(cfg.Service(service_id=0x5566), mock)

        t = asyncio.create_task(self.prot.send_find_services())

        await asyncio.sleep(ticks(2))

        data = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.OfferService,
            service_id=0x5566,
            instance_id=0x7788,
            major_version=1,
            ttl=1,
            minver_or_counter=0xDEADBEEF,
            options_1=(
                hdr.IPv4EndpointOption(
                    address=ipaddress.IPv4Address("254.253.252.251"),
                    l4proto=hdr.L4Protocols.UDP,
                    port=65535,
                ),
            ),
        )

        self.prot.handle_offer(data, self.fake_addr)

        await t
        self.assertTiming()

    async def test_send_no_finds_after_late_offer(self):
        mock = unittest.mock.Mock()
        self.prot.watch_service(cfg.Service(service_id=0x5566), mock)

        t = asyncio.create_task(self.prot.send_find_services())

        await asyncio.sleep(ticks(3.5))

        data = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.OfferService,
            service_id=0x5566,
            instance_id=0x7788,
            major_version=1,
            ttl=1,
            minver_or_counter=0xDEADBEEF,
            options_1=(
                hdr.IPv4EndpointOption(
                    address=ipaddress.IPv4Address("254.253.252.251"),
                    l4proto=hdr.L4Protocols.UDP,
                    port=65535,
                ),
            ),
        )

        self.prot.handle_offer(data, self.fake_addr)

        await t

        find_5566 = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.FindService,
            service_id=0x5566,
            instance_id=0xFFFF,
            major_version=0xFF,
            ttl=5,
            minver_or_counter=0xFFFFFFFF,
        )

        self.assertTiming(
            (2, self._mock_send_sd, unittest.mock.call([find_5566])),
            (3, self._mock_send_sd, unittest.mock.call([find_5566])),
        )

    async def test_send_no_finds(self):
        await self.prot.send_find_services()
        self.assertTiming()

    async def test_send_multiple_services_one_offer_early(self):
        mock = unittest.mock.Mock()
        self.prot.watch_service(cfg.Service(service_id=0x5566), mock)
        self.prot.watch_service(cfg.Service(service_id=0x4433), mock)

        t = asyncio.create_task(self.prot.send_find_services())

        await asyncio.sleep(ticks(0.2))

        data = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.OfferService,
            service_id=0x4433,
            instance_id=0x7788,
            major_version=1,
            ttl=int(ticks(10)),
            minver_or_counter=0xDEADBEEF,
            options_1=(
                hdr.IPv4EndpointOption(
                    address=ipaddress.IPv4Address("254.253.252.251"),
                    l4proto=hdr.L4Protocols.UDP,
                    port=65535,
                ),
            ),
        )

        self.prot.handle_offer(data, self.fake_addr)

        await t

        find_5566 = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.FindService,
            service_id=0x5566,
            instance_id=0xFFFF,
            major_version=0xFF,
            ttl=5,
            minver_or_counter=0xFFFFFFFF,
        )

        self.assertTiming(
            (2, self._mock_send_sd, unittest.mock.call([find_5566])),
            (3, self._mock_send_sd, unittest.mock.call([find_5566])),
            (5, self._mock_send_sd, unittest.mock.call([find_5566])),
            (9, self._mock_send_sd, unittest.mock.call([find_5566])),
        )

    async def test_find_subscribe(self):
        local_addr = ("2001:db8::1111", 3333, 0, 0)

        cfg_eventgroup = cfg.Eventgroup(
            service_id=0x5566,
            instance_id=0xFFFF,
            major_version=0xFF,
            eventgroup_id=0x0000AAAA,
            sockname=local_addr,
            protocol=hdr.L4Protocols.UDP,
        )

        self.prot.find_subscribe_eventgroup(cfg_eventgroup)

        t = asyncio.create_task(self.prot.send_find_services())

        await asyncio.sleep(ticks(2.5))

        data = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.OfferService,
            service_id=0x5566,
            instance_id=0x7788,
            major_version=1,
            ttl=ticks(10),
            minver_or_counter=0xDEADBEEF,
            options_1=(
                hdr.IPv4EndpointOption(
                    address=ipaddress.IPv4Address("254.253.252.251"),
                    l4proto=hdr.L4Protocols.UDP,
                    port=65535,
                ),
            ),
        )

        self.prot.handle_offer(data, self.fake_addr)

        # let offer time out
        await asyncio.sleep(ticks(10.1))
        await t

        find = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.FindService,
            service_id=0x5566,
            instance_id=0xFFFF,
            major_version=0xFF,
            ttl=5,
            minver_or_counter=0xFFFFFFFF,
        )
        evgrp = cfg.Eventgroup(
            service_id=0x5566,
            instance_id=0x7788,
            major_version=1,
            eventgroup_id=0x0000AAAA,
            sockname=local_addr,
            protocol=hdr.L4Protocols.UDP,
        )

        self.prot.handle_offer(data, self.fake_addr)
        await asyncio.sleep(ticks(2))
        self.prot.stop_find_subscribe_eventgroup(cfg_eventgroup)
        await asyncio.sleep(ticks(1))

        self.assertTiming(
            (2, self._mock_send_sd, unittest.mock.call([find])),
            (
                2.5,
                self._mock_subscribe_start,
                unittest.mock.call(evgrp, self.fake_addr),
            ),
            (
                12.5,
                self._mock_subscribe_stop,
                unittest.mock.call(evgrp, self.fake_addr),
            ),
            (
                12.5,
                self._mock_subscribe_start,
                unittest.mock.call(evgrp, self.fake_addr),
            ),
            (
                14.5,
                self._mock_subscribe_stop,
                unittest.mock.call(evgrp, self.fake_addr),
            ),
        )


# }}}


# {{{ ServiceSubscriber Eventgroup Client subscribe / stop subscribe
class TestSubscribeEventgroup(unittest.IsolatedAsyncioTestCase):
    local_addr = ("2001:db8::ff", 30331, 0, 0)
    remote1_addr = ("2001:db8::1", 30332, 0, 0)
    remote2_addr = ("2001:db8::2", 30337, 0, 0)
    maxDiff: typing.Optional[int] = None
    TTL = typing.ClassVar[int]
    REFRESH_INTERVAL = typing.ClassVar[float]

    async def asyncSetUp(self):  # noqa: N802
        mock_sd = unittest.mock.Mock(spec_set=["timings", "log", "send_sd"])
        mock_sd.timings = sd.Timings(
            SUBSCRIBE_TTL=self.TTL, SUBSCRIBE_REFRESH_INTERVAL=self.REFRESH_INTERVAL
        )
        mock_sd.log = logging.getLogger("someip.sd")
        mock_sd.send_sd = unittest.mock.Mock()
        self._mock_send_sd = mock_sd.send_sd
        self.prot = sd.ServiceSubscriber(mock_sd)

        self.evgrp_1 = cfg.Eventgroup(
            service_id=0x1111,
            instance_id=0x4444,
            major_version=0x66,
            eventgroup_id=0xCCDD,
            sockname=self.local_addr,
            protocol=hdr.L4Protocols.UDP,
        )
        self.sub_evgrp_1 = self.evgrp_1.create_subscribe_entry(self.TTL or 0xFFFFFF)
        self.stop_sub_evgrp_1 = self.evgrp_1.create_subscribe_entry(0)

        self.evgrp_2 = cfg.Eventgroup(
            service_id=0x2222,
            instance_id=0x5555,
            major_version=0x66,
            eventgroup_id=0xCCDD,
            sockname=self.local_addr,
            protocol=hdr.L4Protocols.UDP,
        )
        self.sub_evgrp_2 = self.evgrp_2.create_subscribe_entry(self.TTL or 0xFFFFFF)
        self.stop_sub_evgrp_2 = self.evgrp_2.create_subscribe_entry(0)

        self.evgrp_3 = cfg.Eventgroup(
            service_id=0x3333,
            instance_id=0x6666,
            major_version=0x77,
            eventgroup_id=0xAABB,
            sockname=self.local_addr,
            protocol=hdr.L4Protocols.UDP,
        )
        self.sub_evgrp_3 = self.evgrp_3.create_subscribe_entry(self.TTL or 0xFFFFFF)
        self.stop_sub_evgrp_3 = self.evgrp_3.create_subscribe_entry(0)


class TestSubscribeEventgroupTTL3(TestSubscribeEventgroup):
    TTL = 3
    REFRESH_INTERVAL = 1

    async def test_subscribe(self):
        self.prot.subscribe_eventgroup(self.evgrp_1, self.remote1_addr)
        self.prot.subscribe_eventgroup(self.evgrp_2, self.remote2_addr)
        self.prot.start()

        await settle()

        self.assertCountEqual(
            self._mock_send_sd.call_args_list,
            (
                unittest.mock.call([self.sub_evgrp_1], remote=self.remote1_addr),
                unittest.mock.call([self.sub_evgrp_2], remote=self.remote2_addr),
            ),
        )
        self._mock_send_sd.reset_mock()

        # add new eventgroup, show subscription in next cycle
        self.prot.subscribe_eventgroup(self.evgrp_3, self.remote1_addr)

        await asyncio.sleep(0.1)

        self.assertCountEqual(
            self._mock_send_sd.call_args_list,
            (unittest.mock.call([self.sub_evgrp_3], remote=self.remote1_addr),),
        )
        self._mock_send_sd.reset_mock()

        # wait one refresh cycle
        await asyncio.sleep(1)

        self.assertCountEqual(
            self._mock_send_sd.call_args_list,
            (
                unittest.mock.call(
                    [self.sub_evgrp_1, self.sub_evgrp_3],
                    remote=self.remote1_addr,
                ),
                unittest.mock.call([self.sub_evgrp_2], remote=self.remote2_addr),
            ),
        )
        self._mock_send_sd.reset_mock()

        # remove eventgroup, send stop subscribe
        self.prot.stop_subscribe_eventgroup(self.evgrp_1, self.remote1_addr)

        await settle()

        self._mock_send_sd.assert_called_once_with(
            [self.stop_sub_evgrp_1],
            remote=self.remote1_addr,
        )
        self._mock_send_sd.reset_mock()

        # remove eventgroup again => don't send stop again
        self.prot.stop_subscribe_eventgroup(self.evgrp_1, self.remote1_addr)

        await settle()

        self._mock_send_sd.assert_not_called()
        self._mock_send_sd.reset_mock()

        # show changed subscription messages after stop
        await asyncio.sleep(1)

        self.assertCountEqual(
            self._mock_send_sd.call_args_list,
            (
                unittest.mock.call([self.sub_evgrp_3], remote=self.remote1_addr),
                unittest.mock.call([self.sub_evgrp_2], remote=self.remote2_addr),
            ),
        )
        self._mock_send_sd.reset_mock()

        # remove last eventgroup of endpoint, send stop subscribe
        self.prot.stop_subscribe_eventgroup(self.evgrp_3, self.remote1_addr, send=False)

        await settle()

        self._mock_send_sd.assert_not_called()
        self._mock_send_sd.reset_mock()

        # show changed subscription messages after stop
        await asyncio.sleep(1)

        self._mock_send_sd.assert_called_once_with(
            [self.sub_evgrp_2],
            remote=self.remote2_addr,
        )
        self._mock_send_sd.reset_mock()


class TestSubscribeEventgroupTTLForever(TestSubscribeEventgroup):
    TTL = sd.TTL_FOREVER
    REFRESH_INTERVAL = None

    async def test_subscribe(self):
        self.prot.subscribe_eventgroup(self.evgrp_1, self.remote1_addr)
        self.prot.subscribe_eventgroup(self.evgrp_2, self.remote2_addr)
        self.prot.start()

        await settle()

        self.assertCountEqual(
            self._mock_send_sd.call_args_list,
            (
                unittest.mock.call([self.sub_evgrp_1], remote=self.remote1_addr),
                unittest.mock.call([self.sub_evgrp_2], remote=self.remote2_addr),
            ),
        )
        self._mock_send_sd.reset_mock()

        self.prot.subscribe_eventgroup(self.evgrp_3, self.remote1_addr)

        await settle()
        self._mock_send_sd.assert_called_once_with(
            [self.sub_evgrp_3],
            remote=self.remote1_addr,
        )

    async def test_sd_stop_send_stop(self):
        self.prot.subscribe_eventgroup(self.evgrp_1, self.remote1_addr)
        self.prot.start()
        await settle()

        self._mock_send_sd.assert_called_once_with(
            [self.sub_evgrp_1],
            remote=self.remote1_addr,
        )
        self._mock_send_sd.reset_mock()

        self.prot.stop()

        await settle()

        self._mock_send_sd.assert_called_once_with(
            [self.stop_sub_evgrp_1],
            remote=self.remote1_addr,
        )

    async def test_sd_stop_no_send_stop(self):
        self.prot.subscribe_eventgroup(self.evgrp_1, self.remote1_addr)
        self.prot.start()
        await settle()

        self._mock_send_sd.assert_called_once_with(
            [self.sub_evgrp_1],
            remote=self.remote1_addr,
        )
        self._mock_send_sd.reset_mock()

        self.prot.stop(send_stop_subscribe=False)

        await settle()

        self._mock_send_sd.assert_not_called()


# }}}


# {{{ ServiceAnnouncer
class TestSDAnnounce(unittest.IsolatedAsyncioTestCase, _SendTiming):
    multi_addr = ("2001:db8::1", 30490, 0, 0)
    fake_addr = ("2001:db8::2", 30490, 0, 0)

    async def asyncSetUp(self):  # noqa: N802
        mock_sd = unittest.mock.Mock(spec_set=["timings", "log", "send_sd"])
        ttl_ticks = ticks(30)
        assert ttl_ticks.is_integer()
        self.TTL = int(ttl_ticks)
        mock_sd.timings = sd.Timings(
            INITIAL_DELAY_MIN=ticks(1),
            INITIAL_DELAY_MAX=ticks(1),
            CYCLIC_OFFER_DELAY=ticks(20),
            ANNOUNCE_TTL=self.TTL,
            REPETITIONS_MAX=0,
            REPETITIONS_BASE_DELAY=ticks(1),
            REQUEST_RESPONSE_DELAY_MIN=0,
            REQUEST_RESPONSE_DELAY_MAX=0,
        )
        mock_sd.log = logging.getLogger("someip.sd")
        mock_sd.send_sd = unittest.mock.Mock()
        self._mock_send_sd = mock_sd.send_sd
        self.prot = sd.ServiceAnnouncer(mock_sd)
        self.setup_timing(self._mock_send_sd)

        self.ep_1 = hdr.IPv4EndpointOption(
            address=ipaddress.IPv4Address("254.253.252.251"),
            l4proto=hdr.L4Protocols.UDP,
            port=30335,
        )

        self.ep_2 = hdr.IPv4EndpointOption(
            address=ipaddress.IPv6Address("2001:db8::abcd:f00b"),
            l4proto=hdr.L4Protocols.TCP,
            port=30330,
        )

        self.cfg_service_5566 = cfg.Service(
            service_id=0x5566,
            instance_id=0x7788,
            major_version=12,
            minor_version=345,
            options_1=(self.ep_1,),
        )

        self.cfg_service_2233 = cfg.Service(
            service_id=0x2233,
            instance_id=0x0001,
            major_version=1,
            minor_version=0,
            options_1=(self.ep_2,),
        )

        self.cfg_service_9999 = cfg.Service(
            service_id=0x9999,
        )

        self.listener_5566 = unittest.mock.Mock()
        self.listener_2233 = unittest.mock.Mock()
        self.prot.announce_service(self.cfg_service_5566, self.listener_5566)
        self.prot.announce_service(self.cfg_service_2233, self.listener_2233)

    async def test_announce_non_cyclic(self):
        self.prot.timings.REPETITIONS_MAX = 2
        self.prot.timings.CYCLIC_OFFER_DELAY = 0

        self.prot.start()
        with self.assertLogs("someip.sd.announce", "WARNING") as cm:
            await asyncio.sleep(ticks(13))
        self.prot.stop()

        self.assertTrue(any("CYCLIC_OFFER_DELAY" in msg for msg in cm.output))

        call = unittest.mock.call(
            [
                self.cfg_service_5566.create_offer_entry(self.TTL),
                self.cfg_service_2233.create_offer_entry(self.TTL),
            ],
            remote=None,
        )

        self.assertTiming(
            (1, self._mock_send_sd, call),
            (2, self._mock_send_sd, call),
            (4, self._mock_send_sd, call),
        )

        self.reset_mock()

        await asyncio.sleep(ticks(0.01))
        self._mock_send_sd.assert_called_once_with(
            [
                self.cfg_service_5566.create_offer_entry(0),
                self.cfg_service_2233.create_offer_entry(0),
            ],
            remote=None,
        )

    async def test_announce_cyclic(self):
        self.prot.timings.REPETITIONS_MAX = 3
        self.prot.timings.CYCLIC_OFFER_DELAY = ticks(2)

        self.prot.start()
        await asyncio.sleep(ticks(13))
        self.prot.stop()

        call = unittest.mock.call(
            [
                self.cfg_service_5566.create_offer_entry(self.TTL),
                self.cfg_service_2233.create_offer_entry(self.TTL),
            ],
            remote=None,
        )

        self.assertTiming(
            (1, self._mock_send_sd, call),
            (2, self._mock_send_sd, call),
            (4, self._mock_send_sd, call),
            (8, self._mock_send_sd, call),
            (10, self._mock_send_sd, call),
            (12, self._mock_send_sd, call),
        )

        self.reset_mock()

        await asyncio.sleep(ticks(0.01))
        self._mock_send_sd.assert_called_once_with(
            [
                self.cfg_service_5566.create_offer_entry(0),
                self.cfg_service_2233.create_offer_entry(0),
            ],
            remote=None,
        )

    async def test_announce_stop_initial(self):
        self.prot.timings.REPETITIONS_MAX = 3
        self.prot.timings.CYCLIC_OFFER_DELAY = ticks(2)

        self.prot.start()
        # sleep until just before end of initial wait phase
        await asyncio.sleep(ticks(0.9))
        self.prot.stop()

        await asyncio.sleep(ticks(0.01))

        self.assertTiming()

    async def test_find_service_initial(self):
        data = self.cfg_service_5566.create_find_entry(self.TTL)

        await self.prot.handle_findservice(
            data, self.fake_addr, received_over_multicast=True, unicast_supported=True
        )

        self.assertTiming()

        self.prot.start()
        # sleep until middle of initial wait phase
        await self.prot.handle_findservice(
            data, self.fake_addr, received_over_multicast=True, unicast_supported=True
        )
        await asyncio.sleep(ticks(0.5))
        self.prot.stop()

        self.assertTiming()

    async def test_find_service_unknown(self):

        self.prot.start()
        await asyncio.sleep(ticks(0.01))
        self.reset_mock()

        data = self.cfg_service_9999.create_find_entry()
        await self.prot.handle_findservice(
            data, self.fake_addr, received_over_multicast=True, unicast_supported=True
        )

        self.prot.stop()

        self.assertTiming()

    async def test_find_service_known_answer_unicast(self):
        self.prot.timings.INITIAL_DELAY_MIN = self.prot.timings.INITIAL_DELAY_MAX = 0
        self.prot.timings.REQUEST_RESPONSE_DELAY_MIN = ticks(1)
        self.prot.timings.REQUEST_RESPONSE_DELAY_MAX = ticks(1)

        self.prot.start()
        await asyncio.sleep(ticks(1))
        self.reset_mock()

        await self.prot.handle_findservice(
            self.cfg_service_5566.create_find_entry(),
            self.fake_addr,
            received_over_multicast=True,
            unicast_supported=True,
        )
        await self.prot.handle_findservice(
            self.cfg_service_9999.create_find_entry(),
            self.fake_addr,
            received_over_multicast=True,
            unicast_supported=True,
        )

        self.prot.stop()

        self.assertTiming(
            (
                2,
                self._mock_send_sd,
                unittest.mock.call(
                    [self.cfg_service_5566.create_offer_entry(self.TTL)],
                    remote=self.fake_addr,
                ),
            ),
        )

    async def test_find_service_known_request_unicast_no_delay(self):
        self.prot.timings.INITIAL_DELAY_MIN = self.prot.timings.INITIAL_DELAY_MAX = 0
        self.prot.timings.REQUEST_RESPONSE_DELAY_MIN = ticks(1)
        self.prot.timings.REQUEST_RESPONSE_DELAY_MAX = ticks(1)

        self.prot.start()
        await asyncio.sleep(ticks(1))
        self.reset_mock()

        await self.prot.handle_findservice(
            self.cfg_service_5566.create_find_entry(),
            self.fake_addr,
            received_over_multicast=False,
            unicast_supported=True,
        )
        await self.prot.handle_findservice(
            self.cfg_service_9999.create_find_entry(),
            self.fake_addr,
            received_over_multicast=False,
            unicast_supported=True,
        )

        self.prot.stop()

        self.assertTiming(
            (
                1,
                self._mock_send_sd,
                unittest.mock.call(
                    [self.cfg_service_5566.create_offer_entry(self.TTL)],
                    remote=self.fake_addr,
                ),
            ),
        )

    async def test_find_service_known_answer_multicast_supported(self):
        self.prot.timings.INITIAL_DELAY_MIN = self.prot.timings.INITIAL_DELAY_MAX = 0
        self.prot.timings.REQUEST_RESPONSE_DELAY_MIN = ticks(1)
        self.prot.timings.REQUEST_RESPONSE_DELAY_MAX = ticks(1)

        self.prot.start()
        await asyncio.sleep(ticks(1))
        self.reset_mock()

        await self.prot.handle_findservice(
            self.cfg_service_5566.create_find_entry(),
            self.fake_addr,
            received_over_multicast=True,
            unicast_supported=False,
        )
        await self.prot.handle_findservice(
            self.cfg_service_9999.create_find_entry(),
            self.fake_addr,
            received_over_multicast=True,
            unicast_supported=False,
        )

        self.prot.stop()

        self.assertTiming(
            (
                2,
                self._mock_send_sd,
                unittest.mock.call(
                    [self.cfg_service_5566.create_offer_entry(self.TTL)], remote=None
                ),
            ),
        )

    async def test_find_service_known_answer_multicast_delay(self):
        self.prot.timings.INITIAL_DELAY_MIN = self.prot.timings.INITIAL_DELAY_MAX = 0
        self.prot.timings.REQUEST_RESPONSE_DELAY_MIN = ticks(1)
        self.prot.timings.REQUEST_RESPONSE_DELAY_MAX = ticks(1)

        self.prot.start()
        await asyncio.sleep(ticks(11.5))
        self.reset_mock()

        await self.prot.handle_findservice(
            self.cfg_service_5566.create_find_entry(),
            self.fake_addr,
            received_over_multicast=True,
            unicast_supported=True,
        )
        await self.prot.handle_findservice(
            self.cfg_service_9999.create_find_entry(),
            self.fake_addr,
            received_over_multicast=True,
            unicast_supported=True,
        )

        await asyncio.sleep(ticks(1.1))
        self.prot.stop()

        self.assertTiming(
            (
                12.5,
                self._mock_send_sd,
                unittest.mock.call(
                    [self.cfg_service_5566.create_offer_entry(self.TTL)], remote=None
                ),
            ),
        )


# }}}

# {{{ ServiceAnnouncer Server subscription handling
class _BaseSDSubscriptionTest(unittest.IsolatedAsyncioTestCase):
    multi_addr = ("2001:db8::1", 30490, 0, 0)
    fake_sd_addr = ("2001:db8::2", 30490, 0, 0)
    fake_addr = ("2001:db8::2", 30321, 0, 0)
    TTL: int

    async def asyncSetUp(self):  # noqa: N802
        mock_sd = unittest.mock.Mock(spec_set=["timings", "log", "send_sd"])
        mock_sd.timings = sd.Timings()
        mock_sd.log = logging.getLogger("someip.sd")
        mock_sd.send_sd = unittest.mock.Mock()
        self._mock_send_sd = mock_sd.send_sd
        self.prot = sd.ServiceAnnouncer(mock_sd)

        self.cfg_5566 = cfg.Service(
            service_id=0x5566,
            instance_id=0x7788,
            major_version=1,
            minor_version=0,
            eventgroups=(0x3333, 0x4444),
        )
        self.cfg_5567 = replace(self.cfg_5566, service_id=0x5567)

        endpoint = hdr.IPv6EndpointOption(
            ipaddress.IPv6Address(self.fake_addr[0]),
            port=self.fake_addr[1],
            l4proto=hdr.L4Protocols.UDP,
        )

        self.subscribe_5566_3333 = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.Subscribe,
            service_id=0x5566,
            instance_id=0x7788,
            major_version=1,
            minver_or_counter=0x3333,
            ttl=self.TTL,
            options_1=(endpoint,),
            options_2=(hdr.SOMEIPSDConfigOption(configs=(("foo", "bar"),)),),
        )
        self.subscribe_5566_1234 = replace(
            self.subscribe_5566_3333, minver_or_counter=0x11234
        )
        self.subscription_5566_3333 = sd.EventgroupSubscription.from_subscribe_entry(
            self.subscribe_5566_3333
        )
        self.ack_5566_3333 = self.subscription_5566_3333.to_ack_entry()
        self.nack_5566_3333 = self.subscription_5566_3333.to_nack_entry()
        self.nack_5566_1234 = replace(self.nack_5566_3333, minver_or_counter=0x11234)
        self.stop_subscribe_5566_3333 = replace(self.subscribe_5566_3333, ttl=0)

        self.mock = unittest.mock.Mock()
        self.prot.announce_service(self.cfg_5566, self.mock._5566)
        self.prot.announce_service(self.cfg_5567, self.mock._5567)

        await self.prot.handle_subscribe(self.subscribe_5566_3333, self.fake_sd_addr)

        await settle()

        self._mock_send_sd.assert_called_once_with(
            [self.ack_5566_3333], remote=self.fake_sd_addr
        )

        self.assertEqual(
            self.mock.method_calls,
            [
                unittest.mock.call._5566.client_subscribed(
                    self.subscription_5566_3333, self.fake_sd_addr
                ),
            ],
        )

        await settle()

        self.reset_mock()

    def reset_mock(self):
        self.mock.reset_mock()
        self._mock_send_sd.reset_mock()

    async def _test_sd_reject_subscription(self):
        self.mock._5566.client_subscribed.side_effect = sd.NakSubscription
        await self.prot.handle_subscribe(
            self.stop_subscribe_5566_3333, self.fake_sd_addr
        )
        await settle()

        self.reset_mock()

        await self.prot.handle_subscribe(self.subscribe_5566_3333, self.fake_sd_addr)
        await settle()

        self._mock_send_sd.assert_called_once_with(
            [self.nack_5566_3333], remote=self.fake_sd_addr
        )

        self.assertEqual(
            self.mock.method_calls,
            [
                unittest.mock.call._5566.client_subscribed(
                    self.subscription_5566_3333, self.fake_sd_addr
                ),
            ],
        )

        self.reset_mock()
        self.mock._5566.client_subscribed.side_effect = None

        await self.prot.handle_subscribe(self.subscribe_5566_3333, self.fake_sd_addr)
        await settle()

        self._mock_send_sd.assert_called_once_with(
            [self.ack_5566_3333], remote=self.fake_sd_addr
        )

        self.assertEqual(
            self.mock.method_calls,
            [
                unittest.mock.call._5566.client_subscribed(
                    self.subscription_5566_3333, self.fake_sd_addr
                ),
            ],
        )

    async def _test_sd_disconnect(self):
        self.prot.connection_lost(None)

        await settle()

        self.assertEqual(
            self.mock.method_calls,
            [
                unittest.mock.call._5566.client_unsubscribed(
                    self.subscription_5566_3333, self.fake_sd_addr
                ),
            ],
        )


class TestSDSubscriptionTTLForever(_BaseSDSubscriptionTest):
    TTL = sd.TTL_FOREVER

    test_sd_reject_subscription = _BaseSDSubscriptionTest._test_sd_reject_subscription
    test_sd_disconnect = _BaseSDSubscriptionTest._test_sd_disconnect

    async def test_sd_reboot_ttl_forever(self):
        await self.prot.handle_subscribe(self.subscribe_5566_3333, self.fake_sd_addr)
        await settle()

        self._mock_send_sd.assert_called_once_with(
            [self.ack_5566_3333], remote=self.fake_sd_addr
        )

        self.mock.assert_not_called()
        self.reset_mock()

        await self.prot.handle_subscribe(self.subscribe_5566_3333, self.fake_sd_addr)
        await settle()

        self._mock_send_sd.assert_called_once_with(
            [self.ack_5566_3333], remote=self.fake_sd_addr
        )

        self.mock.assert_not_called()
        self.reset_mock()

        self.prot.reboot_detected(self.fake_sd_addr)
        await settle()
        await self.prot.handle_subscribe(self.subscribe_5566_3333, self.fake_sd_addr)
        await settle()

        self._mock_send_sd.assert_called_once_with(
            [self.ack_5566_3333], remote=self.fake_sd_addr
        )

        self.assertEqual(
            self.mock.method_calls,
            [
                unittest.mock.call._5566.client_unsubscribed(
                    self.subscription_5566_3333, self.fake_sd_addr
                ),
                unittest.mock.call._5566.client_subscribed(
                    self.subscription_5566_3333, self.fake_sd_addr
                ),
            ],
        )

        self.reset_mock()

        # send stopsubscribe, should reach listener

        await self.prot.handle_subscribe(
            self.stop_subscribe_5566_3333, self.fake_sd_addr
        )
        await settle()

        self._mock_send_sd.assert_not_called()

        self.assertEqual(
            self.mock.method_calls,
            [
                unittest.mock.call._5566.client_unsubscribed(
                    self.subscription_5566_3333, self.fake_sd_addr
                ),
            ],
        )

    async def test_sd_multiple_listener(self):
        await self.prot.handle_subscribe(
            self.stop_subscribe_5566_3333, self.fake_sd_addr
        )
        await settle()

        self.reset_mock()

        self.prot.announce_service(self.cfg_5566, self.mock._5566_2)

        with self.assertLogs("someip.sd.announce", "WARNING") as cm:
            await self.prot.handle_subscribe(
                self.subscribe_5566_3333, self.fake_sd_addr
            )
            await settle()
        self.assertTrue(any("multiple configured" in msg for msg in cm.output))

        self.assertEqual(
            self.mock.method_calls,
            [
                unittest.mock.call._5566.client_subscribed(
                    self.subscription_5566_3333, self.fake_sd_addr
                ),
            ],
        )


class TestSDSubscriptionTTL1(_BaseSDSubscriptionTest):
    TTL = 1

    test_sd_reject_subscription = _BaseSDSubscriptionTest._test_sd_reject_subscription
    test_sd_disconnect = _BaseSDSubscriptionTest._test_sd_disconnect

    async def test_sd_reboot(self):
        self.prot.reboot_detected(self.fake_sd_addr)
        await settle()
        await self.prot.handle_subscribe(self.subscribe_5566_3333, self.fake_sd_addr)
        await settle()

        self._mock_send_sd.assert_called_once_with(
            [self.ack_5566_3333], remote=self.fake_sd_addr
        )

        self.assertEqual(
            self.mock.method_calls,
            [
                unittest.mock.call._5566.client_unsubscribed(
                    self.subscription_5566_3333, self.fake_sd_addr
                ),
                unittest.mock.call._5566.client_subscribed(
                    self.subscription_5566_3333, self.fake_sd_addr
                ),
            ],
        )

        self.reset_mock()

        # wait for timeout of initial service, should not call client_unsubscribed since
        # it was removed by reboot detection
        await asyncio.sleep(0.8)

        self.mock.assert_not_called()

    async def test_sd(self):
        await self.prot.handle_subscribe(self.subscribe_5566_3333, self.fake_sd_addr)
        await settle()

        self._mock_send_sd.assert_called_once_with(
            [self.ack_5566_3333], remote=self.fake_sd_addr
        )

        self.mock.assert_not_called()

        await asyncio.sleep(0.2)

        await self.prot.handle_subscribe(
            self.stop_subscribe_5566_3333, self.fake_sd_addr
        )
        await settle()

        self.assertEqual(
            self.mock.method_calls,
            [
                unittest.mock.call._5566.client_unsubscribed(
                    self.subscription_5566_3333, self.fake_sd_addr
                ),
            ],
        )

        self.reset_mock()

        await self.prot.handle_subscribe(self.subscribe_5566_3333, self.fake_sd_addr)
        await settle()

        self._mock_send_sd.assert_called_once_with(
            [self.ack_5566_3333], remote=self.fake_sd_addr
        )

        self.assertEqual(
            self.mock.method_calls,
            [
                unittest.mock.call._5566.client_subscribed(
                    self.subscription_5566_3333, self.fake_sd_addr
                ),
            ],
        )

        self.reset_mock()

        await asyncio.sleep(1.2)

        self.assertEqual(
            self.mock.method_calls,
            [
                unittest.mock.call._5566.client_unsubscribed(
                    self.subscription_5566_3333, self.fake_sd_addr
                ),
            ],
        )

        self.reset_mock()

        # service already removed by timeout detection above.
        # send stopoffer again, should not reach listener

        await self.prot.handle_subscribe(
            self.stop_subscribe_5566_3333, self.fake_sd_addr
        )
        await settle()

        self.mock.assert_not_called()

    async def test_sd_unknown(self):
        with self.assertLogs("someip.sd.announce", "WARNING") as cm:
            await self.prot.handle_subscribe(
                self.subscribe_5566_1234, self.fake_sd_addr
            )
            await settle()

        self.assertTrue(any("subscribe for unknown" in msg for msg in cm.output))

        self._mock_send_sd.assert_called_once_with(
            [self.nack_5566_1234], remote=self.fake_sd_addr
        )

        self.mock.assert_not_called()


# }}}


# {{{ ServiceDiscoveryProtocol multicast endpoints
class _MulticastEndpointsTest:
    maxDiff: typing.Optional[int] = None
    AF: socket.AddressFamily
    bind_lo_addr: str
    bind_mc_addr: str
    bind_interface: str
    send_addr: str
    sender_lo_addr: str
    send_mc_addr: str

    def _mc_sockopts(self, sock: socket.socket) -> None:
        ...

    async def asyncSetUp(self):  # noqa: N802
        (
            self.trsp_u,
            self.trsp_m,
            self.prot,
        ) = await sd.ServiceDiscoveryProtocol.create_endpoints(
            family=self.AF,
            local_addr=self.bind_lo_addr,
            multicast_addr=self.bind_mc_addr,
            port=30490,
            multicast_interface=self.bind_interface,
        )

    async def asyncTearDown(self):  # noqa: N802
        self.trsp_u.close()
        self.trsp_m.close()

    async def test_endpoint_recv_unicast(self):
        payload = (
            b"\x40\x00\x00\x00"
            b"\x00\x00\x00\x30"
            b"\x06\x00\x00\x21\x88\x99\x66\x77\xEE\x20\x21\x22\x00\x00\x00\x10"
            b"\x01\x01\x01\x01\x55\x66\x77\x88\x99\x00\x00\x01\xde\xad\xbe\xef"
            b"\x01\x01\x01\x01\x55\x67\x77\x88\x99\x00\x00\x01\xde\xad\xbe\xef"
            b"\x00\x00\x00\x20"
            b"\x00\x09\x04\x00\x01\x02\x03\x04\x00\x11\x07\xff"
            b"\x00\x09\x04\x00\xfe\xfd\xfc\xfb\x00\x11\xff\xff"
            b"\x00\x05\x02\x00\x22\x22\x33\x33"
        )

        data = hdr.SOMEIPHeader(
            service_id=hdr.SD_SERVICE,
            method_id=hdr.SD_METHOD,
            client_id=0,
            session_id=1,
            interface_version=hdr.SD_INTERFACE_VERSION,
            message_type=hdr.SOMEIPMessageType.NOTIFICATION,
            payload=payload,
        ).build()

        mock = unittest.mock.Mock()
        self.prot.datagram_received = mock

        ais = socket.getaddrinfo(
            self.send_addr,
            30490,
            self.AF,
            socket.SOCK_DGRAM,
            socket.IPPROTO_UDP,
            flags=socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
        )
        dst_ai = ais[0]

        sender_sock = socket.socket(self.AF, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._mc_sockopts(sender_sock)
        try:
            sender_sock.sendto(data, dst_ai[4])
            await asyncio.sleep(0.01)
            sender_port = sender_sock.getsockname()[1]

            ais = socket.getaddrinfo(
                self.sender_lo_addr,
                sender_port,
                self.AF,
                socket.SOCK_DGRAM,
                socket.IPPROTO_UDP,
                flags=(
                    socket.AI_NUMERICHOST | socket.AI_NUMERICSERV | socket.AI_PASSIVE
                ),
            )
            src_ai = ais[0]

            mock.assert_called_once_with(data, src_ai[4], multicast=False)
        finally:
            sender_sock.close()

    async def test_endpoint_recv_multicast(self):
        payload = (
            b"\x40\x00\x00\x00"
            b"\x00\x00\x00\x30"
            b"\x06\x00\x00\x21\x88\x99\x66\x77\xEE\x20\x21\x22\x00\x00\x00\x10"
            b"\x01\x01\x01\x01\x55\x66\x77\x88\x99\x00\x00\x01\xde\xad\xbe\xef"
            b"\x01\x01\x01\x01\x55\x67\x77\x88\x99\x00\x00\x01\xde\xad\xbe\xef"
            b"\x00\x00\x00\x20"
            b"\x00\x09\x04\x00\x01\x02\x03\x04\x00\x11\x07\xff"
            b"\x00\x09\x04\x00\xfe\xfd\xfc\xfb\x00\x11\xff\xff"
            b"\x00\x05\x02\x00\x22\x22\x33\x33"
        )

        data = hdr.SOMEIPHeader(
            service_id=hdr.SD_SERVICE,
            method_id=hdr.SD_METHOD,
            client_id=0,
            session_id=1,
            interface_version=hdr.SD_INTERFACE_VERSION,
            message_type=hdr.SOMEIPMessageType.NOTIFICATION,
            payload=payload,
        ).build()

        mock = unittest.mock.Mock()
        self.prot.datagram_received = mock

        ais = socket.getaddrinfo(
            self.send_mc_addr,
            30490,
            self.AF,
            socket.SOCK_DGRAM,
            socket.IPPROTO_UDP,
            flags=socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
        )
        dst_ai = ais[0]

        sender_sock = socket.socket(self.AF, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._mc_sockopts(sender_sock)
        try:
            sender_sock.sendto(data, dst_ai[4])
            await asyncio.sleep(0.01)
            sender_port = sender_sock.getsockname()[1]

            ais = socket.getaddrinfo(
                self.sender_lo_addr,
                sender_port,
                self.AF,
                socket.SOCK_DGRAM,
                socket.IPPROTO_UDP,
                flags=(
                    socket.AI_NUMERICHOST | socket.AI_NUMERICSERV | socket.AI_PASSIVE
                ),
            )
            src_ai = ais[0]

            mock.assert_called_once_with(data, src_ai[4], multicast=True)
        finally:
            sender_sock.close()


class TestMulticastEndpointsV4(
    _MulticastEndpointsTest, unittest.IsolatedAsyncioTestCase
):
    bind_lo_addr = "127.0.0.1"
    sender_lo_addr = "127.0.0.1"
    send_addr = "127.0.0.1"
    bind_mc_addr = "224.244.224.245"
    send_mc_addr = "224.244.224.245"
    bind_interface = "lo"
    AF = socket.AF_INET

    def _mc_sockopts(self, sock: socket.socket) -> None:
        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_IF,
            ipaddress.IPv4Address(self.sender_lo_addr).packed,
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        # For Linux, the loopback interface does the loopback already, so
        # IP_MULTICAST_LOOP is not required. BSD however does not receive own multicast
        # packets on a loopback interface, therefore IP_MULTICAST_LOOP=1 is required for
        # BSD.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)


class TestMulticastEndpointsV6(
    _MulticastEndpointsTest, unittest.IsolatedAsyncioTestCase
):
    """
    required setup on Linux:

        ip link add type veth
        ip link set dev veth0 address 02:00:00:00:00:00
        ip link set dev veth1 address 02:00:00:00:00:01
        ip link set up dev veth0
        ip link set up dev veth1
    """

    bind_lo_addr = "fe80::ff:fe00:0%veth0"
    sender_lo_addr = "fe80::ff:fe00:1%veth0"
    send_addr = "fe80::ff:fe00:0%veth1"
    bind_mc_addr = "ff02::dead:beef%veth0"
    send_mc_addr = "ff02::dead:beef%veth1"
    bind_interface = "veth0"
    send_interface = "veth1"
    AF = socket.AF_INET6

    def setUp(self):
        try:
            socket.if_nametoindex(self.bind_interface)
            socket.if_nametoindex(self.send_interface)
        except OSError as exc:
            raise unittest.SkipTest("test interfaces veth0 / veth1 not up") from exc

    def _mc_sockopts(self, sock: socket.socket) -> None:
        ifindex = socket.if_nametoindex(self.send_interface)
        sock.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, struct.pack("=i", ifindex)
        )
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)


# }}}


if __name__ == "__main__":
    unittest.main()
