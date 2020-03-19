import asyncio
import ipaddress
import itertools
import logging
import unittest
import unittest.mock
import socket
from dataclasses import replace

import someip.header as hdr
import someip.config as cfg
import someip.sd as sd

logging.captureWarnings(True)
logging.basicConfig(level=logging.DEBUG)

logging.getLogger('asyncio').setLevel(logging.WARNING)
logging.getLogger('someip').setLevel(logging.WARNING)
LOG = logging.getLogger('test_sd')


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


class TestSD(unittest.IsolatedAsyncioTestCase):
    multi_addr = ('2001:db8::1', 30490, 0, 0)
    fake_addr = ('2001:db8::2', 30490, 0, 0)

    async def _test_endpoint(self, family, host):
        sock = None
        trsp, prot = await sd.SOMEIPDatagramProtocol.create_unicast_endpoint(
            local_addr=(host, 0),
        )
        try:
            prot.message_received = unittest.mock.Mock()
            prot.log = unittest.mock.Mock()
            local_sockname = trsp.get_extra_info('sockname')

            message = hdr.SOMEIPHeader(service_id=0xdead,
                                       method_id=0xbeef,
                                       client_id=0xcccc,
                                       session_id=0xdddd,
                                       protocol_version=1,
                                       interface_version=2,
                                       message_type=hdr.SOMEIPMessageType.REQUEST_ACK,
                                       return_code=hdr.SOMEIPReturnCode.E_NOT_READY)
            data = b'\xde\xad\xbe\xef\x00\x00\x00\x08\xcc\xcc\xdd\xdd\x01\x02\x40\x04'

            sock = socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            addrs = await asyncio.get_event_loop().getaddrinfo(
                host, 0,
                family=sock.family,
                type=sock.type,
                proto=sock.proto,
                flags=socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
            )
            bind_addr = addrs[0][4]
            sock.bind(bind_addr)

            sock.sendto(data, local_sockname)
            sender_sockname = sock.getsockname()
            await asyncio.sleep(.01)
            prot.message_received.assert_called_once_with(message, sender_sockname, False)
            prot.log.error.assert_not_called()

            prot.message_received.reset_mock()
            prot.log.reset_mock()

            data = b'\xde\xad\xbe\xef\x00\x00\x00\x08\xcc\xcc\xdd\xdd\x00\x02\x40\x04'
            sock.sendto(data, local_sockname)
            await asyncio.sleep(.01)
            prot.message_received.assert_not_called()
            prot.log.error.assert_called_once()
        finally:
            if sock:
                sock.close()
            trsp.close()

    async def test_endpoint_v6(self):
        await self._test_endpoint(socket.AF_INET6, '::1')

    async def test_endpoint_v4(self):
        await self._test_endpoint(socket.AF_INET, '127.0.0.1')

    async def test_send_session_id(self):
        entry = cfg.Service(service_id=0x1234).create_find_entry()

        prot = sd.SOMEIPDatagramProtocol()
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
                pack_sd((entry,), session_id=i & 0xffff, reboot=i < 0x10000),
                self.fake_addr,
            )
            _mock.reset_mock()

            if i < 0x10020:
                prot.send_sd([entry], self.multi_addr)
                _mock.sendto.assert_called_once_with(
                    pack_sd((entry,), session_id=i & 0xffff, reboot=i < 0x10000),
                    self.multi_addr,
                )
                _mock.reset_mock()

            if i % 64 == 0:
                # yield to event loop every couple iterations
                await asyncio.sleep(0)

    async def test_offer_start(self):
        prot = sd.ServiceDiscoveryProtocol(self.multi_addr)

        payload = b'\x40\x00\x00\x00' \
            b'\x00\x00\x00\x30' \
            b'\x06\x00\x00\x21\x88\x99\x66\x77\xEE\x20\x21\x22\x00\x00\x00\x10' \
            b'\x01\x01\x01\x01\x55\x66\x77\x88\x99\x00\x00\x01\xde\xad\xbe\xef' \
            b'\x01\x01\x01\x01\x55\x67\x77\x88\x99\x00\x00\x01\xde\xad\xbe\xef' \
            b'\x00\x00\x00\x20' \
            b'\x00\x09\x04\x00\x01\x02\x03\x04\x00\x11\x07\xff' \
            b'\x00\x09\x04\x00\xfe\xfd\xfc\xfb\x00\x11\xff\xff' \
            b'\x00\x05\x02\x00\x22\x22\x33\x33'

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
        mock_single = unittest.mock.Mock()
        prot.watch_service(cfg.Service(service_id=0x5566), mock_single)

        prot.datagram_received(data, self.fake_addr, multicast=False)

        await asyncio.sleep(0)

        self.assertEqual(
            mock_single.service_offered.call_args_list,
            [unittest.mock.call(
                cfg.Service(
                    service_id=0x5566,
                    instance_id=0x7788,
                    major_version=0x99,
                    minor_version=0xdeadbeef,
                    options_2=(
                        hdr.IPv4EndpointOption(
                            address=ipaddress.IPv4Address('254.253.252.251'),
                            l4proto=hdr.L4Protocols.UDP,
                            port=65535,
                        ),
                    ),
                ),
            )],
        )

        mock_single.service_stopped.assert_not_called()

        payload = b'\x40\x00\x00\x00' \
            b'\x00\x00\x00\x30' \
            b'\x06\x00\x00\x00\x88\x99\x66\x77\xEE\x00\x00\x00\x00\x00\x00\x10' \
            b'\x01\x00\x00\x00\x55\x66\x77\x88\x99\x00\x00\x00\xde\xad\xbe\xef' \
            b'\x01\x00\x00\x00\x55\x67\x77\x88\x99\x00\x00\x00\xde\xad\xbe\xef' \
            b'\x00\x00\x00\x00'

        data = hdr.SOMEIPHeader(
            service_id=hdr.SD_SERVICE,
            method_id=hdr.SD_METHOD,
            client_id=0,
            session_id=1,
            interface_version=hdr.SD_INTERFACE_VERSION,
            message_type=hdr.SOMEIPMessageType.NOTIFICATION,
            payload=payload,
        ).build()

        # send StopOffer => check if service_stopped reaches listener
        mock_single.reset_mock()
        # also install catchall-listener, but it will only receive service_stopped for 0x5566
        # as 0x5567 was ignored before
        prot.watch_all_services(mock)

        prot.datagram_received(data, self.fake_addr, multicast=False)

        await asyncio.sleep(0)

        mock.service_offered.assert_not_called()
        mock_single.service_offered.assert_not_called()

        mock.service_stopped.assert_called_once_with(cfg.Service(
            service_id=0x5566,
            instance_id=0x7788,
            major_version=0x99,
            minor_version=0xdeadbeef,
        ))

        mock_single.service_stopped.assert_called_once_with(cfg.Service(
            service_id=0x5566,
            instance_id=0x7788,
            major_version=0x99,
            minor_version=0xdeadbeef,
        ))

    async def test_sd_malformed(self):
        prot = sd.ServiceDiscoveryProtocol(self.multi_addr)

        msg = hdr.SOMEIPHeader(
            service_id=hdr.SD_SERVICE,
            method_id=hdr.SD_METHOD,
            client_id=0,
            session_id=1,
            interface_version=hdr.SD_INTERFACE_VERSION,
            message_type=hdr.SOMEIPMessageType.NOTIFICATION,
            payload=b'deadbeef',
        )

        prot.sd_message_received = unittest.mock.Mock()
        prot.log = unittest.mock.Mock()

        prot.datagram_received(msg.build(), self.fake_addr, multicast=False)

        prot.sd_message_received.assert_not_called()
        prot.log.error.assert_called_once()

        prot.log.reset_mock()

        payload = b'\x40\x00\x00\x00' \
            b'\x00\x00\x00\x30' \
            b'\x06\x00\x00\x00\x88\x99\x66\x77\xEE\x00\x00\x00\x00\x00\x00\x10' \
            b'\x01\x00\x00\x00\x55\x66\x77\x88\x99\x00\x00\x00\xde\xad\xbe\xef' \
            b'\x01\x00\x00\x00\x55\x67\x77\x88\x99\x00\x00\x00\xde\xad\xbe\xef' \
            b'\x00\x00\x00\x00'
        msg = replace(msg, payload=payload)

        prot.datagram_received(
            replace(msg, service_id=0x1234).build(),
            self.fake_addr,
            multicast=False,
        )

        prot.sd_message_received.assert_not_called()
        prot.log.error.assert_called_once()

        prot.log.reset_mock()
        prot.datagram_received(
            replace(msg, method_id=0x1234).build(),
            self.fake_addr,
            multicast=False,
        )

        prot.sd_message_received.assert_not_called()
        prot.log.error.assert_called_once()

        prot.log.reset_mock()
        prot.datagram_received(
            replace(msg, interface_version=12).build(),
            self.fake_addr,
            multicast=False,
        )

        prot.sd_message_received.assert_not_called()
        prot.log.error.assert_called_once()

        prot.log.reset_mock()
        prot.datagram_received(
            replace(msg, message_type=hdr.SOMEIPMessageType.REQUEST).build(),
            self.fake_addr,
            multicast=False,
        )

        prot.sd_message_received.assert_not_called()
        prot.log.error.assert_called_once()

        prot.log.reset_mock()
        prot.datagram_received(
            replace(msg, return_code=hdr.SOMEIPReturnCode.E_NOT_OK).build(),
            self.fake_addr,
            multicast=False,
        )

        prot.sd_message_received.assert_not_called()
        prot.log.error.assert_called_once()

    async def test_sd_subscribe_bad_ttl(self):
        with self.assertRaises(ValueError):
            sd.SubscriptionProtocol(0)
        with self.assertRaises(ValueError):
            sd.SubscriptionProtocol(sd.TTL_FOREVER)

    async def test_sd_subscribe_no_transport(self):
        prot = sd.SubscriptionProtocol(ttl=None, refresh_interval=None)
        prot.log = unittest.mock.Mock()

        evgrp_1 = cfg.Eventgroup(service_id=0x1111, instance_id=0x4444, major_version=0x66,
                                 eventgroup_id=0xccdd, sockname=self.fake_addr,
                                 protocol=hdr.L4Protocols.UDP)

        prot.subscribe_eventgroup(evgrp_1, self.multi_addr)
        prot.start()
        await asyncio.sleep(0)
        prot.stop()

        prot.log.error.assert_called_once()


class _BaseSDTest(unittest.IsolatedAsyncioTestCase):
    multi_addr = ('2001:db8::1', 30490, 0, 0)
    fake_addr = ('2001:db8::2', 30490, 0, 0)
    TTL = sd.TTL_FOREVER

    async def asyncSetUp(self):  # noqa: N802
        self.prot = sd.ServiceDiscoveryProtocol(self.multi_addr)

        self.offer_5566 = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.OfferService,
            service_id=0x5566,
            instance_id=0x7788,
            major_version=1,
            ttl=self.TTL,
            minver_or_counter=0xdeadbeef,
            options_1=(
                hdr.IPv4EndpointOption(
                    address=ipaddress.IPv4Address('254.253.252.251'),
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

        self.prot.datagram_received(
            pack_sd((self.offer_5566, self.offer_5567), session_id=100, reboot=False),
            self.fake_addr, multicast=False,
        )

        await asyncio.sleep(0)

        self.assertEqual(
            self.mock.service_offered.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566),
                unittest.mock.call(self.cfg_offer_5567),
            ],
        )

        self.mock_single.service_offered.assert_called_once_with(self.cfg_offer_5566)
        self.mock.service_stopped.assert_not_called()
        self.mock_single.service_stopped.assert_not_called()

        await asyncio.sleep(0.8)

        self.mock.reset_mock()
        self.mock_single.reset_mock()


class TestSDTTLForever(_BaseSDTest):
    TTL = sd.TTL_FOREVER

    async def test_sd_reboot_ttl_forever(self):
        prot = self.prot
        mock = self.mock
        mock_single = self.mock_single

        prot.datagram_received(
            pack_sd((self.offer_5566, self.offer_5567), reboot=False, session_id=0x1000),
            self.fake_addr, multicast=False,
        )

        await asyncio.sleep(0)

        mock.service_offered.assert_not_called()
        mock_single.service_offered.assert_not_called()
        mock.service_stopped.assert_not_called()
        mock_single.service_stopped.assert_not_called()

        prot.datagram_received(
            pack_sd((self.offer_5566, self.offer_5567), reboot=False, session_id=1),
            self.fake_addr, multicast=False,
        )

        await asyncio.sleep(0)

        mock.service_offered.assert_not_called()
        mock_single.service_offered.assert_not_called()
        mock.service_stopped.assert_not_called()
        mock_single.service_stopped.assert_not_called()

        prot.datagram_received(
            pack_sd((self.offer_5566, self.offer_5567), reboot=True, session_id=7),
            self.fake_addr, multicast=False,
        )

        await asyncio.sleep(0)

        self.assertEqual(
            mock.service_offered.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566),
                unittest.mock.call(self.cfg_offer_5567),
            ],
        )

        self.assertEqual(
            mock_single.service_offered.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566),
            ],
        )
        self.assertEqual(
            mock.service_stopped.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566),
                unittest.mock.call(self.cfg_offer_5567),
            ],
        )

        mock_single.service_stopped.assert_called_once_with(self.cfg_offer_5566)

        # send stopoffer, should reach listener
        mock.reset_mock()
        mock_single.reset_mock()

        prot.datagram_received(
            pack_sd((self.stop_offer_5566, self.offer_5567), session_id=12),
            self.fake_addr, multicast=False,
        )
        await asyncio.sleep(0)

        mock.service_offered.assert_not_called()
        mock_single.service_offered.assert_not_called()
        mock.service_stopped.assert_called_once_with(self.cfg_offer_5566)
        mock_single.service_stopped.assert_called_once_with(self.cfg_offer_5566)

    async def test_sd_disconnect(self):
        self.prot.connection_lost(None)

        await asyncio.sleep(0)

        self.assertEqual(
            self.mock.service_stopped.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566),
                unittest.mock.call(self.cfg_offer_5567),
            ],
        )
        self.mock_single.service_stopped.assert_called_once_with(self.cfg_offer_5566)

        self.mock.reset_mock()
        self.mock_single.reset_mock()


class TestSDTTL1(_BaseSDTest):
    TTL = 1

    async def test_sd_disconnect(self):
        self.prot.connection_lost(None)

        await asyncio.sleep(0)

        self.assertEqual(
            self.mock.service_stopped.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566),
                unittest.mock.call(self.cfg_offer_5567),
            ],
        )
        self.mock_single.service_stopped.assert_called_once_with(self.cfg_offer_5566)

        self.mock.reset_mock()
        self.mock_single.reset_mock()

    async def test_sd_reboot(self):
        self.prot.datagram_received(
            pack_sd((self.offer_5566, self.offer_5567), session_id=7, reboot=True),
            self.fake_addr, multicast=False,
        )

        await asyncio.sleep(0)

        self.assertEqual(
            self.mock.service_offered.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566),
                unittest.mock.call(self.cfg_offer_5567),
            ],
        )

        self.mock_single.service_offered.assert_called_once_with(self.cfg_offer_5566)

        self.assertEqual(
            self.mock.service_stopped.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566),
                unittest.mock.call(self.cfg_offer_5567),
            ],
        )

        self.mock_single.service_stopped.assert_called_once_with(self.cfg_offer_5566)

        # wait for timeout of initial service, should not call service_stopped since
        # it was removed by reboot detection
        self.mock.reset_mock()
        self.mock_single.reset_mock()

        await asyncio.sleep(0.8)

        self.mock.service_offered.assert_not_called()
        self.mock_single.service_offered.assert_not_called()
        self.mock.service_stopped.assert_not_called()
        self.mock_single.service_stopped.assert_not_called()

    async def test_sd(self):
        self.prot.datagram_received(
            pack_sd((self.offer_5566, self.offer_5567), session_id=2, reboot=False),
            self.fake_addr, multicast=False,
        )

        await asyncio.sleep(0)

        self.mock.service_offered.assert_not_called()
        self.mock_single.service_offered.assert_not_called()
        self.mock.service_stopped.assert_not_called()
        self.mock_single.service_stopped.assert_not_called()

        await asyncio.sleep(1.2)

        self.assertEqual(
            self.mock.service_stopped.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566),
                unittest.mock.call(self.cfg_offer_5567),
            ],
        )
        self.mock_single.service_stopped.assert_called_once_with(self.cfg_offer_5566)

        self.mock.service_offered.assert_not_called()
        self.mock_single.service_offered.assert_not_called()

        self.mock.reset_mock()
        self.mock_single.reset_mock()

        self.prot.datagram_received(
            pack_sd((self.offer_5566, self.offer_5567), session_id=5, reboot=False),
            self.fake_addr, multicast=False,
        )

        await asyncio.sleep(0)

        self.assertEqual(
            self.mock.service_offered.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566),
                unittest.mock.call(self.cfg_offer_5567),
            ],
        )

        self.mock_single.service_offered.assert_called_once_with(self.cfg_offer_5566)
        self.mock.service_stopped.assert_not_called()
        self.mock_single.service_stopped.assert_not_called()

        self.mock.reset_mock()
        self.mock_single.reset_mock()

        await asyncio.sleep(1.2)

        self.assertEqual(
            self.mock.service_stopped.call_args_list,
            [
                unittest.mock.call(self.cfg_offer_5566),
                unittest.mock.call(self.cfg_offer_5567),
            ],
        )
        self.mock_single.service_stopped.assert_called_once_with(self.cfg_offer_5566)
        self.mock.service_offered.assert_not_called()
        self.mock_single.service_offered.assert_not_called()

        # service already removed by timeout detection above.
        # send stopoffer again, should not reach listener
        self.mock.reset_mock()
        self.mock_single.reset_mock()

        self.prot.datagram_received(
            pack_sd((self.stop_offer_5566, self.offer_5567), session_id=7, reboot=False),
            self.fake_addr, multicast=False,
        )
        await asyncio.sleep(0)

        self.mock.service_offered.assert_called_once_with(self.cfg_offer_5567)
        self.mock_single.service_offered.assert_not_called()
        self.mock.service_stopped.assert_not_called()
        self.mock_single.service_stopped.assert_not_called()


class TestSDFind(unittest.IsolatedAsyncioTestCase):
    multi_addr = ('2001:db8::1', 30490, 0, 0)
    fake_addr = ('2001:db8::2', 30490, 0, 0)

    async def asyncSetUp(self):  # noqa: N802
        self.prot = sd.ServiceDiscoveryProtocol(self.multi_addr)

        self.send_times = []

        def _mock_sendto(*args, **kwargs):
            self.send_times.append(asyncio.get_running_loop().time())
            return unittest.mock.DEFAULT

        self.prot.transport = unittest.mock.Mock()
        self.prot.transport.sendto.side_effect = _mock_sendto

        self.prot.INITIAL_DELAY_MIN = 0.2
        self.prot.INITIAL_DELAY_MAX = 0.2
        self.prot.REPETITIONS_BASE_DELAY = 0.1
        self.prot.REPETITIONS_MAX = 3
        self.t_start = asyncio.get_running_loop().time()

    async def test_send_find(self):
        mock = unittest.mock.Mock()
        self.prot.watch_service(cfg.Service(service_id=0x5566), mock)

        await self.prot.send_find_services()

        find_5566 = bytearray(
            b'\xff\xff\x81\x00\x00\x00\x00\x24\x00\x00\x00\x01\x01\x01\x02\x00'
            b'\xc0\x00\x00\x00\x00\x00\x00\x10'
            b'\x00\x00\x00\x00\x55\x66\xff\xff\xff\x00\x00\x03\xff\xff\xff\xff'
            b'\x00\x00\x00\x00',
        )
        find_5566_1 = bytes(find_5566)
        find_5566[11] = 2
        find_5566_2 = bytes(find_5566)
        find_5566[11] = 3
        find_5566_3 = bytes(find_5566)

        self.assertEqual(
            self.prot.transport.sendto.call_args_list,
            [
                unittest.mock.call(find_5566_1, self.multi_addr),
                unittest.mock.call(find_5566_2, self.multi_addr),
                unittest.mock.call(find_5566_3, self.multi_addr),
            ],
        )

        tdiffs = [t - self.t_start for t in self.send_times]
        self.assertAlmostEqual(tdiffs[0], 0.2, places=1)
        self.assertAlmostEqual(tdiffs[1], 0.3, places=1)
        self.assertAlmostEqual(tdiffs[2], 0.5, places=1)

    async def test_send_no_finds_early_offer(self):
        mock = unittest.mock.Mock()
        self.prot.watch_service(cfg.Service(service_id=0x5566), mock)

        t = asyncio.create_task(self.prot.send_find_services())

        await asyncio.sleep(0.02)

        data = pack_sd([hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.OfferService,
            service_id=0x5566,
            instance_id=0x7788,
            major_version=1,
            ttl=1,
            minver_or_counter=0xdeadbeef,
            options_1=(
                hdr.IPv4EndpointOption(
                    address=ipaddress.IPv4Address('254.253.252.251'),
                    l4proto=hdr.L4Protocols.UDP,
                    port=65535,
                ),
            ),
        )])

        self.prot.datagram_received(data, self.fake_addr, multicast=True)

        await t
        self.prot.transport.sendto.assert_not_called()

    async def test_send_no_finds(self):
        await self.prot.send_find_services()
        self.prot.transport.sendto.assert_not_called()

    async def test_send_multiple_services_one_offer_early(self):
        mock = unittest.mock.Mock()
        self.prot.watch_service(cfg.Service(service_id=0x5566), mock)
        self.prot.watch_service(cfg.Service(service_id=0x4433), mock)

        t = asyncio.create_task(self.prot.send_find_services())

        await asyncio.sleep(0.02)

        data = pack_sd([hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.OfferService,
            service_id=0x4433,
            instance_id=0x7788,
            major_version=1,
            ttl=1,
            minver_or_counter=0xdeadbeef,
            options_1=(
                hdr.IPv4EndpointOption(
                    address=ipaddress.IPv4Address('254.253.252.251'),
                    l4proto=hdr.L4Protocols.UDP,
                    port=65535,
                ),
            ),
        )])

        self.prot.datagram_received(data, self.fake_addr, multicast=True)

        await t

        find_5566 = bytearray(
            b'\xff\xff\x81\x00\x00\x00\x00\x24\x00\x00\x00\x01\x01\x01\x02\x00'
            b'\xc0\x00\x00\x00\x00\x00\x00\x10'
            b'\x00\x00\x00\x00\x55\x66\xff\xff\xff\x00\x00\x03\xff\xff\xff\xff'
            b'\x00\x00\x00\x00',
        )
        find_5566_1 = bytes(find_5566)
        find_5566[11] = 2
        find_5566_2 = bytes(find_5566)
        find_5566[11] = 3
        find_5566_3 = bytes(find_5566)

        self.assertEqual(
            self.prot.transport.sendto.call_args_list,
            [
                unittest.mock.call(find_5566_1, self.multi_addr),
                unittest.mock.call(find_5566_2, self.multi_addr),
                unittest.mock.call(find_5566_3, self.multi_addr),
            ],
        )

        tdiffs = [t - self.t_start for t in self.send_times]
        self.assertAlmostEqual(tdiffs[0], 0.2, places=1)
        self.assertAlmostEqual(tdiffs[1], 0.3, places=1)
        self.assertAlmostEqual(tdiffs[2], 0.5, places=1)


class TestEventgroup(unittest.IsolatedAsyncioTestCase):
    local_addr = ('2001:db8::ff', 30331, 0, 0)
    remote1_addr = ('2001:db8::1', 30332, 0, 0)
    remote2_addr = ('2001:db8::2', 30337, 0, 0)
    maxDiff = None

    async def asyncSetUp(self):  # noqa: N802
        self.prot = sd.SubscriptionProtocol(ttl=self.TTL, refresh_interval=self.REFRESH_INTERVAL)
        self.prot.ttl_offset = 2

        self.evgrp_1 = cfg.Eventgroup(service_id=0x1111, instance_id=0x4444, major_version=0x66,
                                      eventgroup_id=0xccdd, sockname=self.local_addr,
                                      protocol=hdr.L4Protocols.UDP)
        self.sub_evgrp_1 = self.evgrp_1.create_subscribe_entry(self.TTL or 0xffffff)
        self.stop_sub_evgrp_1 = self.evgrp_1.create_subscribe_entry(0)

        self.evgrp_2 = cfg.Eventgroup(service_id=0x2222, instance_id=0x5555, major_version=0x66,
                                      eventgroup_id=0xccdd, sockname=self.local_addr,
                                      protocol=hdr.L4Protocols.UDP)
        self.sub_evgrp_2 = self.evgrp_2.create_subscribe_entry(self.TTL or 0xffffff)
        self.stop_sub_evgrp_2 = self.evgrp_2.create_subscribe_entry(0)

        self.evgrp_3 = cfg.Eventgroup(service_id=0x3333, instance_id=0x6666, major_version=0x77,
                                      eventgroup_id=0xaabb, sockname=self.local_addr,
                                      protocol=hdr.L4Protocols.UDP)
        self.sub_evgrp_3 = self.evgrp_3.create_subscribe_entry(self.TTL or 0xffffff)
        self.stop_sub_evgrp_3 = self.evgrp_3.create_subscribe_entry(0)

        self.prot.transport = unittest.mock.Mock()
        self._mock_sendto = self.prot.transport.sendto


class TestEventgroupTTL3(TestEventgroup):
    TTL = 3
    REFRESH_INTERVAL = 1

    async def test_subscribe(self):
        self.prot.subscribe_eventgroup(self.evgrp_1, self.remote1_addr)
        self.prot.subscribe_eventgroup(self.evgrp_2, self.remote2_addr)
        self.prot.start()

        await asyncio.sleep(0)

        self.assertCountEqual(
            self._mock_sendto.call_args_list,
            (
                unittest.mock.call(pack_sd((self.sub_evgrp_1,)), self.remote1_addr),
                unittest.mock.call(pack_sd((self.sub_evgrp_2,)), self.remote2_addr),
            ),
        )
        self._mock_sendto.reset_mock()

        # add new eventgroup, show subscription in next cycle
        self.prot.subscribe_eventgroup(self.evgrp_3, self.remote1_addr)

        await asyncio.sleep(1)

        self.assertCountEqual(
            self._mock_sendto.call_args_list,
            (
                unittest.mock.call(pack_sd((
                    self.sub_evgrp_1, self.sub_evgrp_3,
                ), session_id=2), self.remote1_addr),
                unittest.mock.call(pack_sd((self.sub_evgrp_2,), session_id=2), self.remote2_addr),
            ),
        )
        self._mock_sendto.reset_mock()

        # remove eventgroup, send stop subscribe
        self.prot.stop_subscribe_eventgroup(self.evgrp_1, self.remote1_addr)

        await asyncio.sleep(0)

        self._mock_sendto.assert_called_once_with(
            pack_sd((self.stop_sub_evgrp_1,), session_id=3),
            self.remote1_addr,
        )
        self._mock_sendto.reset_mock()

        # remove eventgroup again => don't send stop again
        self.prot.stop_subscribe_eventgroup(self.evgrp_1, self.remote1_addr)

        await asyncio.sleep(0)

        self._mock_sendto.assert_not_called()
        self._mock_sendto.reset_mock()

        # show changed subscription messages after stop
        await asyncio.sleep(1)

        self.assertCountEqual(
            self._mock_sendto.call_args_list,
            (
                unittest.mock.call(pack_sd((self.sub_evgrp_3,), session_id=4), self.remote1_addr),
                unittest.mock.call(pack_sd((self.sub_evgrp_2,), session_id=3), self.remote2_addr),
            ),
        )
        self._mock_sendto.reset_mock()

        # remove last eventgroup of endpoint, send stop subscribe
        self.prot.stop_subscribe_eventgroup(self.evgrp_3, self.remote1_addr)

        await asyncio.sleep(0)

        self._mock_sendto.assert_called_once_with(
            pack_sd((self.stop_sub_evgrp_3,), session_id=5),
            self.remote1_addr,
        )
        self._mock_sendto.reset_mock()

        # show changed subscription messages after stop
        await asyncio.sleep(1)

        self._mock_sendto.assert_called_once_with(
            pack_sd((self.sub_evgrp_2,), session_id=4),
            self.remote2_addr,
        )
        self._mock_sendto.reset_mock()


class TestEventgroupTTLForever(TestEventgroup):
    TTL = None
    REFRESH_INTERVAL = None

    async def test_subscribe(self):
        self.prot.subscribe_eventgroup(self.evgrp_1, self.remote1_addr)
        self.prot.subscribe_eventgroup(self.evgrp_2, self.remote2_addr)
        self.prot.start()

        await asyncio.sleep(0)

        self.assertCountEqual(
            self._mock_sendto.call_args_list,
            (
                unittest.mock.call(pack_sd((self.sub_evgrp_1,)), self.remote1_addr),
                unittest.mock.call(pack_sd((self.sub_evgrp_2,)), self.remote2_addr),
            ),
        )
        self._mock_sendto.reset_mock()

        self.prot.subscribe_eventgroup(self.evgrp_3, self.remote1_addr)

        await asyncio.sleep(0)
        self._mock_sendto.assert_called_once_with(
            pack_sd((self.sub_evgrp_3,), session_id=2),
            self.remote1_addr,
        )

    async def test_sd_stop_send_stop(self):
        self.prot.subscribe_eventgroup(self.evgrp_1, self.remote1_addr)
        self.prot.start()
        await asyncio.sleep(0)

        self._mock_sendto.assert_called_once_with(
            pack_sd((self.sub_evgrp_1,), session_id=1),
            self.remote1_addr,
        )
        self._mock_sendto.reset_mock()

        self.prot.stop()

        await asyncio.sleep(0)

        self._mock_sendto.assert_called_once_with(
            pack_sd((self.stop_sub_evgrp_1,), session_id=2),
            self.remote1_addr,
        )

    async def test_sd_stop_no_send_stop(self):
        self.prot.subscribe_eventgroup(self.evgrp_1, self.remote1_addr)
        self.prot.start()
        await asyncio.sleep(0)

        self._mock_sendto.assert_called_once_with(
            pack_sd((self.sub_evgrp_1,), session_id=1),
            self.remote1_addr,
        )
        self._mock_sendto.reset_mock()

        self.prot.stop(send_stop_subscribe=False)

        await asyncio.sleep(0)

        self._mock_sendto.assert_not_called()


if __name__ == '__main__':
    unittest.main()
