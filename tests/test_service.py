from __future__ import annotations

import asyncio
import logging
import ipaddress
import os
import typing
import unittest
import unittest.mock
from dataclasses import replace

import someip.config as cfg
import someip.header as hdr
import someip.sd as sd
import someip.service as service

logging.captureWarnings(True)
logging.basicConfig(level=logging.DEBUG)

logging.getLogger("asyncio").setLevel(logging.WARNING)
logging.getLogger("someip").setLevel(logging.WARNING)


PRECISION = 0.4 if os.environ.get("CI") == "true" else 0.2  # in seconds


def ticks(n):
    return PRECISION * n


async def settle():
    fut: asyncio.Future[None] = asyncio.Future()
    asyncio.get_event_loop().call_soon(fut.set_result, None)
    await fut


class ExampleEvgrp(service.SimpleEventgroup):
    def __init__(self, service: ExampleService):
        super().__init__(service, id=1, interval=ticks(1))

        self.service: ExampleService

        self.update_task = asyncio.create_task(self.update())

    async def update(self):
        while True:
            self.values[1] = self.service.counter.to_bytes(2, "big")
            await asyncio.sleep(ticks(0.9))


class ExampleService(service.SimpleService):
    service_id = 0xB0A7
    version_major = 1
    version_minor = 0

    def __init__(self, instance_id):
        super().__init__(instance_id)
        self.counter = 0
        self.register_method(1, self.method_get_counter)
        self.register_method(2, self.method_increment_counter)
        self.register_method(3, self.method_set_counter)
        self.register_method(4, self.method_reset_counter)
        self.eventgroup = ExampleEvgrp(self)
        self.register_eventgroup(self.eventgroup)

    def method_get_counter(
        self, someip_message: hdr.SOMEIPHeader, addr: hdr._T_SOCKNAME
    ) -> typing.Optional[bytes]:
        # only handle empty get requests
        if someip_message.payload:
            raise service.MalformedMessageError

        return self.counter.to_bytes(2, "big")

    def method_increment_counter(
        self, someip_message: hdr.SOMEIPHeader, addr: hdr._T_SOCKNAME
    ) -> typing.Optional[bytes]:
        # only handle empty get requests
        if someip_message.payload:
            raise service.MalformedMessageError

        self.counter += 1

        return b""

    def method_set_counter(
        self, someip_message: hdr.SOMEIPHeader, addr: hdr._T_SOCKNAME
    ) -> typing.Optional[bytes]:
        if len(someip_message.payload) != 2:
            raise service.MalformedMessageError

        self.counter = int.from_bytes(someip_message.payload, "big")
        return b""

    def method_reset_counter(
        self, someip_message: hdr.SOMEIPHeader, addr: hdr._T_SOCKNAME
    ) -> typing.Optional[bytes]:
        # only handle empty get requests
        if someip_message.payload:
            raise service.MalformedMessageError

        self.counter = 0

        return b""


class TestService(unittest.IsolatedAsyncioTestCase):
    fake_addr = ("2001:db8::2", 30501, 0, 0)

    async def asyncSetUp(self):  # noqa: N802
        inst = 12
        self.prot = ExampleService(inst)
        self.mock = self.prot.transport = unittest.mock.Mock()
        self.endpoint = hdr.IPv6EndpointOption(
            ipaddress.IPv6Address(self.fake_addr[0]),
            port=self.fake_addr[1],
            l4proto=hdr.L4Protocols.UDP,
        )

    def test_start_announce(self):
        sd = unittest.mock.Mock()

        ip, port = ("192.0.2.42", 30501)

        def get_extra_info(key):
            assert key == "sockname"
            return ip, port

        self.prot.transport.get_extra_info.side_effect = get_extra_info

        self.prot.start_announce(sd)

        ep = hdr.IPv4EndpointOption(
            ipaddress.IPv4Address(ip),
            port=port,
            l4proto=hdr.L4Protocols.UDP,
        )

        self.assertEqual(
            sd.method_calls,
            [
                unittest.mock.call.announce_service(
                    cfg.Service(
                        service_id=self.prot.service_id,
                        instance_id=self.prot.instance_id,
                        major_version=self.prot.version_major,
                        minor_version=self.prot.version_minor,
                        options_1=(ep,),
                        eventgroups=frozenset({self.prot.eventgroup.id}),
                    ),
                    self.prot,
                )
            ],
        )
        sd.reset_mock()

        self.prot.stop_announce(sd)
        self.assertEqual(
            sd.method_calls,
            [
                unittest.mock.call.stop_announce_service(
                    cfg.Service(
                        service_id=self.prot.service_id,
                        instance_id=self.prot.instance_id,
                        major_version=self.prot.version_major,
                        minor_version=self.prot.version_minor,
                        options_1=(ep,),
                        eventgroups=frozenset({self.prot.eventgroup.id}),
                    ),
                    self.prot,
                )
            ],
        )

    def test_call_good(self):
        get = hdr.SOMEIPHeader(
            service_id=self.prot.service_id,
            method_id=1,
            client_id=0xCCCC,
            session_id=0xDDDD,
            protocol_version=1,
            interface_version=self.prot.version_major,
            message_type=hdr.SOMEIPMessageType.REQUEST,
            return_code=hdr.SOMEIPReturnCode.E_OK,
        )
        inc = replace(
            get, method_id=2, message_type=hdr.SOMEIPMessageType.REQUEST_NO_RETURN
        )

        self.prot.message_received(get, self.fake_addr, False)

        self.mock.sendto.assert_called_once_with(
            replace(
                get, message_type=hdr.SOMEIPMessageType.RESPONSE, payload=b"\0\0"
            ).build(),
            self.fake_addr,
        )
        self.mock.reset_mock()

        # stays the same
        self.prot.message_received(get, self.fake_addr, False)

        self.mock.sendto.assert_called_once_with(
            replace(
                get, message_type=hdr.SOMEIPMessageType.RESPONSE, payload=b"\0\0"
            ).build(),
            self.fake_addr,
        )
        self.mock.reset_mock()

        # increment twice
        self.prot.message_received(inc, self.fake_addr, False)
        self.prot.message_received(inc, self.fake_addr, False)

        self.mock.sendto.assert_not_called()

        self.mock.reset_mock()

        # counter changed
        self.prot.message_received(get, self.fake_addr, False)

        self.mock.sendto.assert_called_once_with(
            replace(
                get, message_type=hdr.SOMEIPMessageType.RESPONSE, payload=b"\0\2"
            ).build(),
            self.fake_addr,
        )
        self.mock.reset_mock()

    def test_call_unknown_service(self):
        get = hdr.SOMEIPHeader(
            service_id=0xABAB,
            method_id=1,
            client_id=0xCCCC,
            session_id=0xDDDD,
            protocol_version=1,
            interface_version=self.prot.version_major,
            message_type=hdr.SOMEIPMessageType.REQUEST,
            return_code=hdr.SOMEIPReturnCode.E_OK,
        )

        with self.assertLogs(self.prot.log, "WARNING"):
            self.prot.message_received(get, self.fake_addr, False)

        self.mock.sendto.assert_called_once_with(
            replace(
                get,
                message_type=hdr.SOMEIPMessageType.ERROR,
                return_code=hdr.SOMEIPReturnCode.E_UNKNOWN_SERVICE,
            ).build(),
            self.fake_addr,
        )
        self.mock.reset_mock()

    def test_call_bad_version(self):
        get = hdr.SOMEIPHeader(
            service_id=self.prot.service_id,
            method_id=1,
            client_id=0xCCCC,
            session_id=0xDDDD,
            protocol_version=1,
            interface_version=13,
            message_type=hdr.SOMEIPMessageType.REQUEST_NO_RETURN,
            return_code=hdr.SOMEIPReturnCode.E_OK,
        )

        with self.assertLogs(self.prot.log, "WARNING"):
            self.prot.message_received(get, self.fake_addr, False)

        self.mock.sendto.assert_called_once_with(
            replace(
                get,
                message_type=hdr.SOMEIPMessageType.ERROR,
                return_code=hdr.SOMEIPReturnCode.E_WRONG_INTERFACE_VERSION,
            ).build(),
            self.fake_addr,
        )
        self.mock.reset_mock()

    def test_call_unknown_method(self):
        get = hdr.SOMEIPHeader(
            service_id=self.prot.service_id,
            method_id=0x7777,
            client_id=0xCCCC,
            session_id=0xDDDD,
            protocol_version=1,
            interface_version=self.prot.version_major,
            message_type=hdr.SOMEIPMessageType.REQUEST_NO_RETURN,
            return_code=hdr.SOMEIPReturnCode.E_OK,
        )

        with self.assertLogs(self.prot.log, "WARNING"):
            self.prot.message_received(get, self.fake_addr, False)

        self.mock.sendto.assert_called_once_with(
            replace(
                get,
                message_type=hdr.SOMEIPMessageType.ERROR,
                return_code=hdr.SOMEIPReturnCode.E_UNKNOWN_METHOD,
            ).build(),
            self.fake_addr,
        )
        self.mock.reset_mock()

    def test_call_bad_type(self):
        get = hdr.SOMEIPHeader(
            service_id=self.prot.service_id,
            method_id=1,
            client_id=0xCCCC,
            session_id=0xDDDD,
            protocol_version=1,
            interface_version=self.prot.version_major,
            message_type=hdr.SOMEIPMessageType.ERROR,
            return_code=hdr.SOMEIPReturnCode.E_OK,
        )

        with self.assertLogs(self.prot.log, "WARNING"):
            self.prot.message_received(get, self.fake_addr, False)

        self.mock.sendto.assert_called_once_with(
            replace(
                get,
                message_type=hdr.SOMEIPMessageType.ERROR,
                return_code=hdr.SOMEIPReturnCode.E_WRONG_MESSAGE_TYPE,
            ).build(),
            self.fake_addr,
        )
        self.mock.reset_mock()

    def test_call_bad_code(self):
        get = hdr.SOMEIPHeader(
            service_id=self.prot.service_id,
            method_id=1,
            client_id=0xCCCC,
            session_id=0xDDDD,
            protocol_version=1,
            interface_version=self.prot.version_major,
            message_type=hdr.SOMEIPMessageType.REQUEST,
            return_code=hdr.SOMEIPReturnCode.E_NOT_READY,
        )

        with self.assertLogs(self.prot.log, "WARNING"):
            self.prot.message_received(get, self.fake_addr, False)

        self.mock.sendto.assert_called_once_with(
            replace(
                get,
                message_type=hdr.SOMEIPMessageType.ERROR,
                return_code=hdr.SOMEIPReturnCode.E_WRONG_MESSAGE_TYPE,
            ).build(),
            self.fake_addr,
        )
        self.mock.reset_mock()

    def test_call_multicast(self):
        get = hdr.SOMEIPHeader(
            service_id=self.prot.service_id,
            method_id=1,
            client_id=0xCCCC,
            session_id=0xDDDD,
            protocol_version=1,
            interface_version=self.prot.version_major,
            message_type=hdr.SOMEIPMessageType.REQUEST,
            return_code=hdr.SOMEIPReturnCode.E_OK,
        )
        with self.assertWarnsRegex(UserWarning, r"(?i)multicast"):
            self.prot.message_received(get, self.fake_addr, True)

    def test_call_malformed(self):
        get = hdr.SOMEIPHeader(
            service_id=self.prot.service_id,
            method_id=1,
            client_id=0xCCCC,
            session_id=0xDDDD,
            protocol_version=1,
            interface_version=self.prot.version_major,
            message_type=hdr.SOMEIPMessageType.REQUEST,
            return_code=hdr.SOMEIPReturnCode.E_OK,
            payload=b"\xff\xff",
        )

        self.prot.message_received(get, self.fake_addr, False)

        self.mock.sendto.assert_called_once_with(
            replace(
                get,
                payload=b"",
                message_type=hdr.SOMEIPMessageType.ERROR,
                return_code=hdr.SOMEIPReturnCode.E_MALFORMED_MESSAGE,
            ).build(),
            self.fake_addr,
        )
        self.mock.reset_mock()

    def test_register_duplicate(self):
        with self.assertRaises(KeyError):
            self.prot.register_method(1, self.prot.method_reset_counter)
        with self.assertRaises(KeyError):
            self.prot.register_eventgroup(service.SimpleEventgroup(self.prot, id=1))

    async def test_subscribe_eventgroup(self):
        sub = sd.EventgroupSubscription(
            service_id=self.prot.service_id,
            instance_id=self.prot.instance_id,
            major_version=self.prot.version_major,
            id=1,
            counter=0,
            ttl=ticks(3),
            endpoints=frozenset({self.endpoint}),
        )
        self.prot.client_subscribed(sub, self.fake_addr)

        notification = hdr.SOMEIPHeader(
            service_id=self.prot.service_id,
            method_id=0x8001,
            client_id=0,
            session_id=0,
            interface_version=self.prot.version_major,
            message_type=hdr.SOMEIPMessageType.NOTIFICATION,
        )

        # notification after subscribe
        await asyncio.sleep(ticks(0.1))
        self.mock.sendto.assert_called_once_with(
            replace(
                notification,
                session_id=1,
                payload=b"\0\0",
            ).build(),
            self.fake_addr,
        )
        self.mock.reset_mock()

        # cyclic notification
        await asyncio.sleep(ticks(1.1))
        self.mock.sendto.assert_called_once_with(
            replace(
                notification,
                session_id=2,
                payload=b"\0\0",
            ).build(),
            self.fake_addr,
        )
        self.mock.reset_mock()

        inc = hdr.SOMEIPHeader(
            service_id=self.prot.service_id,
            method_id=2,
            client_id=0xCCCC,
            session_id=0xDDDD,
            protocol_version=1,
            interface_version=self.prot.version_major,
            message_type=hdr.SOMEIPMessageType.REQUEST_NO_RETURN,
        )
        self.prot.message_received(inc, self.fake_addr, False)

        # cyclic notification
        await asyncio.sleep(ticks(1.1))
        self.mock.sendto.assert_called_once_with(
            replace(
                notification,
                session_id=3,
                payload=b"\0\1",
            ).build(),
            self.fake_addr,
        )
        self.mock.reset_mock()

    async def test_subscribe_eventgroup_two_clients(self):
        sub1 = sd.EventgroupSubscription(
            service_id=self.prot.service_id,
            instance_id=self.prot.instance_id,
            major_version=self.prot.version_major,
            id=1,
            counter=0,
            ttl=ticks(3),
            endpoints=frozenset({self.endpoint}),
        )
        self.prot.client_subscribed(sub1, self.fake_addr)

        fake_addr2 = ("192.0.2.42", 30501)

        endpoint2 = hdr.IPv4EndpointOption(
            ipaddress.IPv4Address(fake_addr2[0]),
            port=fake_addr2[1],
            l4proto=hdr.L4Protocols.UDP,
        )
        sub2 = sd.EventgroupSubscription(
            service_id=self.prot.service_id,
            instance_id=self.prot.instance_id,
            major_version=self.prot.version_major,
            id=1,
            counter=0,
            ttl=ticks(3),
            endpoints=frozenset({endpoint2}),
        )
        self.prot.client_subscribed(sub2, fake_addr2)

        notification = hdr.SOMEIPHeader(
            service_id=self.prot.service_id,
            method_id=0x8001,
            client_id=0,
            session_id=0,
            interface_version=self.prot.version_major,
            message_type=hdr.SOMEIPMessageType.NOTIFICATION,
        )

        # ignore notification after subscribe
        await asyncio.sleep(ticks(0.1))
        self.mock.reset_mock()

        # cyclic notification
        await asyncio.sleep(ticks(1.1))
        self.assertCountEqual(
            self.mock.sendto.call_args_list,
            (
                unittest.mock.call(
                    replace(
                        notification,
                        session_id=2,
                        payload=b"\0\0",
                    ).build(),
                    self.fake_addr,
                ),
                unittest.mock.call(
                    replace(
                        notification,
                        session_id=2,
                        payload=b"\0\0",
                    ).build(),
                    fake_addr2,
                ),
            ),
        )
        self.mock.reset_mock()

        self.prot.client_unsubscribed(sub2, fake_addr2)

        # one client removed -> one remaining cyclic notification
        await asyncio.sleep(ticks(1.1))
        self.assertCountEqual(
            self.mock.sendto.call_args_list,
            (
                unittest.mock.call(
                    replace(
                        notification,
                        session_id=3,
                        payload=b"\0\0",
                    ).build(),
                    self.fake_addr,
                ),
            ),
        )
        self.mock.reset_mock()

        self.prot.client_unsubscribed(sub1, self.fake_addr)

        # cyclic notification
        await asyncio.sleep(ticks(1.1))

        self.mock.sendto.assert_not_called()

    def test_unsubscribe_unknown(self):
        sub = sd.EventgroupSubscription(
            service_id=self.prot.service_id,
            instance_id=self.prot.instance_id,
            major_version=self.prot.version_major,
            id=1,
            counter=0,
            ttl=ticks(3),
            endpoints=frozenset({self.endpoint}),
        )

        with self.assertLogs(self.prot.log, "WARNING"):
            self.prot.client_unsubscribed(sub, self.fake_addr)

    def test_nak_subscription(self):
        self.prot.eventgroup.subscribe = unittest.mock.Mock()
        self.prot.eventgroup.subscribe.side_effect = sd.NakSubscription

        sub = sd.EventgroupSubscription(
            service_id=self.prot.service_id,
            instance_id=self.prot.instance_id,
            major_version=self.prot.version_major,
            id=1,
            counter=0,
            ttl=ticks(3),
            endpoints=frozenset({self.endpoint}),
        )

        with self.assertLogs(self.prot.log, "ERROR"):
            with self.assertRaises(sd.NakSubscription):
                self.prot.client_subscribed(sub, self.fake_addr)

    def test_nak_malformed(self):
        fake_addr2 = ("192.0.2.42", 30501)

        endpoint2 = hdr.IPv4EndpointOption(
            ipaddress.IPv4Address(fake_addr2[0]),
            port=fake_addr2[1],
            l4proto=hdr.L4Protocols.UDP,
        )

        sub = sd.EventgroupSubscription(
            service_id=self.prot.service_id,
            instance_id=self.prot.instance_id,
            major_version=self.prot.version_major,
            id=1,
            counter=0,
            ttl=ticks(3),
            endpoints=frozenset({self.endpoint, endpoint2}),
        )

        with self.assertLogs(self.prot.log, "ERROR"):
            with self.assertRaises(sd.NakSubscription):
                self.prot.client_subscribed(sub, self.fake_addr)

    async def test_eventgroup_manual(self):
        evgrp = service.SimpleEventgroup(self.prot, id=2)
        self.prot.register_eventgroup(evgrp)
        self.prot.send = unittest.mock.Mock()

        # no clients -> no notification triggered
        evgrp.values[1] = b"\1\2\3\4"
        evgrp.notify_once((1,))

        await asyncio.sleep(ticks(1.1))

        self.prot.send.assert_not_called()

        sub = sd.EventgroupSubscription(
            service_id=self.prot.service_id,
            instance_id=self.prot.instance_id,
            major_version=self.prot.version_major,
            id=evgrp.id,
            counter=0,
            ttl=ticks(3),
            endpoints=frozenset({self.endpoint}),
        )
        self.prot.client_subscribed(sub, self.fake_addr)
        # ignore notification after subscribe
        await asyncio.sleep(ticks(0.1))
        self.prot.send.reset_mock()

        # clients subscribed -> notification triggered
        evgrp.values[1] = b"\4\3\2\1"
        evgrp.notify_once((1,))

        await asyncio.sleep(ticks(1.1))

        self.prot.send.assert_called_once()
        self.prot.send.reset_mock()

        # no event given -> don't send out notification
        evgrp.notify_once(())

        await asyncio.sleep(ticks(1.1))

        self.prot.send.assert_not_called()
