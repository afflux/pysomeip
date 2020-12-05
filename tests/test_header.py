import asyncio
import ipaddress
import logging
import unittest
from dataclasses import replace

import someip.header as hdr

logging.captureWarnings(True)
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("asyncio").setLevel(logging.INFO)


class TestHeader(unittest.IsolatedAsyncioTestCase):
    def _check(self, payload, obj, parser, extra=b""):
        result = parser(payload + extra)
        self.assertEqual(result[1], extra)
        self.assertEqual(result[0], obj)
        self.assertEqual(obj.build(), payload)

    def test_someip_no_payload(self):
        payload = b"\xde\xad\xbe\xef\x00\x00\x00\x08\xcc\xcc\xdd\xdd\x01\x02\x40\x04"
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
        self._check(payload, message, hdr.SOMEIPHeader.parse)

    def test_someip_no_payload_rest(self):
        payload = b"\xde\xad\xbe\xef\x00\x00\x00\x08\xcc\xcc\xdd\xdd\x01\x02\x40\x04"
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
        self._check(payload, message, hdr.SOMEIPHeader.parse, extra=b"\1\2\3\4")
        self._check(payload, message, hdr.SOMEIPHeader.parse, extra=payload)

    def test_someip_with_payload(self):
        payload = (
            b"\xde\xad\xbe\xef\x00\x00\x00\x0a\xcc\xcc\xdd\xdd\x01\x02\x40\x04\xaa\x55"
        )
        message = hdr.SOMEIPHeader(
            service_id=0xDEAD,
            method_id=0xBEEF,
            client_id=0xCCCC,
            session_id=0xDDDD,
            protocol_version=1,
            interface_version=2,
            message_type=hdr.SOMEIPMessageType.REQUEST_ACK,
            return_code=hdr.SOMEIPReturnCode.E_NOT_READY,
            payload=b"\xaa\x55",
        )
        self._check(payload, message, hdr.SOMEIPHeader.parse)

    def test_someip_with_payload_rest(self):
        payload = (
            b"\xde\xad\xbe\xef\x00\x00\x00\x0a\xcc\xcc\xdd\xdd\x01\x02\x40\x04\xaa\x55"
        )
        message = hdr.SOMEIPHeader(
            service_id=0xDEAD,
            method_id=0xBEEF,
            client_id=0xCCCC,
            session_id=0xDDDD,
            protocol_version=1,
            interface_version=2,
            message_type=hdr.SOMEIPMessageType.REQUEST_ACK,
            return_code=hdr.SOMEIPReturnCode.E_NOT_READY,
            payload=b"\xaa\x55",
        )
        self._check(payload, message, hdr.SOMEIPHeader.parse, extra=b"\1\2\3\4")

    def test_someip_short(self):
        payload = b"\xde\xad\xbe\xef\x00\x00\x00\x08\xcc\xcc\xdd\xdd\x01\x02\x40"
        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPHeader.parse(payload)

    def test_someip_bad_version(self):
        payload = b"\xde\xad\xbe\xef\x00\x00\x00\x08\xcc\xcc\xdd\xdd\x00\x02\x40\x04"
        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPHeader.parse(payload)

    def test_someip_bad_messagetype(self):
        payload = b"\xde\xad\xbe\xef\x00\x00\x00\x08\xcc\xcc\xdd\xdd\x01\x02\xaa\x04"
        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPHeader.parse(payload)

    def test_someip_bad_returncode(self):
        payload = b"\xde\xad\xbe\xef\x00\x00\x00\x08\xcc\xcc\xdd\xdd\x01\x02\x40\xaa"
        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPHeader.parse(payload)

    def test_someip_bad_length(self):
        payload = b"\xde\xad\xbe\xef\x00\x00\x00\x09\xcc\xcc\xdd\xdd\x01\x02\x40\x04"
        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPHeader.parse(payload)

        payload = b"\xde\xad\xbe\xef\xff\xff\xff\xff\xcc\xcc\xdd\xdd\x01\x02\x40\x04"
        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPHeader.parse(payload)

    async def test_someip_stream_async(self):
        bytes_reader = asyncio.StreamReader()
        someip_reader = hdr.SOMEIPReader(bytes_reader)

        async def consume(reader):
            return await reader.read()

        bytes_reader.feed_data(b"\xde\xad\xbe\xef")
        bytes_reader.feed_data(b"\x00\x00")
        bytes_reader.feed_data(b"\x00\x08\xcc\xcc")
        bytes_reader.feed_data(b"\xdd\xdd\x01\x02\x40\x04")
        bytes_reader.feed_data(
            b"\xde\xad\xbe\xef\x00\x00\x00\x0a" b"\xcc\xcc\xdd\xdd\x01\x02\x40\x04"
        )

        parsed = await someip_reader.read()

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
        self.assertEqual(parsed, message)

        bytes_reader.feed_data(b"\xaa\x55")
        bytes_reader.feed_eof()

        parsed = await someip_reader.read()
        message = hdr.SOMEIPHeader(
            service_id=0xDEAD,
            method_id=0xBEEF,
            client_id=0xCCCC,
            session_id=0xDDDD,
            protocol_version=1,
            interface_version=2,
            message_type=hdr.SOMEIPMessageType.REQUEST_ACK,
            return_code=hdr.SOMEIPReturnCode.E_NOT_READY,
            payload=b"\xaa\x55",
        )
        self.assertEqual(parsed, message)
        self.assertTrue(someip_reader.at_eof())

    def test_sdentry_service(self):
        payload = b"\x00\xAA\xBB\xCD\x88\x99\x66\x77\xEE\x20\x21\x22\x10\x11\x12\x13"
        entry = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.FindService,
            option_index_1=0xAA,
            option_index_2=0xBB,
            num_options_1=0xC,
            num_options_2=0xD,
            service_id=0x8899,
            instance_id=0x6677,
            major_version=0xEE,
            ttl=0x202122,
            minver_or_counter=0x10111213,
        )
        self._check(payload, entry, lambda x: hdr.SOMEIPSDEntry.parse(x, 512))
        self.assertFalse(entry.options_resolved)

    def test_sdentry_bad_type(self):
        payload = b"\x77\xAA\xBB\xCD\x88\x99\x66\x77\xEE\x20\x21\x22\x10\x11\x12\x13"
        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDEntry.parse(payload, 512)

    def test_sdentry_service_stopoffer(self):
        payload = b"\x01\xAA\xBB\xCD\x88\x99\x66\x77\xEE\x00\x00\x00\x10\x11\x12\x13"
        entry = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.OfferService,
            option_index_1=0xAA,
            option_index_2=0xBB,
            num_options_1=0xC,
            num_options_2=0xD,
            service_id=0x8899,
            instance_id=0x6677,
            major_version=0xEE,
            ttl=0,
            minver_or_counter=0x10111213,
        )
        self._check(payload, entry, lambda x: hdr.SOMEIPSDEntry.parse(x, 512))
        self.assertFalse(entry.options_resolved)

    def test_sdentry_service_minver(self):
        entry = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.FindService,
            option_index_1=0xAA,
            option_index_2=0xBB,
            num_options_1=0xC,
            num_options_2=0xD,
            service_id=0x8899,
            instance_id=0x6677,
            major_version=0xEE,
            ttl=0x202122,
            minver_or_counter=0x10111213,
        )
        self.assertEqual(entry.service_minor_version, 0x10111213)
        self.assertFalse(entry.options_resolved)
        with self.assertRaises(TypeError):
            entry.eventgroup_counter
        with self.assertRaises(TypeError):
            entry.eventgroup_id

    def test_sdentry_service_rest(self):
        payload = b"\x01\xAA\xBB\xCD\x88\x99\x66\x77\xEE\x20\x21\x22\x10\x11\x12\x13"
        entry = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.OfferService,
            option_index_1=0xAA,
            option_index_2=0xBB,
            num_options_1=0xC,
            num_options_2=0xD,
            service_id=0x8899,
            instance_id=0x6677,
            major_version=0xEE,
            ttl=0x202122,
            minver_or_counter=0x10111213,
        )
        self._check(
            payload, entry, lambda x: hdr.SOMEIPSDEntry.parse(x, 512), extra=b"\1\2\3\4"
        )

        self._check(
            payload, entry, lambda x: hdr.SOMEIPSDEntry.parse(x, 512), extra=payload
        )
        self.assertFalse(entry.options_resolved)

    def test_sdentry_eventgroup(self):
        payload = b"\x06\xAA\xBB\xCD\x88\x99\x66\x77\xEE\x20\x21\x22\x00\x09\x11\x11"
        result = hdr.SOMEIPSDEntry.parse(payload, 512)
        entry = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.Subscribe,
            option_index_1=0xAA,
            option_index_2=0xBB,
            num_options_1=0xC,
            num_options_2=0xD,
            service_id=0x8899,
            instance_id=0x6677,
            major_version=0xEE,
            ttl=0x202122,
            minver_or_counter=0x091111,
        )
        self.assertEqual(result[1], b"")
        self.assertEqual(result[0], entry)
        self.assertEqual(entry.build(), payload)

    def test_sdentry_service_counter(self):
        entry = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.Subscribe,
            option_index_1=0xAA,
            option_index_2=0xBB,
            num_options_1=0xC,
            num_options_2=0xD,
            service_id=0x8899,
            instance_id=0x6677,
            major_version=0xEE,
            ttl=0x202122,
            minver_or_counter=0x091111,
        )
        self.assertEqual(entry.eventgroup_counter, 0x9)
        self.assertEqual(entry.eventgroup_id, 0x1111)
        with self.assertRaises(TypeError):
            entry.service_minor_version

    def test_sdentry_eventgroup_bad_reserved(self):
        payload = b"\x06\xAA\xBB\xCD\x88\x99\x66\x77\xEE\x20\x21\x22\x10\x10\x10\x10"
        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDEntry.parse(payload, 512)

    def test_sdoption_bad_length(self):
        payload = b"\x00\x04\xFFABC"
        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDOption.parse(payload)

        payload = b"\xff\xff\xFFABC"
        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDOption.parse(payload)

    def test_sdoption_unknown(self):
        payload = b"\x00\x03\xFFABC"
        option = hdr.SOMEIPSDUnknownOption(type=0xFF, payload=b"ABC")
        self._check(payload, option, hdr.SOMEIPSDOption.parse)

    def test_sdoption_loadbal(self):
        payload = b"\x00\x05\x02\x00\x12\x34\x56\x78"
        option = hdr.SOMEIPSDLoadBalancingOption(priority=0x1234, weight=0x5678)
        self._check(payload, option, hdr.SOMEIPSDOption.parse)

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDOption.parse(b"\x00\x04\x02\x00\x12\x34\x56")

    async def test_sdoption_ipv4(self):
        payload = b"\x00\x09\x04\x00\x01\x02\xfe\xff\x00\x06\x03\xff"
        option = hdr.IPv4EndpointOption(
            address=ipaddress.IPv4Address("1.2.254.255"),
            l4proto=hdr.L4Protocols.TCP,
            port=1023,
        )
        self._check(payload, option, hdr.SOMEIPSDOption.parse)

        self.assertEqual(await option.addrinfo(), ("1.2.254.255", 1023))

        payload = b"\x00\x09\x04\x00\x01\x02\xfe\xff\x00\x42\x03\xff"
        option = hdr.IPv4EndpointOption(
            address=ipaddress.IPv4Address("1.2.254.255"),
            l4proto=0x42,
            port=1023,
        )
        self._check(payload, option, hdr.SOMEIPSDOption.parse)

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDOption.parse(
                b"\x00\x0a\x04\x00\x01\x02\xfe\xff\x00\x06\x03\xff\xff"
            )

    def test_sdoption_config(self):
        payload = b"\x00\x02\x01\x00\x00"
        option = hdr.SOMEIPSDConfigOption(configs=())
        self._check(payload, option, hdr.SOMEIPSDOption.parse)

        payload = b"\x00\x07\x01\x00\x02AB\x01C\x00"
        option = hdr.SOMEIPSDConfigOption(configs=(("AB", None), ("C", None)))
        self._check(payload, option, hdr.SOMEIPSDOption.parse)

        payload = b"\x00\x0b\x01\x00\x04AB=X\x03C=Y\x00"
        option = hdr.SOMEIPSDConfigOption(configs=(("AB", "X"), ("C", "Y")))
        self._check(payload, option, hdr.SOMEIPSDOption.parse)

        payload = b"\x00\x0e\x01\x00\x04AB=X\x02AB\x03C=Y\x00"
        option = hdr.SOMEIPSDConfigOption(
            configs=(("AB", "X"), ("AB", None), ("C", "Y"))
        )
        self._check(payload, option, hdr.SOMEIPSDOption.parse)

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDOption.parse(b"\x00\x01\x01\x00")

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDOption.parse(b"\x00\x03\x01\x00\x01\x00")

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDOption.parse(b"\x00\x03\x01\x00\x02\x00")

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDOption.parse(b"\x00\x03\x01\x00\xff\x00")

        with self.assertRaises(UnicodeDecodeError):
            hdr.SOMEIPSDOption.parse(b"\x00\x04\x01\x00\x01\xd6\x00")

    def test_sd(self):
        payload = b"\xa5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        sd = hdr.SOMEIPSDHeader(
            flag_reboot=True,
            flag_unicast=False,
            flags_unknown=0xA5 & ~0x80,
            entries=(),
            options=(),
        )
        self._check(payload, sd, hdr.SOMEIPSDHeader.parse)

        entries = [
            hdr.SOMEIPSDEntry(
                sd_type=hdr.SOMEIPSDEntryType.Subscribe,
                option_index_1=0x00,
                option_index_2=0x00,
                num_options_1=0x2,
                num_options_2=0x1,
                service_id=0x8899,
                instance_id=0x6677,
                major_version=0xEE,
                ttl=0x202122,
                minver_or_counter=0x10,
            ),
            hdr.SOMEIPSDEntry(
                sd_type=hdr.SOMEIPSDEntryType.OfferService,
                option_index_1=0x01,
                option_index_2=0x01,
                num_options_1=0x0,
                num_options_2=0x1,
                service_id=0x5566,
                instance_id=0x7788,
                major_version=0x99,
                ttl=0xAAABAC,
                minver_or_counter=0xDEADBEEF,
            ),
        ]
        options = [
            hdr.IPv4EndpointOption(
                address=ipaddress.IPv4Address("1.2.3.4"),
                l4proto=hdr.L4Protocols.UDP,
                port=2047,
            ),
            hdr.IPv4EndpointOption(
                address=ipaddress.IPv4Address("254.253.252.251"),
                l4proto=hdr.L4Protocols.UDP,
                port=65535,
            ),
            hdr.SOMEIPSDLoadBalancingOption(priority=0x2222, weight=0x3333),
        ]
        payload = (
            b"\x40\x00\x00\x00"
            b"\x00\x00\x00\x20"
            b"\x06\x00\x00\x21\x88\x99\x66\x77\xEE\x20\x21\x22\x00\x00\x00\x10"
            b"\x01\x01\x01\x01\x55\x66\x77\x88\x99\xaa\xab\xac\xde\xad\xbe\xef"
            b"\x00\x00\x00\x20"
            b"\x00\x09\x04\x00\x01\x02\x03\x04\x00\x11\x07\xff"
            b"\x00\x09\x04\x00\xfe\xfd\xfc\xfb\x00\x11\xff\xff"
            b"\x00\x05\x02\x00\x22\x22\x33\x33"
        )
        sd = hdr.SOMEIPSDHeader(
            flag_reboot=False,
            flag_unicast=True,
            flags_unknown=0,
            entries=tuple(entries),
            options=tuple(options),
        )
        self._check(payload, sd, hdr.SOMEIPSDHeader.parse)

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDHeader.parse(b"\xa5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDHeader.parse(
                b"\xa5\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00"
            )

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDHeader.parse(
                b"\xa5\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00"
            )

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDHeader.parse(
                b"\xa5\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff"
            )

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDHeader.parse(
                b"\xa5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"
            )

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDHeader.parse(
                b"\xa5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10"
            )

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDHeader.parse(
                b"\xa5\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff"
            )

    def test_sd_option_indexes(self):
        newopt = hdr.SOMEIPSDConfigOption(configs={"foo": "bar"}.items())
        entries = [
            hdr.SOMEIPSDEntry(
                sd_type=hdr.SOMEIPSDEntryType.Subscribe,
                option_index_1=0x00,
                option_index_2=0x00,
                num_options_1=0x2,
                num_options_2=0x1,
                service_id=0x8899,
                instance_id=0x6677,
                major_version=0xEE,
                ttl=0x202122,
                minver_or_counter=0x10,
            ),
            hdr.SOMEIPSDEntry(
                sd_type=hdr.SOMEIPSDEntryType.OfferService,
                option_index_1=0x1,
                option_index_2=0x2,
                num_options_1=0x2,
                num_options_2=0x1,
                service_id=0x5566,
                instance_id=0x7788,
                major_version=0x99,
                ttl=0xAAABAC,
                minver_or_counter=0xDEADBEEF,
            ),
        ]
        options = [
            hdr.IPv4EndpointOption(
                address=ipaddress.IPv4Address("1.2.3.4"),
                l4proto=hdr.L4Protocols.UDP,
                port=2047,
            ),
            hdr.IPv4EndpointOption(
                address=ipaddress.IPv4Address("254.253.252.251"),
                l4proto=hdr.L4Protocols.UDP,
                port=65535,
            ),
            hdr.SOMEIPSDLoadBalancingOption(priority=0x2222, weight=0x3333),
        ]
        sd = hdr.SOMEIPSDHeader(
            flag_reboot=False,
            flag_unicast=True,
            flags_unknown=0,
            entries=entries,
            options=options,
        )

        self.assertFalse(any(e.options_resolved for e in sd.entries))

        sd_resolved = sd.resolve_options()
        self.assertTrue(all(e.options_resolved for e in sd_resolved.entries))
        with self.assertRaises(ValueError):
            sd_resolved.resolve_options()
        with self.assertRaises(ValueError):
            sd_resolved.build()

        self.assertEqual(sd_resolved.entries[0].options_1, options[:2])
        self.assertEqual(sd_resolved.entries[0].options_2, options[:1])
        self.assertEqual(sd_resolved.entries[0].options, options[:2] + options[:1])
        self.assertEqual(sd_resolved.entries[1].options_1, options[1:3])
        self.assertEqual(sd_resolved.entries[1].options_2, options[2:3])
        self.assertEqual(sd_resolved.entries[1].options, options[1:3] + options[2:3])
        self.assertIsNone(sd_resolved.entries[0].option_index_1)
        self.assertIsNone(sd_resolved.entries[0].option_index_2)
        self.assertIsNone(sd_resolved.entries[1].option_index_1)
        self.assertIsNone(sd_resolved.entries[1].option_index_2)
        self.assertIsNone(sd_resolved.entries[0].num_options_1)
        self.assertIsNone(sd_resolved.entries[0].num_options_2)
        self.assertIsNone(sd_resolved.entries[1].num_options_1)
        self.assertIsNone(sd_resolved.entries[1].num_options_2)

        self.assertNotIn(newopt, sd_resolved.options)

        newsd = replace(
            sd_resolved,
            entries=(
                replace(sd_resolved.entries[0], options_2=[]),
                replace(sd_resolved.entries[1], options_1=[options[0], newopt]),
            ),
        ).assign_option_indexes()
        self.assertIn(newopt, newsd.options)

        self.assertFalse(newsd.entries[0].options_1)
        self.assertFalse(newsd.entries[0].options_2)
        self.assertFalse(newsd.entries[0].options)
        self.assertFalse(newsd.entries[1].options_1)
        self.assertFalse(newsd.entries[1].options_2)
        self.assertFalse(newsd.entries[1].options)
        self.assertEqual(newsd.entries[0].option_index_1, 0)
        self.assertEqual(newsd.entries[0].option_index_2, 0)
        self.assertEqual(newsd.entries[0].num_options_1, 2)
        self.assertEqual(newsd.entries[0].num_options_2, 0)
        self.assertEqual(newsd.entries[1].option_index_1, 3)
        self.assertEqual(newsd.entries[1].option_index_2, 2)
        self.assertEqual(newsd.entries[1].num_options_1, 2)
        self.assertEqual(newsd.entries[1].num_options_2, 1)

    def test_sd_bad_option_indexes(self):
        header = b"\x00\x00\x00\x00\x00\x00\x00\x10"
        entries = (
            b"\x00\x00\x00\x38"
            b"\x00\x09\x04\x00\x01\x02\x03\x04\x00\x11\x07\xff"
            b"\x00\x09\x04\x00\xfe\xfd\xfc\xfb\x00\x11\xff\xff"
            b"\x00\x09\x04\x00\x01\x02\x03\x04\x00\x11\x07\xff"
            b"\x00\x09\x04\x00\xfe\xfd\xfc\xfb\x00\x11\xff\xff"
            b"\x00\x05\x02\x00\x22\x22\x33\x33"
        )

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDHeader.parse(
                header
                + b"\x06\x00\x00\x60\x88\x99\x66\x77\xEE\x20\x21\x22\x00\x00\x00\x10"
                + entries,
            )

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDHeader.parse(
                header
                + b"\x06\x00\x00\x0f\x88\x99\x66\x77\xEE\x20\x21\x22\x00\x00\x00\x10"
                + entries,
            )

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDHeader.parse(
                header
                + b"\x06\x05\x00\x10\x88\x99\x66\x77\xEE\x20\x21\x22\x00\x00\x00\x10"
                + entries,
            )

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDHeader.parse(
                header
                + b"\x06\x00\x05\x0f\x88\x99\x66\x77\xEE\x20\x21\x22\x00\x00\x00\x10"
                + entries,
            )

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDHeader.parse(
                header
                + b"\x06\x77\x00\x10\x88\x99\x66\x77\xEE\x20\x21\x22\x00\x00\x00\x10"
                + entries,
            )

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDHeader.parse(
                header
                + b"\x06\x00\xff\x0f\x88\x99\x66\x77\xEE\x20\x21\x22\x00\x00\x00\x10"
                + entries,
            )


if __name__ == "__main__":
    unittest.main()
