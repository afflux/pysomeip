import asyncio
import ipaddress
import logging
import unittest

import someip.header as hdr

logging.captureWarnings(True)
logging.basicConfig(level=logging.DEBUG)


class TestHeader(unittest.TestCase):

    def _check(self, payload, obj, parser, extra=b''):
        result = parser(payload + extra)
        self.assertEqual(result[1], extra)
        self.assertEqual(result[0], obj)
        self.assertEqual(obj.build(), payload)

    def test_someip_no_payload(self):
        payload = b'\xde\xad\xbe\xef\x00\x00\x00\x08\xcc\xcc\xdd\xdd\x01\x02\x40\x04'
        message = hdr.SOMEIPHeader(service_id=0xdead,
                                   method_id=0xbeef,
                                   client_id=0xcccc,
                                   session_id=0xdddd,
                                   protocol_version=1,
                                   interface_version=2,
                                   message_type=hdr.SOMEIPMessageType.REQUEST_ACK,
                                   return_code=hdr.SOMEIPReturnCode.E_NOT_READY)
        self._check(payload, message, hdr.SOMEIPHeader.parse)

    def test_someip_no_payload_rest(self):
        payload = b'\xde\xad\xbe\xef\x00\x00\x00\x08\xcc\xcc\xdd\xdd\x01\x02\x40\x04'
        message = hdr.SOMEIPHeader(service_id=0xdead,
                                   method_id=0xbeef,
                                   client_id=0xcccc,
                                   session_id=0xdddd,
                                   protocol_version=1,
                                   interface_version=2,
                                   message_type=hdr.SOMEIPMessageType.REQUEST_ACK,
                                   return_code=hdr.SOMEIPReturnCode.E_NOT_READY)
        self._check(payload, message, hdr.SOMEIPHeader.parse, extra=b'\1\2\3\4')
        self._check(payload, message, hdr.SOMEIPHeader.parse, extra=payload)

    def test_someip_with_payload(self):
        payload = b'\xde\xad\xbe\xef\x00\x00\x00\x0a\xcc\xcc\xdd\xdd\x01\x02\x40\x04\xaa\x55'
        message = hdr.SOMEIPHeader(service_id=0xdead,
                                   method_id=0xbeef,
                                   client_id=0xcccc,
                                   session_id=0xdddd,
                                   protocol_version=1,
                                   interface_version=2,
                                   message_type=hdr.SOMEIPMessageType.REQUEST_ACK,
                                   return_code=hdr.SOMEIPReturnCode.E_NOT_READY,
                                   payload=b'\xaa\x55')
        self._check(payload, message, hdr.SOMEIPHeader.parse)

    def test_someip_with_payload_rest(self):
        payload = b'\xde\xad\xbe\xef\x00\x00\x00\x0a\xcc\xcc\xdd\xdd\x01\x02\x40\x04\xaa\x55'
        message = hdr.SOMEIPHeader(service_id=0xdead,
                                   method_id=0xbeef,
                                   client_id=0xcccc,
                                   session_id=0xdddd,
                                   protocol_version=1,
                                   interface_version=2,
                                   message_type=hdr.SOMEIPMessageType.REQUEST_ACK,
                                   return_code=hdr.SOMEIPReturnCode.E_NOT_READY,
                                   payload=b'\xaa\x55')
        self._check(payload, message, hdr.SOMEIPHeader.parse, extra=b'\1\2\3\4')

    def test_someip_bad_version(self):
        payload = b'\xde\xad\xbe\xef\x00\x00\x00\x08\xcc\xcc\xdd\xdd\x00\x02\x40\x04'
        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPHeader.parse(payload)

    def test_someip_bad_length(self):
        payload = b'\xde\xad\xbe\xef\x00\x00\x00\x09\xcc\xcc\xdd\xdd\x01\x02\x40\x04'
        with self.assertRaises(hdr.IncompleteReadError):
            hdr.SOMEIPHeader.parse(payload)

        payload = b'\xde\xad\xbe\xef\xff\xff\xff\xff\xcc\xcc\xdd\xdd\x01\x02\x40\x04'
        with self.assertRaises(hdr.IncompleteReadError):
            hdr.SOMEIPHeader.parse(payload)

    def test_someip_stream_async(self):
        loop = asyncio.get_event_loop()
        bytes_reader = asyncio.StreamReader(loop=loop)
        someip_reader = hdr.SOMEIPReader(bytes_reader)

        async def consume(reader):
            return await reader.read()

        bytes_reader.feed_data(b'\xde\xad\xbe\xef')
        bytes_reader.feed_data(b'\x00\x00')
        bytes_reader.feed_data(b'\x00\x08\xcc\xcc')
        bytes_reader.feed_data(b'\xdd\xdd\x01\x02\x40\x04')
        bytes_reader.feed_data(b'\xde\xad\xbe\xef\x00\x00\x00\x0a\xcc\xcc\xdd\xdd\x01\x02\x40\x04')

        parsed = loop.run_until_complete(consume(someip_reader))

        message = hdr.SOMEIPHeader(service_id=0xdead,
                                   method_id=0xbeef,
                                   client_id=0xcccc,
                                   session_id=0xdddd,
                                   protocol_version=1,
                                   interface_version=2,
                                   message_type=hdr.SOMEIPMessageType.REQUEST_ACK,
                                   return_code=hdr.SOMEIPReturnCode.E_NOT_READY)
        self.assertEqual(parsed, message)

        bytes_reader.feed_data(b'\xaa\x55')

        parsed = loop.run_until_complete(consume(someip_reader))
        message = hdr.SOMEIPHeader(service_id=0xdead,
                                   method_id=0xbeef,
                                   client_id=0xcccc,
                                   session_id=0xdddd,
                                   protocol_version=1,
                                   interface_version=2,
                                   message_type=hdr.SOMEIPMessageType.REQUEST_ACK,
                                   return_code=hdr.SOMEIPReturnCode.E_NOT_READY,
                                   payload=b'\xaa\x55')
        self.assertEqual(parsed, message)

    def test_sdentry_service(self):
        payload = b'\x00\xAA\xBB\xCD\x88\x99\x66\x77\xEE\x20\x21\x22\x10\x11\x12\x13'
        entry = hdr.SOMEIPSDEntry(sd_type=hdr.SOMEIPSDEntryType.FindService,
                                  option_index_1=0xaa,
                                  option_index_2=0xbb,
                                  num_options_1=0xc,
                                  num_options_2=0xd,
                                  service_id=0x8899,
                                  instance_id=0x6677,
                                  major_version=0xee,
                                  ttl=0x202122,
                                  minver_or_counter=0x10111213)
        self._check(payload, entry, hdr.SOMEIPSDEntry.parse)

    def test_sdentry_service_minver(self):
        entry = hdr.SOMEIPSDEntry(sd_type=hdr.SOMEIPSDEntryType.FindService,
                                  option_index_1=0xaa,
                                  option_index_2=0xbb,
                                  num_options_1=0xc,
                                  num_options_2=0xd,
                                  service_id=0x8899,
                                  instance_id=0x6677,
                                  major_version=0xee,
                                  ttl=0x202122,
                                  minver_or_counter=0x10111213)
        self.assertEqual(entry.service_minor_version, 0x10111213)
        with self.assertRaises(TypeError):
            entry.eventgroup_counter

    def test_sdentry_service_rest(self):
        payload = b'\x01\xAA\xBB\xCD\x88\x99\x66\x77\xEE\x20\x21\x22\x10\x11\x12\x13'
        entry = hdr.SOMEIPSDEntry(sd_type=hdr.SOMEIPSDEntryType.OfferService,
                                  option_index_1=0xaa,
                                  option_index_2=0xbb,
                                  num_options_1=0xc,
                                  num_options_2=0xd,
                                  service_id=0x8899,
                                  instance_id=0x6677,
                                  major_version=0xee,
                                  ttl=0x202122,
                                  minver_or_counter=0x10111213)
        self._check(payload, entry, hdr.SOMEIPSDEntry.parse, extra=b'\1\2\3\4')

        self._check(payload, entry, hdr.SOMEIPSDEntry.parse, extra=payload)

    def test_sdentry_eventgroup(self):
        payload = b'\x06\xAA\xBB\xCD\x88\x99\x66\x77\xEE\x20\x21\x22\x00\x09\x11\x11'
        result = hdr.SOMEIPSDEntry.parse(payload)
        entry = hdr.SOMEIPSDEntry(sd_type=hdr.SOMEIPSDEntryType.Subscribe,
                                  option_index_1=0xaa,
                                  option_index_2=0xbb,
                                  num_options_1=0xc,
                                  num_options_2=0xd,
                                  service_id=0x8899,
                                  instance_id=0x6677,
                                  major_version=0xee,
                                  ttl=0x202122,
                                  minver_or_counter=0x091111)
        self.assertEqual(result[1], b'')
        self.assertEqual(result[0], entry)
        self.assertEqual(entry.build(), payload)

    def test_sdentry_service_counter(self):
        entry = hdr.SOMEIPSDEntry(sd_type=hdr.SOMEIPSDEntryType.Subscribe,
                                  option_index_1=0xaa,
                                  option_index_2=0xbb,
                                  num_options_1=0xc,
                                  num_options_2=0xd,
                                  service_id=0x8899,
                                  instance_id=0x6677,
                                  major_version=0xee,
                                  ttl=0x202122,
                                  minver_or_counter=0x091111)
        self.assertEqual(entry.eventgroup_counter, 0x9)
        self.assertEqual(entry.eventgroup_id, 0x1111)
        with self.assertRaises(TypeError):
            entry.service_minor_version

    def test_sdentry_eventgroup_bad_reserved(self):
        payload = b'\x06\xAA\xBB\xCD\x88\x99\x66\x77\xEE\x20\x21\x22\x10\x10\x10\x10'
        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDEntry.parse(payload)

    def test_sdoption_bad_length(self):
        payload = b'\x00\x04\xFFABC'
        with self.assertRaises(hdr.IncompleteReadError):
            hdr.SOMEIPHeader.parse(payload)

        payload = b'\xff\xff\xFFABC'
        with self.assertRaises(hdr.IncompleteReadError):
            hdr.SOMEIPHeader.parse(payload)

    def test_sdoption_unknown(self):
        payload = b'\x00\x03\xFFABC'
        option = hdr.SOMEIPSDUnknownOption(type_=0xff, payload=b'ABC')
        self._check(payload, option, hdr.SOMEIPSDOption.parse)

    def test_sdoption_loadbal(self):
        payload = b'\x00\x05\x02\x00\x12\x34\x56\x78'
        option = hdr.SOMEIPSDLoadBalancingOption(priority=0x1234, weight=0x5678)
        self._check(payload, option, hdr.SOMEIPSDOption.parse)

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDOption.parse(b'\x00\x04\x02\x00\x12\x34\x56')

    def test_sdoption_ipv4(self):
        payload = b'\x00\x09\x04\x00\x01\x02\xfe\xff\x00\x06\x03\xff'
        option = hdr.SOMEIPSDIPv4EndpointOption(
            address=ipaddress.IPv4Address('1.2.254.255'),
            l4proto=hdr.L4Protocols.TCP,
            port=1023
        )
        self._check(payload, option, hdr.SOMEIPSDOption.parse)

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDOption.parse(b'\x00\x0a\x04\x00\x01\x02\xfe\xff\x00\x06\x03\xff\xff')

    def test_sdoption_config(self):
        payload = b'\x00\x02\x01\x00\x00'
        option = hdr.SOMEIPSDConfigOption(configs=[])
        self._check(payload, option, hdr.SOMEIPSDOption.parse)

        payload = b'\x00\x07\x01\x00\x02AB\x01C\x00'
        option = hdr.SOMEIPSDConfigOption(configs=[('AB', None), ('C', None)])
        self._check(payload, option, hdr.SOMEIPSDOption.parse)

        payload = b'\x00\x0b\x01\x00\x04AB=X\x03C=Y\x00'
        option = hdr.SOMEIPSDConfigOption(configs=[('AB', 'X'), ('C', 'Y')])
        self._check(payload, option, hdr.SOMEIPSDOption.parse)

        payload = b'\x00\x0e\x01\x00\x04AB=X\x02AB\x03C=Y\x00'
        option = hdr.SOMEIPSDConfigOption(configs=[('AB', 'X'), ('AB', None), ('C', 'Y')])
        self._check(payload, option, hdr.SOMEIPSDOption.parse)

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDOption.parse(b'\x00\x01\x01\x00')

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDOption.parse(b'\x00\x03\x01\x00\x01\x00')

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDOption.parse(b'\x00\x03\x01\x00\x02\x00')

        with self.assertRaises(hdr.ParseError):
            hdr.SOMEIPSDOption.parse(b'\x00\x03\x01\x00\xff\x00')

        with self.assertRaises(UnicodeDecodeError):
            hdr.SOMEIPSDOption.parse(b'\x00\x04\x01\x00\x01\xd6\x00')

    def test_sd(self):
        payload = b'\xa5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        sd = hdr.SOMEIPSDHeader(
            flag_reboot=True,
            flag_unicast=False,
            flags_unknown=0xa5 & ~0x80,
            entries=[],
            options=[]
        )
        self._check(payload, sd, hdr.SOMEIPSDHeader.parse)

        entries = [
            hdr.SOMEIPSDEntry(
                sd_type=hdr.SOMEIPSDEntryType.Subscribe,
                option_index_1=0xaa,
                option_index_2=0xbb,
                num_options_1=0xc,
                num_options_2=0xd,
                service_id=0x8899,
                instance_id=0x6677,
                major_version=0xee,
                ttl=0x202122,
                minver_or_counter=0x10
            ),
            hdr.SOMEIPSDEntry(
                sd_type=hdr.SOMEIPSDEntryType.OfferService,
                option_index_1=0x11,
                option_index_2=0x22,
                num_options_1=0x3,
                num_options_2=0x4,
                service_id=0x5566,
                instance_id=0x7788,
                major_version=0x99,
                ttl=0xaaabac,
                minver_or_counter=0xdeadbeef
            ),
        ]
        options = [
            hdr.SOMEIPSDIPv4EndpointOption(
                address=ipaddress.IPv4Address('1.2.3.4'),
                l4proto=hdr.L4Protocols.UDP,
                port=2047
            ),
            hdr.SOMEIPSDIPv4EndpointOption(
                address=ipaddress.IPv4Address('254.253.252.251'),
                l4proto=hdr.L4Protocols.UDP,
                port=65535
            ),
            hdr.SOMEIPSDLoadBalancingOption(priority=0x2222, weight=0x3333),
        ]
        payload = b'\x00\x00\x00\x00' \
                  b'\x00\x00\x00\x20' \
                  b'\x06\xAA\xBB\xCD\x88\x99\x66\x77\xEE\x20\x21\x22\x00\x00\x00\x10' \
                  b'\x01\x11\x22\x34\x55\x66\x77\x88\x99\xaa\xab\xac\xde\xad\xbe\xef' \
                  b'\x00\x00\x00\x20' \
                  b'\x00\x09\x04\x00\x01\x02\x03\x04\x00\x11\x07\xff' \
                  b'\x00\x09\x04\x00\xfe\xfd\xfc\xfb\x00\x11\xff\xff' \
                  b'\x00\x05\x02\x00\x22\x22\x33\x33'
        sd = hdr.SOMEIPSDHeader(
            flag_reboot=False,
            flag_unicast=False,
            flags_unknown=0,
            entries=entries,
            options=options
        )
        self._check(payload, sd, hdr.SOMEIPSDHeader.parse)

        with self.assertRaises(hdr.IncompleteReadError):
            hdr.SOMEIPSDHeader.parse(b'\xa5\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00')

        with self.assertRaises(hdr.IncompleteReadError):
            hdr.SOMEIPSDHeader.parse(b'\xa5\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00')

        with self.assertRaises(hdr.IncompleteReadError):
            hdr.SOMEIPSDHeader.parse(b'\xa5\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff')

        with self.assertRaises(hdr.IncompleteReadError):
            hdr.SOMEIPSDHeader.parse(b'\xa5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04')

        with self.assertRaises(hdr.IncompleteReadError):
            hdr.SOMEIPSDHeader.parse(b'\xa5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10')

        with self.assertRaises(hdr.IncompleteReadError):
            hdr.SOMEIPSDHeader.parse(b'\xa5\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff')


if __name__ == '__main__':
    unittest.main()
