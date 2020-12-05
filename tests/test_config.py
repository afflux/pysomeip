import ipaddress
import logging
import unittest
import socket
from dataclasses import replace

import someip.header as hdr
import someip.config as cfg

logging.captureWarnings(True)
logging.basicConfig(level=logging.DEBUG)


class TestConfig(unittest.TestCase):
    def test_eventgroup_subscribe_ipv4(self):
        host = ipaddress.ip_address("203.0.113.78")
        port = 4321
        results = socket.getaddrinfo(
            str(host),
            port,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
        if not results:
            raise RuntimeError("could not get addr info")
        sockaddr = results[0][4]

        evgr = cfg.Eventgroup(
            service_id=0xDEAD,
            instance_id=0x42,
            major_version=23,
            eventgroup_id=0xF00BAA,
            sockname=sockaddr,
            protocol=hdr.L4Protocols.TCP,
        )

        ep = hdr.IPv4EndpointOption(
            address=host, l4proto=hdr.L4Protocols.TCP, port=port
        )

        entry = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.Subscribe,
            service_id=0xDEAD,
            instance_id=0x42,
            major_version=23,
            ttl=3,
            minver_or_counter=0xF00BAA,
            options_1=(ep,),
        )

        self.assertEqual(evgr.create_subscribe_entry(), entry)

    def test_eventgroup_subscribe_ipv6(self):
        host = ipaddress.ip_address("2001:db8::1234:5678:dead:beef")
        port = 4321
        results = socket.getaddrinfo(
            str(host),
            port,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
        if not results:
            raise RuntimeError("could not get addr info")
        sockaddr = results[0][4]

        evgr = cfg.Eventgroup(
            service_id=0xDEAD,
            instance_id=0x42,
            major_version=23,
            eventgroup_id=0xF00BAA,
            sockname=sockaddr,
            protocol=hdr.L4Protocols.TCP,
        )

        ep = hdr.IPv6EndpointOption(
            address=host, l4proto=hdr.L4Protocols.TCP, port=port
        )

        entry = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.Subscribe,
            service_id=0xDEAD,
            instance_id=0x42,
            major_version=23,
            ttl=3,
            minver_or_counter=0xF00BAA,
            options_1=(ep,),
        )

        self.assertEqual(evgr.create_subscribe_entry(), entry)

    def test_eventgroup_for_service_no_match(self):
        sockaddr = "203.0.113.78", 4321

        evgr = cfg.Eventgroup(
            service_id=0xDEAD,
            instance_id=0x42,
            major_version=23,
            eventgroup_id=0xF00BAA,
            sockname=sockaddr,
            protocol=hdr.L4Protocols.TCP,
        )

        host_1 = ipaddress.ip_address("2001:db8::1234:5678:dead:beef")
        host_2 = ipaddress.ip_address("203.0.113.78")
        port = 4321

        ep_1 = hdr.IPv6EndpointOption(
            address=host_1, l4proto=hdr.L4Protocols.UDP, port=port
        )
        ep_2 = hdr.IPv4EndpointOption(
            address=host_2, l4proto=hdr.L4Protocols.UDP, port=port
        )
        srv = cfg.Service(
            service_id=0x0000,
            instance_id=0xFFFF,
            major_version=0xAA,
            minor_version=0x123456,
            options_1=(ep_1,),
            options_2=(ep_2,),
        )

        self.assertIsNone(evgr.for_service(srv))

    def test_eventgroup_for_service_match(self):
        sockaddr = "203.0.113.78", 4321

        evgr = cfg.Eventgroup(
            service_id=0xDEAD,
            instance_id=0x42,
            major_version=0xFF,
            eventgroup_id=0xF00BAA,
            sockname=sockaddr,
            protocol=hdr.L4Protocols.TCP,
        )

        host_1 = ipaddress.ip_address("2001:db8::1234:5678:dead:beef")
        host_2 = ipaddress.ip_address("203.0.113.78")
        port = 4321

        ep_1 = hdr.IPv6EndpointOption(
            address=host_1, l4proto=hdr.L4Protocols.UDP, port=port
        )
        ep_2 = hdr.IPv4EndpointOption(
            address=host_2, l4proto=hdr.L4Protocols.UDP, port=port
        )
        srv = cfg.Service(
            service_id=0xDEAD,
            instance_id=0x42,
            major_version=0xAA,
            minor_version=0x123456,
            options_1=(ep_1,),
            options_2=(ep_2,),
        )

        self.assertEqual(evgr.for_service(srv), replace(evgr, major_version=0xAA))

    def test_service_convert_offer(self):
        host_1 = ipaddress.ip_address("2001:db8::1234:5678:dead:beef")
        host_2 = ipaddress.ip_address("203.0.113.78")
        port = 4321

        ep_1 = hdr.IPv6EndpointOption(
            address=host_1, l4proto=hdr.L4Protocols.TCP, port=port
        )
        ep_2 = hdr.IPv4EndpointOption(
            address=host_2, l4proto=hdr.L4Protocols.TCP, port=port
        )

        srv = cfg.Service(
            service_id=0x0000,
            instance_id=0xFFFF,
            major_version=0xAA,
            minor_version=0x123456,
            options_1=(ep_1,),
            options_2=(ep_2,),
        )
        offer = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.OfferService,
            service_id=0,
            instance_id=0xFFFF,
            major_version=0xAA,
            minver_or_counter=0x123456,
            ttl=3,
            options_1=(ep_1,),
            options_2=(ep_2,),
        )

        self.assertEqual(srv.create_offer_entry(), offer)
        self.assertEqual(cfg.Service.from_offer_entry(offer), srv)

        sd_hdr = hdr.SOMEIPSDHeader(entries=(offer,))
        sd_hdr_assigned = sd_hdr.assign_option_indexes()

        with self.assertRaises(ValueError):
            cfg.Service.from_offer_entry(sd_hdr_assigned.entries[0])

        with self.assertRaises(ValueError):
            cfg.Service.from_offer_entry(
                hdr.SOMEIPSDEntry(
                    sd_type=hdr.SOMEIPSDEntryType.FindService,
                    service_id=0,
                    instance_id=0xFFFF,
                    major_version=0xAA,
                    minver_or_counter=0x123456,
                    ttl=3,
                )
            )

    def test_service_convert_find(self):
        srv = cfg.Service(
            service_id=0x0000,
            instance_id=0xFFFF,
            major_version=0xAA,
            minor_version=0x123456,
        )
        offer = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.FindService,
            service_id=0,
            instance_id=0xFFFF,
            major_version=0xAA,
            minver_or_counter=0x123456,
            ttl=3,
        )

        self.assertEqual(srv.create_find_entry(), offer)

    def test_service_match_offer(self):
        host_1 = ipaddress.ip_address("2001:db8::1234:5678:dead:beef")
        host_2 = ipaddress.ip_address("203.0.113.78")
        port = 4321

        ep_1 = hdr.IPv6EndpointOption(
            address=host_1, l4proto=hdr.L4Protocols.TCP, port=port
        )
        ep_2 = hdr.IPv6EndpointOption(
            address=host_2, l4proto=hdr.L4Protocols.TCP, port=port
        )

        offer = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.OfferService,
            service_id=0,
            instance_id=0xFEEE,
            major_version=0xAA,
            minver_or_counter=0x123456,
            ttl=3,
            options_1=(ep_1,),
            options_2=(ep_2,),
        )

        srv = cfg.Service(
            service_id=0x0000,
            instance_id=0xFEEE,
            major_version=0xAA,
            minor_version=0x123456,
            options_2=(ep_2,),
        )

        self.assertTrue(srv.matches_offer(offer))
        self.assertFalse(replace(srv, service_id=1).matches_offer(offer))
        self.assertFalse(replace(srv, instance_id=0xBBBB).matches_offer(offer))
        self.assertTrue(replace(srv, instance_id=0xFFFF).matches_offer(offer))
        self.assertFalse(replace(srv, major_version=0xBB).matches_offer(offer))
        self.assertTrue(replace(srv, major_version=0xFF).matches_offer(offer))
        self.assertFalse(replace(srv, minor_version=0xBBBBBB).matches_offer(offer))
        self.assertTrue(replace(srv, minor_version=0xFFFFFFFF).matches_offer(offer))

        # ttl=0 is StopOffer, should still match
        stop_offer = replace(offer, ttl=0)
        self.assertTrue(srv.matches_offer(stop_offer))

        with self.assertRaises(ValueError):
            srv.matches_offer(
                replace(stop_offer, sd_type=hdr.SOMEIPSDEntryType.FindService)
            )

    def test_service_match_find(self):
        host = ipaddress.ip_address("2001:db8::1234:5678:dead:beef")
        port = 4321

        ep = hdr.IPv6EndpointOption(
            address=host, l4proto=hdr.L4Protocols.TCP, port=port
        )

        srv = cfg.Service(
            service_id=0x1111,
            instance_id=0x2222,
            major_version=0x33,
            minor_version=0x333333,
            options_1=(ep,),
        )

        find = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.FindService,
            service_id=0x1111,
            instance_id=0x2222,
            major_version=0x33,
            minver_or_counter=0x333333,
            ttl=3,
        )

        self.assertTrue(srv.matches_find(find))
        self.assertFalse(srv.matches_find(replace(find, service_id=0x0101)))
        self.assertFalse(srv.matches_find(replace(find, instance_id=0x0101)))
        self.assertTrue(srv.matches_find(replace(find, instance_id=0xFFFF)))
        self.assertFalse(srv.matches_find(replace(find, major_version=0x0B)))
        self.assertTrue(srv.matches_find(replace(find, major_version=0xFF)))
        self.assertFalse(srv.matches_find(replace(find, minver_or_counter=0x0B0B0B)))
        self.assertTrue(srv.matches_find(replace(find, minver_or_counter=0xFFFFFFFF)))

        with self.assertRaises(ValueError):
            srv.matches_find(replace(find, sd_type=hdr.SOMEIPSDEntryType.OfferService))

    def test_service_match_subscribe(self):
        host = ipaddress.ip_address("2001:db8::1234:5678:dead:beef")
        port = 4321

        ep = hdr.IPv6EndpointOption(
            address=host, l4proto=hdr.L4Protocols.TCP, port=port
        )

        srv = cfg.Service(
            service_id=0x1111,
            instance_id=0x2222,
            major_version=0x33,
            minor_version=0x333333,
            eventgroups=(23, 24, 25),
        )

        subscribe = hdr.SOMEIPSDEntry(
            sd_type=hdr.SOMEIPSDEntryType.Subscribe,
            service_id=0x1111,
            instance_id=0x2222,
            major_version=0x33,
            minver_or_counter=(12 << 16) | 23,
            ttl=3,
            options_1=(ep,),
        )

        self.assertTrue(srv.matches_subscribe(subscribe))
        self.assertFalse(replace(srv, service_id=1).matches_subscribe(subscribe))
        self.assertFalse(replace(srv, instance_id=0xBBBB).matches_subscribe(subscribe))
        self.assertTrue(replace(srv, instance_id=0xFFFF).matches_subscribe(subscribe))
        self.assertFalse(replace(srv, major_version=0xBB).matches_subscribe(subscribe))
        self.assertTrue(replace(srv, major_version=0xFF).matches_subscribe(subscribe))
        self.assertFalse(
            replace(srv, eventgroups=(1, 2, 3)).matches_subscribe(subscribe)
        )

        # ttl=0 is StopSubscribe, should still match
        stop_subscribe = replace(subscribe, ttl=0)
        self.assertTrue(srv.matches_subscribe(stop_subscribe))

        with self.assertRaises(ValueError):
            srv.matches_subscribe(
                replace(stop_subscribe, sd_type=hdr.SOMEIPSDEntryType.FindService)
            )

    def test_service_match_service(self):
        host = ipaddress.ip_address("2001:db8::1234:5678:dead:beef")
        port = 4321

        ep = hdr.IPv6EndpointOption(
            address=host, l4proto=hdr.L4Protocols.TCP, port=port
        )

        srv = cfg.Service(
            service_id=0x1111,
            instance_id=0x2222,
            major_version=0x33,
            minor_version=0x333333,
            options_1=(ep,),
        )

        other = cfg.Service(
            service_id=0x1111,
            instance_id=0x2222,
            major_version=0x33,
            minor_version=0x333333,
        )

        self.assertTrue(srv.matches_service(other))
        self.assertFalse(srv.matches_service(replace(other, service_id=0x0101)))
        self.assertFalse(srv.matches_service(replace(other, instance_id=0x0101)))
        self.assertTrue(srv.matches_service(replace(other, instance_id=0xFFFF)))
        self.assertFalse(srv.matches_service(replace(other, major_version=0x0B)))
        self.assertTrue(srv.matches_service(replace(other, major_version=0xFF)))
        self.assertFalse(srv.matches_service(replace(other, minor_version=0x0B0B0B)))
        self.assertTrue(srv.matches_service(replace(other, minor_version=0xFFFFFFFF)))


if __name__ == "__main__":
    unittest.main()
