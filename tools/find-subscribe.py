#!/usr/bin/env python3
import asyncio
import ipaddress
import logging
import socket

import someip.header
from someip.config import Eventgroup, _T_SOCKNAME
from someip.sd import SOMEIPDatagramProtocol, ServiceDiscoveryProtocol

logging.getLogger("someip.sd").setLevel(logging.WARNING)
logging.getLogger("someip.sd.announce").setLevel(logging.WARNING)


def enhex(buf, sep=" "):
    return sep.join("%02x" % b for b in buf)


class EventGroupReceiver(SOMEIPDatagramProtocol):
    def __init__(self):
        super().__init__(logger="notification")

    def message_received(
        self,
        someip_message: someip.header.SOMEIPHeader,
        addr: _T_SOCKNAME,
        multicast: bool,
    ) -> None:
        """
        called when a well-formed SOME/IP datagram was received
        """
        if someip_message.message_type != someip.header.SOMEIPMessageType.NOTIFICATION:
            self.log.warning("unexpected message type: %s", someip_message)
            return
        self.log.info(
            "service=0x%04x method=0x%04x interface_version=0x%02x"
            " returncode=%s payload=%s",
            someip_message.service_id,
            someip_message.method_id,
            someip_message.interface_version,
            someip_message.return_code.name,
            enhex(someip_message.payload),
        )


async def run(
    local_addr, multicast_addr, local_port, service_id, instance_id, major_version, evgid
):
    trsp_u, trsp_m, protocol = await ServiceDiscoveryProtocol.create_endpoints(
        family=socket.AF_INET,
        local_addr=str(local_addr),
        multicast_addr=str(multicast_addr),
        port=30490,
    )

    evgrp_receiver, _ = await EventGroupReceiver.create_unicast_endpoint(
        local_addr=(str(local_addr), local_port)
    )
    sockname = evgrp_receiver.get_extra_info("sockname")

    try:
        protocol.start()
        protocol.discovery.find_subscribe_eventgroup(
            Eventgroup(
                service_id=service_id,
                instance_id=instance_id,
                major_version=major_version,
                eventgroup_id=evgid,
                sockname=sockname,
                protocol=someip.header.L4Protocols.UDP,
            )
        )
        while True:
            await asyncio.sleep(10)
    finally:
        protocol.stop()
        evgrp_receiver.close()
        trsp_u.close()
        trsp_m.close()


def auto_int(s):
    return int(s, 0)


def setup_log(fmt="", **kwargs):
    try:
        import coloredlogs  # type: ignore[import]
        coloredlogs.install(fmt="%(asctime)s,%(msecs)03d " + fmt, **kwargs)
    except ModuleNotFoundError:
        logging.basicConfig(format="%(asctime)s " + fmt, **kwargs)
        logging.info("install coloredlogs for colored logs :-)")


def main():
    setup_log(level=logging.DEBUG, fmt="%(levelname)-8s %(name)s: %(message)s")
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("local_addr", type=ipaddress.ip_address)
    parser.add_argument("multicast_addr", type=ipaddress.ip_address)
    parser.add_argument("local_port", type=int)
    parser.add_argument("service", type=auto_int)
    parser.add_argument("eventgroup_id", type=auto_int)
    parser.add_argument("--instance", type=auto_int, default=0xffff)
    parser.add_argument("--major_version", type=auto_int, default=0xff)

    args = parser.parse_args()

    try:
        asyncio.get_event_loop().run_until_complete(
            run(
                args.local_addr,
                args.multicast_addr,
                args.local_port,
                args.service,
                args.instance,
                args.major_version,
                args.eventgroup_id,
            )
        )
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
