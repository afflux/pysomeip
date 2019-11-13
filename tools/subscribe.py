#!/usr/bin/env python3
import asyncio
import ipaddress
import logging
import socket
import typing

import someip.header
from someip.config import Eventgroup
from someip.sd import SubscriptionProtocol, SOMEIPDatagramProtocol
from someip.utils import getfirstaddrinfo


def enhex(buf, sep=' '):
    return sep.join('%02x' % b for b in buf)


class Prot(SOMEIPDatagramProtocol):
    def __init__(self):
        super().__init__(logger='notification')

    def message_received(self,
                         someip_message: someip.header.SOMEIPHeader,
                         addr: typing.Tuple[str, int],
                         multicast: bool) -> None:
        '''
        called when a well-formed SOME/IP datagram was received
        '''
        if someip_message.message_type != someip.header.SOMEIPMessageType.NOTIFICATION:
            self.log.warning('unexpected message type: %s', someip_message)
            return
        self.log.info('service=0x%04x method=0x%04x interface_version=0x%02x'
                      ' returncode=%s payload=%s',
                      someip_message.service_id,
                      someip_message.method_id,
                      someip_message.interface_version,
                      someip_message.return_code.name,
                      enhex(someip_message.payload))


async def run(local_addr, remote_addr, port, service, instance, major_version, eventgroup_id):
    local_transport, _ = await Prot.create_unicast_endpoint(local_addr=(str(local_addr), 0))

    remote_sa = (await getfirstaddrinfo(str(remote_addr), port, type=socket.SOCK_DGRAM))[4]

    transport, protocol = await SubscriptionProtocol.create_unicast_endpoint(
        local_addr=(str(local_addr), port),
    )

    local_sa = local_transport.get_extra_info('sockname')
    protocol.subscribe_eventgroup(
        Eventgroup(
            service,
            instance,
            major_version,
            eventgroup_id,
            local_sa,
            someip.header.L4Protocols.UDP
        ),
        remote_sa
    )

    protocol.start()

    try:
        while True:
            await asyncio.sleep(3)
    except asyncio.CancelledError:
        pass
    finally:
        protocol.stop()
        transport.close()
        local_transport.close()


def auto_int(s):
    return int(s, 0)


def setup_log(fmt='', **kwargs):
    try:
        import coloredlogs
        coloredlogs.install(fmt='%(asctime)s,%(msecs)03d ' + fmt, **kwargs)
    except ModuleNotFoundError:
        logging.basicConfig(format='%(asctime)s ' + fmt, **kwargs)
        logging.info('install coloredlogs for colored logs :-)')


def main():
    setup_log(level=logging.DEBUG, fmt='%(levelname)-8s %(name)s: %(message)s')
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('local', type=ipaddress.ip_address)
    parser.add_argument('remote', type=ipaddress.ip_address)
    parser.add_argument('port', type=int)
    parser.add_argument('service', type=auto_int)
    parser.add_argument('instance', type=auto_int)
    parser.add_argument('major_version', type=auto_int)
    parser.add_argument('eventgroup_id', type=auto_int)

    args = parser.parse_args()

    try:
        asyncio.get_event_loop().run_until_complete(run(args.local, args.remote, args.port,
                                                        args.service, args.instance,
                                                        args.major_version, args.eventgroup_id))
    except KeyboardInterrupt:
        pass


# TODO SD: watch for service, then subscribe on every offer with same ttl


if __name__ == '__main__':
    main()
