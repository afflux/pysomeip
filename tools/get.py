#!/usr/bin/env python3
import asyncio
import ipaddress
import logging
import typing

import someip.header
from someip.sd import DatagramProtocol

LOG = logging.getLogger('someip.get')


class Prot(DatagramProtocol):
    def get(self, service, method):
        hdr = someip.header.SOMEIPHeader(
            service_id=service,
            method_id=method,
            client_id=0,
            session_id=0,
            interface_version=1,
            message_type=someip.header.SOMEIPMessageType.REQUEST,
        )
        self.transport.sendto(hdr.build())

    def message_received(self,
                         someip_message: someip.header.SOMEIPHeader,
                         addr: typing.Tuple[str, int]) -> None:
        '''
        called when a well-formed SOME/IP datagram was received
        '''
        super().message_received(someip_message, addr)
        LOG.info('payload: %r', someip_message.payload)


async def run(addr, port, service, method, interval):
    transport, protocol = await asyncio.get_event_loop().create_datagram_endpoint(
        Prot,
        remote_addr=(str(addr), port),
    )

    try:
        while True:
            protocol.get(service, method)
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        pass
    finally:
        transport.close()


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
    setup_log('%(levelname)-8s %(name)s: %(message)s', level=logging.DEBUG)

    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('host', type=ipaddress.ip_address)
    parser.add_argument('port', type=int)
    parser.add_argument('service', type=auto_int)
    parser.add_argument('method', type=auto_int)
    parser.add_argument('--interval', type=int, default=3)

    args = parser.parse_args()

    try:
        asyncio.get_event_loop().run_until_complete(run(args.host,
                                                        args.port,
                                                        args.service,
                                                        args.method,
                                                        args.interval))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
