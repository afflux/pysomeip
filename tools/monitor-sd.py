#!/usr/bin/env python3
import asyncio
import ipaddress
import logging

import someip.config
from someip.sd import ServiceDiscoveryProtocol as SDProto


async def run(local_addr, multicast_addr, port, services):
    transport, protocol = await SDProto.create_endpoint(
        local_addr=local_addr,
        multicast_addr=multicast_addr,
        port=port,
    )

    if services:
        for sid in services:
            protocol.watch_service(someip.config.Service(sid))

        await protocol.send_find_services()

    try:
        while True:
            await asyncio.sleep(10)
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
    parser.add_argument('local_addr', type=ipaddress.ip_address)
    parser.add_argument('multicast_addr', type=ipaddress.ip_address)
    parser.add_argument('port', type=int)
    parser.add_argument('--service', type=auto_int, action='append')

    args = parser.parse_args()

    try:
        asyncio.get_event_loop().run_until_complete(run(args.local_addr,
                                                        args.multicast_addr,
                                                        args.port, args.service))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
