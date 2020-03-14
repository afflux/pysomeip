#!/usr/bin/env python3
import asyncio
import ipaddress
import logging

import someip.config
from someip.sd import ServiceDiscoveryProtocol as SDProto, ServiceListener

LOG = logging.getLogger('monitor-sd')


class Monitor(ServiceListener):
    def service_offered(self, service):
        LOG.info('offer: %s', service)

    def service_stopped(self, service):
        LOG.info('offer STOPPED: %s', service)


async def run(local_addr, multicast_addr, port, services):
    trsp_u, trsp_m, protocol = await SDProto.create_endpoints(
        local_addr=local_addr,
        multicast_addr=multicast_addr,
        port=port,
    )

    monitor = Monitor()

    if services:
        for sid in services:
            protocol.watch_service(someip.config.Service(sid), monitor)

        await protocol.send_find_services()
    else:
        protocol.watch_all_service(monitor)

    try:
        while True:
            await asyncio.sleep(10)
    except asyncio.CancelledError:
        pass
    finally:
        trsp_u.close()
        trsp_m.close()


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
    setup_log('%(levelname)-8s %(name)s: %(message)s', level=logging.INFO)

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
