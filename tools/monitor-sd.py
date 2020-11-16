#!/usr/bin/env python3
import asyncio
import socket
import logging

import someip.config
from someip.sd import ServiceDiscoveryProtocol as SDProto, ClientServiceListener

LOG = logging.getLogger("monitor-sd")
logging.getLogger("someip.sd.announce").setLevel(logging.WARNING)


class Monitor(ClientServiceListener):
    def service_offered(self, service, source):
        LOG.info("offer: %s", service)

    def service_stopped(self, service, source):
        LOG.info("offer STOPPED: %s", service)


async def run(local_addr, multicast_addr, port, services):
    trsp_u, trsp_m, protocol = await SDProto.create_endpoints(
        family=socket.AF_INET,
        local_addr=local_addr,
        multicast_addr=multicast_addr,
        port=port,
    )

    monitor = Monitor()

    if services:
        for sid in services:
            protocol.discovery.watch_service(someip.config.Service(sid), monitor)

        protocol.discovery.start()
    else:
        protocol.discovery.watch_all_services(monitor)

    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    finally:
        protocol.discovery.stop()
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
    setup_log("%(levelname)-8s %(name)s: %(message)s", level=logging.INFO)

    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("local_addr")
    parser.add_argument("multicast_addr")
    parser.add_argument("port", type=int, default=30490)
    parser.add_argument("--service", type=auto_int, action="append")

    args = parser.parse_args()

    try:
        asyncio.get_event_loop().run_until_complete(
            run(args.local_addr, args.multicast_addr, args.port, args.service)
        )
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
