#!/usr/bin/env python3
import argparse
import asyncio
import ipaddress
import logging

import someip.header
from someip.sd import SOMEIPDatagramProtocol

LOG = logging.getLogger("someip.get")


class Prot(SOMEIPDatagramProtocol):
    def get(self, service, method, major_version):
        hdr = someip.header.SOMEIPHeader(
            service_id=service,
            method_id=method,
            client_id=0,
            session_id=0,
            interface_version=major_version,
            message_type=someip.header.SOMEIPMessageType.REQUEST,
        )
        self.send(hdr.build())

    def message_received(
        self,
        someip_message: someip.header.SOMEIPHeader,
        addr: someip.header._T_SOCKNAME,
        multicast: bool,
    ) -> None:
        LOG.info(
            "response: %r / %r", someip_message.return_code, someip_message.payload
        )


async def run(addr, port, service, method, version, interval):
    transport, prot = await Prot.create_unicast_endpoint(remote_addr=(str(addr), port))

    try:
        while True:
            prot.get(service, method, version)
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        pass
    finally:
        transport.close()


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
    setup_log("%(levelname)-8s %(name)s: %(message)s", level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument("host", type=ipaddress.ip_address)
    parser.add_argument("port", type=int)
    parser.add_argument("service", type=auto_int)
    parser.add_argument("method", type=auto_int)
    parser.add_argument("version", type=auto_int)
    parser.add_argument("--interval", type=int, default=3)

    args = parser.parse_args()

    try:
        asyncio.get_event_loop().run_until_complete(
            run(
                args.host,
                args.port,
                args.service,
                args.method,
                args.version,
                args.interval,
            )
        )
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
