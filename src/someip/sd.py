from __future__ import annotations

import asyncio
import collections
import dataclasses
import functools
import ipaddress
import itertools
import logging
import os
import platform
import random
import socket
import struct
import threading
import typing

import someip.header
import someip.config
from someip.config import _T_SOCKNAME as _T_SOCKADDR
from someip.utils import log_exceptions, wait_cancelled

LOG = logging.getLogger("someip.sd")
_T_IPADDR = typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
_T_OPT_SOCKADDR = typing.Optional[_T_SOCKADDR]

TTL_FOREVER = 0xFFFFFF


def ip_address(s: str) -> _T_IPADDR:
    return typing.cast(_T_IPADDR, ipaddress.ip_address(s.split("%", 1)[0]))


def pack_addr_v4(a):
    return socket.inet_pton(socket.AF_INET, a.split("%", 1)[0])


def pack_addr_v6(a):
    return socket.inet_pton(socket.AF_INET6, a.split("%", 1)[0])


def format_address(addr: _T_SOCKADDR) -> str:
    host, port = socket.getnameinfo(addr, socket.NI_NUMERICHOST | socket.NI_NUMERICSERV)
    ip = ipaddress.ip_address(host)
    if isinstance(ip, ipaddress.IPv4Address):
        return f"{ip!s}:{port:s}"
    elif isinstance(ip, ipaddress.IPv6Address):
        return f"[{ip!s}]:{port:s}"
    else:  # pragma: nocover
        raise NotImplementedError(f"unknown ip address format: {addr!r} -> {ip!r}")


class SOMEIPDatagramProtocol:
    """
    is actually not a subclass of asyncio.BaseProtocol or asyncio.DatagramProtocol,
    because datagram_received() has an additional parameter `multicast: bool`

    TODO: fix misleading name
    """

    @classmethod
    async def create_unicast_endpoint(
        cls,
        *args,
        local_addr: _T_OPT_SOCKADDR = None,
        remote_addr: _T_OPT_SOCKADDR = None,
        loop=None,
        **kwargs,
    ):
        if loop is None:  # pragma: nobranch
            loop = asyncio.get_event_loop()
        protocol = cls(*args, **kwargs)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: DatagramProtocolAdapter(protocol, is_multicast=False),
            local_addr=local_addr,
            remote_addr=remote_addr,
        )
        protocol.transport = transport
        return transport, protocol

    def __init__(self, logger: str = "someip"):
        self.log = logging.getLogger(logger)
        self.transport: asyncio.DatagramTransport
        self.session_storage = _SessionStorage()

        # default_addr=None means use connected address from socket
        self.default_addr: _T_OPT_SOCKADDR = None

    def datagram_received(self, data, addr: _T_SOCKADDR, multicast: bool) -> None:
        try:
            while data:
                # 4.2.1, TR_SOMEIP_00140 more than one SOMEIP message per UDP frame
                # allowed
                parsed, data = someip.header.SOMEIPHeader.parse(data)
                self.message_received(parsed, addr, multicast)
        except someip.header.ParseError as exc:
            self.log.error(
                "failed to parse SOME/IP datagram from %s: %r",
                format_address(addr),
                data,
                exc_info=exc,
            )

    def error_received(self, exc: typing.Optional[Exception]):  # pragma: nocover
        self.log.exception("someip event listener protocol failed", exc_info=exc)

    def connection_lost(
        self, exc: typing.Optional[Exception]
    ) -> None:  # pragma: nocover
        log = self.log.exception if exc else self.log.info
        log("someip closed", exc_info=exc)

    def message_received(
        self,
        someip_message: someip.header.SOMEIPHeader,
        addr: _T_SOCKADDR,
        multicast: bool,
    ) -> None:  # pragma: nocover
        """
        called when a well-formed SOME/IP datagram was received
        """
        self.log.info("received from %s\n%s", format_address(addr), someip_message)
        pass

    def send(self, buf: bytes, remote: _T_OPT_SOCKADDR = None):
        # ideally, we'd use transport.write() and have the DGRAM socket connected to the
        # default_addr. However, after connect() the socket will not be bound to
        # INADDR_ANY anymore. so we store the multicast address as a default destination
        # address on the instance and wrap the send calls with self.send
        if not self.transport:  # pragma: nocover
            self.log.error(
                "no transport set on %r but tried to send to %r: %r", self, remote, buf
            )
            return
        if not remote:
            remote = self.default_addr
        self.transport.sendto(buf, remote)


class DatagramProtocolAdapter(asyncio.DatagramProtocol):
    def __init__(self, protocol: SOMEIPDatagramProtocol, is_multicast: bool):
        self.is_multicast = is_multicast
        self.protocol = protocol

    def datagram_received(self, data, addr: _T_SOCKADDR) -> None:
        self.protocol.datagram_received(data, addr, multicast=self.is_multicast)

    def error_received(
        self, exc: typing.Optional[Exception]
    ) -> None:  # pragma: nocover
        self.protocol.error_received(exc)

    def connection_lost(
        self, exc: typing.Optional[Exception]
    ) -> None:  # pragma: nocover
        self.protocol.connection_lost(exc)


class _SessionStorage:
    def __init__(self):
        self.incoming = {}
        self.outgoing: typing.DefaultDict[
            _T_OPT_SOCKADDR, typing.Tuple[bool, int]
        ] = collections.defaultdict(lambda: (True, 1))
        self.outgoing_lock = threading.Lock()

    def check_received(
        self, sender: _T_SOCKADDR, multicast: bool, flag: bool, session_id: int
    ) -> bool:
        """
        return true if a reboot was detected
        """
        k = (sender, multicast)

        try:
            old_flag, old_session_id = self.incoming[k]

            if flag and (
                not old_flag or (old_session_id > 0 and old_session_id >= session_id)
            ):
                return True
            return False
        except KeyError:
            # sender not yet known -> insert
            self.incoming[k] = (flag, session_id)
            return False
        finally:
            self.incoming[k] = (flag, session_id)

    def assign_outgoing(self, remote: _T_OPT_SOCKADDR):
        # need a lock for outgoing messages if they may be sent from separate threads
        # eg. when an application logic runs in a seperate thread from the SOMEIP stack
        # event loop
        with self.outgoing_lock:
            flag, _id = self.outgoing[remote]
            if _id >= 0xFFFF:
                # 4.2.1, TR_SOMEIP_00521
                # 4.2.1, TR_SOMEIP_00255
                self.outgoing[remote] = (False, 1)
            else:
                self.outgoing[remote] = (flag, _id + 1)
        return flag, _id


@dataclasses.dataclass()
class Timings:
    INITIAL_DELAY_MIN: float = dataclasses.field(default=0.0)  # in seconds
    INITIAL_DELAY_MAX: float = dataclasses.field(default=3)  # in seconds
    REQUEST_RESPONSE_DELAY_MIN: float = dataclasses.field(default=0.01)  # in seconds
    REQUEST_RESPONSE_DELAY_MAX: float = dataclasses.field(default=0.05)  # in seconds
    REPETITIONS_MAX: int = dataclasses.field(default=3)
    REPETITIONS_BASE_DELAY: float = dataclasses.field(default=0.01)  # in seconds
    CYCLIC_OFFER_DELAY: float = dataclasses.field(default=1)  # in seconds
    FIND_TTL: int = dataclasses.field(default=3)  # in seconds
    ANNOUNCE_TTL: int = dataclasses.field(default=3)  # in seconds
    SUBSCRIBE_TTL: int = dataclasses.field(default=5)  # in seconds
    SUBSCRIBE_REFRESH_INTERVAL: typing.Optional[float] = dataclasses.field(
        default=3
    )  # in seconds


class ServiceDiscoveryProtocol(SOMEIPDatagramProtocol):
    @classmethod
    async def _create_endpoint(
        cls,
        loop: asyncio.BaseEventLoop,
        prot: SOMEIPDatagramProtocol,
        family: socket.AddressFamily,
        local_addr: str,
        port: int,
        multicast_addr: typing.Optional[str] = None,
        multicast_interface: typing.Optional[str] = None,
        ttl: int = 1,
    ):

        if family not in (socket.AF_INET, socket.AF_INET6):
            raise ValueError("only IPv4 and IPv6 supported, got {family!r}")

        if os.name == "posix":  # pragma: nocover
            # multicast binding:
            # - BSD: will only receive packets destined for multicast addr,
            #        but will send with address from bind()
            # - Linux: will receive all multicast traffic destined for this port,
            #          can be filtered using bind()
            bind_addr: typing.Optional[str] = local_addr
            if multicast_addr:
                bind_addr = None
                if platform.system() == "Linux":  # pragma: nocover
                    if family == socket.AF_INET or "%" in multicast_addr:
                        bind_addr = multicast_addr
                    else:
                        bind_addr = f"{multicast_addr}%{multicast_interface}"
            # wrong type in asyncio typeshed, should be optional
            bind_addr = typing.cast(str, bind_addr)

            trsp, _ = await loop.create_datagram_endpoint(
                lambda: DatagramProtocolAdapter(
                    prot, is_multicast=bool(multicast_addr)
                ),
                local_addr=(bind_addr, port),
                reuse_port=True,
                family=family,
                proto=socket.IPPROTO_UDP,
                flags=socket.AI_PASSIVE,
            )
        elif platform.system() == "Windows":  # pragma: nocover
            sock = socket.socket(
                family=family, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP
            )

            if (
                family == socket.AF_INET6
                and platform.python_version_tuple() < ("3", "8", "4")
                and isinstance(loop, getattr(asyncio, "ProactorEventLoop", ()))
            ):
                prot.log.warning(
                    "ProactorEventLoop has issues with ipv6 datagram sockets!"
                    " https://bugs.python.org/issue39148. Update to Python>=3.8.4, or"
                    " workaround with asyncio.set_event_loop_policy("
                    "asyncio.WindowsSelectorEventLoopPolicy())",
                )

            # python disallowed SO_REUSEADDR on create_datagram_endpoint.
            # https://bugs.python.org/issue37228
            # Windows doesnt have SO_REUSEPORT and the problem apparently does not exist
            # for multicast, so we need to set SO_REUSEADDR on the socket manually
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            addrinfos = await loop.getaddrinfo(
                local_addr,
                port,
                family=sock.family,
                type=sock.type,
                proto=sock.proto,
                flags=socket.AI_PASSIVE,
            )
            if not addrinfos:
                raise RuntimeError(
                    f"could not resolve local_addr={local_addr!r} port={port!r}"
                )

            ai = addrinfos[0]

            sock.bind(ai[4])
            trsp, _ = await loop.create_datagram_endpoint(
                lambda: DatagramProtocolAdapter(
                    prot, is_multicast=bool(multicast_addr)
                ),
                sock=sock,
            )
        else:  # pragma: nocover
            raise NotImplementedError(
                f"unsupported platform {os.name} {platform.system()}"
            )

        sock = trsp.get_extra_info("socket")

        try:
            if family == socket.AF_INET:
                packed_local_addr = pack_addr_v4(local_addr)
                if multicast_addr:
                    packed_mcast_addr = pack_addr_v4(multicast_addr)
                    mreq = struct.pack("=4s4s", packed_mcast_addr, packed_local_addr)
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_IF, packed_local_addr
                )
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

            else:  # AF_INET6
                if multicast_interface is None:
                    raise ValueError("ipv6 requires interface name")
                ifindex = socket.if_nametoindex(multicast_interface)
                if multicast_addr:
                    packed_mcast_addr = pack_addr_v6(multicast_addr)
                    mreq = struct.pack("=16sl", packed_mcast_addr, ifindex)
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
                sock.setsockopt(
                    socket.IPPROTO_IPV6,
                    socket.IPV6_MULTICAST_IF,
                    struct.pack("=i", ifindex),
                )
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
        except BaseException:
            trsp.close()
            raise

        return trsp

    @classmethod
    async def create_endpoints(
        cls,
        family: socket.AddressFamily,
        local_addr: str,
        multicast_addr: str,
        multicast_interface: typing.Optional[str] = None,
        port: int = 30490,
        ttl=1,
        loop=None,
    ):
        if loop is None:  # pragma: nobranch
            loop = asyncio.get_event_loop()
        if not ip_address(multicast_addr).is_multicast:
            raise ValueError("multicast_addr is not multicast")

        # since posix does not provide a portable interface to figure out what address a
        # datagram was received on, we need one unicast and one multicast socket
        prot = cls((str(multicast_addr), port))

        # order matters, at least for Windows. If the multicast socket was created
        # first, both unicast and multicast packets would go to the multicast socket
        trsp_u = await cls._create_endpoint(
            loop,
            prot,
            family,
            local_addr,
            port,
            multicast_interface=multicast_interface,
            ttl=ttl,
        )

        trsp_m = await cls._create_endpoint(
            loop,
            prot,
            family,
            local_addr,
            port,
            multicast_addr=multicast_addr,
            multicast_interface=multicast_interface,
            ttl=ttl,
        )

        prot.transport = trsp_u

        return trsp_u, trsp_m, prot

    def __init__(
        self,
        multicast_addr: _T_SOCKADDR,
        timings: typing.Optional[Timings] = None,
        logger: str = "someip.sd",
    ):
        super().__init__(logger=logger)
        self.timings = timings or Timings()
        self.default_addr = multicast_addr
        self.discovery = ServiceDiscover(self)
        self.subscriber = ServiceSubscriber(self)
        self.announcer = ServiceAnnouncer(self)

    def message_received(
        self,
        someip_message: someip.header.SOMEIPHeader,
        addr: _T_SOCKADDR,
        multicast: bool,
    ) -> None:
        if (
            someip_message.service_id != someip.header.SD_SERVICE
            or someip_message.method_id != someip.header.SD_METHOD
            or someip_message.interface_version != someip.header.SD_INTERFACE_VERSION
            or someip_message.return_code != someip.header.SOMEIPReturnCode.E_OK
            or someip_message.message_type
            != someip.header.SOMEIPMessageType.NOTIFICATION
        ):
            self.log.error("SD protocol received non-SD message: %s", someip_message)
            return

        try:
            sdhdr, rest = someip.header.SOMEIPSDHeader.parse(someip_message.payload)
        except someip.header.ParseError as exc:
            self.log.error("SD-message did not parse: %r", exc)
            return

        if self.session_storage.check_received(
            addr, multicast, sdhdr.flag_reboot, someip_message.session_id
        ):
            self.reboot_detected(addr)

        # FIXME this will drop the SD Endpoint options, since they are not referenced by
        # entries. see 4.2.1 TR_SOMEIP_00548
        sdhdr_resolved = sdhdr.resolve_options()
        self.sd_message_received(sdhdr_resolved, addr, multicast)

        if rest:  # pragma: nocover
            self.log.warning(
                "unparsed data after SD from %s: %r", format_address(addr), rest
            )

    def send_sd(
        self,
        entries: typing.Collection[someip.header.SOMEIPSDEntry],
        remote: _T_OPT_SOCKADDR = None,
    ) -> None:
        if not entries:
            return
        flag_reboot, session_id = self.session_storage.assign_outgoing(remote)

        msg = someip.header.SOMEIPSDHeader(
            flag_reboot=flag_reboot,
            flag_unicast=True,  # 4.2.1, TR_SOMEIP_00540 receiving unicast is supported
            entries=tuple(entries),
        )
        msg_assigned = msg.assign_option_indexes()

        hdr = someip.header.SOMEIPHeader(
            service_id=someip.header.SD_SERVICE,
            method_id=someip.header.SD_METHOD,
            client_id=0,
            session_id=session_id,
            interface_version=1,
            message_type=someip.header.SOMEIPMessageType.NOTIFICATION,
            payload=msg_assigned.build(),
        )

        self.send(hdr.build(), remote)

    def start(self) -> None:
        self.subscriber.start()
        self.announcer.start()
        self.discovery.start()

    def stop(self) -> None:
        self.discovery.stop()
        self.announcer.stop()
        self.subscriber.stop()

    def connection_lost(self, exc: typing.Optional[Exception]) -> None:
        log = self.log.exception if exc else self.log.info
        log("connection lost. stopping all child tasks", exc_info=exc)
        asyncio.get_event_loop().call_soon(self.subscriber.connection_lost, exc)
        asyncio.get_event_loop().call_soon(self.discovery.connection_lost, exc)
        asyncio.get_event_loop().call_soon(self.announcer.connection_lost, exc)

    def reboot_detected(self, addr: _T_SOCKADDR) -> None:
        asyncio.get_event_loop().call_soon(self.subscriber.reboot_detected, addr)
        asyncio.get_event_loop().call_soon(self.discovery.reboot_detected, addr)
        asyncio.get_event_loop().call_soon(self.announcer.reboot_detected, addr)

    def sd_message_received(
        self, sdhdr: someip.header.SOMEIPSDHeader, addr: _T_SOCKADDR, multicast: bool
    ) -> None:
        """
        called when a well-formed SOME/IP SD message was received
        """
        LOG.debug(
            "sd_message_received received from %s (multicast=%r): %s",
            format_address(addr),
            multicast,
            sdhdr,
        )

        for entry in sdhdr.entries:
            if entry.sd_type == someip.header.SOMEIPSDEntryType.OfferService:
                asyncio.get_event_loop().call_soon(
                    self.discovery.handle_offer, entry, addr
                )
                continue

            if entry.sd_type == someip.header.SOMEIPSDEntryType.SubscribeAck:
                # TODO raise to application
                # TODO figure out what to do when not receiving an ACK after X?
                if entry.ttl == 0:
                    self.log.info("received Subscribe NACK from %s: %s", addr, entry)
                else:
                    self.log.info("received Subscribe ACK from %s: %s", addr, entry)
                continue

            if entry.sd_type == someip.header.SOMEIPSDEntryType.FindService:
                asyncio.create_task(
                    self.announcer.handle_findservice(
                        entry, addr, multicast, sdhdr.flag_unicast
                    ),
                )
                continue

            if (  # pragma: nobranch
                entry.sd_type == someip.header.SOMEIPSDEntryType.Subscribe
            ):
                if multicast:
                    self.log.warning(
                        "discarding subscribe received over multicast from %s: %s",
                        format_address(addr),
                        entry,
                    )
                    continue
                asyncio.create_task(self.announcer.handle_subscribe(entry, addr))
                continue


class ServiceSubscriber:
    """
    datagram protocol for subscribing to eventgroups via SOME/IP SD

    example:
        TODO
    """

    def __init__(self, sd: ServiceDiscoveryProtocol):
        self.sd = sd
        self.timings = sd.timings
        self.log = sd.log.getChild("subscribe")

        ttl = self.timings.SUBSCRIBE_TTL
        refresh_interval = self.timings.SUBSCRIBE_REFRESH_INTERVAL

        if not refresh_interval and ttl < TTL_FOREVER:  # pragma: nocover
            self.log.warning(
                "no refresh, but ttl=%r set. expect lost connection after ttl", ttl
            )
        elif refresh_interval and refresh_interval >= ttl:  # pragma: nocover
            self.log.warning(
                "refresh_interval=%r too high for ttl=%r. expect dropped updates.",
                refresh_interval,
                ttl,
            )

        self.task: typing.Optional[asyncio.Task[None]] = None
        # separate alive tracking (instead of using task.done()) as task will only run
        # for one iteration when ttl=None
        self.alive = False

        self.subscribeentries: typing.List[
            typing.Tuple[someip.config.Eventgroup, _T_SOCKADDR],
        ] = []

    def subscribe_eventgroup(
        self, eventgroup: someip.config.Eventgroup, endpoint: _T_SOCKADDR
    ) -> None:
        """
        eventgroup:
          someip.config.Eventgroup that describes the eventgroup to subscribe to and the
          local endpoint that accepts the notifications
        endpoint:
          remote SD endpoint that will receive the subscription messages
        """
        # relies on _subscribe() to send out the Subscribe messages in the next cycle.
        self.subscribeentries.append((eventgroup, endpoint))

        if self.alive:
            asyncio.get_event_loop().call_soon(
                self._send_start_subscribe, endpoint, [eventgroup]
            )

    def stop_subscribe_eventgroup(
        self,
        eventgroup: someip.config.Eventgroup,
        endpoint: _T_SOCKADDR,
        send: bool = True,
    ) -> None:
        """
        eventgroup:
          someip.config.Eventgroup that describes the eventgroup to unsubscribe from
        endpoint:
          remote SD endpoint that will receive the subscription messages
        """
        try:
            self.subscribeentries.remove((eventgroup, endpoint))
        except ValueError:
            return

        if send:
            asyncio.get_event_loop().call_soon(
                self._send_stop_subscribe, endpoint, [eventgroup]
            )

    def _send_stop_subscribe(
        self, remote: _T_SOCKADDR, entries: typing.Collection[someip.config.Eventgroup]
    ) -> None:
        self._send_subscribe(0, remote, entries)

    def _send_start_subscribe(
        self, remote: _T_SOCKADDR, entries: typing.Collection[someip.config.Eventgroup]
    ) -> None:
        self._send_subscribe(self.timings.SUBSCRIBE_TTL, remote, entries)

    def _send_subscribe(
        self,
        ttl: int,
        remote: _T_SOCKADDR,
        entries: typing.Collection[someip.config.Eventgroup],
    ) -> None:
        self.sd.send_sd(
            [e.create_subscribe_entry(ttl=ttl) for e in entries], remote=remote
        )

    def start(self, loop=None) -> None:
        if self.alive:  # pragma: nocover
            return
        if loop is None:  # pragma: nobranch
            loop = asyncio.get_event_loop()

        self.alive = True
        self.task = loop.create_task(self._subscribe())

    def stop(self, send_stop_subscribe=True) -> None:
        if not self.alive:
            return

        self.alive = False

        if self.task:  # pragma: nobranch
            self.task.cancel()
            asyncio.create_task(wait_cancelled(self.task))
            self.task = None

        if send_stop_subscribe:
            for endpoint, entries in self._group_entries().items():
                asyncio.get_event_loop().call_soon(
                    self._send_stop_subscribe, endpoint, entries
                )

    def _group_entries(
        self,
    ) -> typing.Mapping[_T_SOCKADDR, typing.Collection[someip.config.Eventgroup]]:
        endpoint_entries: typing.DefaultDict[
            _T_SOCKADDR, typing.List[someip.config.Eventgroup]
        ] = collections.defaultdict(list)
        for eventgroup, endpoint in self.subscribeentries:
            endpoint_entries[endpoint].append(eventgroup)
        return endpoint_entries

    @log_exceptions()
    async def _subscribe(self) -> None:
        while True:
            for endpoint, entries in self._group_entries().items():
                self._send_start_subscribe(endpoint, entries)

            if self.timings.SUBSCRIBE_REFRESH_INTERVAL is None:
                break

            try:
                await asyncio.sleep(self.timings.SUBSCRIBE_REFRESH_INTERVAL)
            except asyncio.CancelledError:
                break

    def reboot_detected(self, addr: _T_SOCKADDR) -> None:
        # TODO
        pass

    def connection_lost(self, exc: typing.Optional[Exception]) -> None:
        self.stop(send_stop_subscribe=False)


class ClientServiceListener:
    def service_offered(
        self, service: someip.config.Service, source: _T_SOCKADDR
    ) -> None:
        ...

    def service_stopped(
        self, service: someip.config.Service, source: _T_SOCKADDR
    ) -> None:
        ...


@dataclasses.dataclass(frozen=True)
class AutoSubscribeServiceListener(ClientServiceListener):
    subscriber: ServiceSubscriber
    eventgroup: someip.config.Eventgroup

    def service_offered(
        self, service: someip.config.Service, source: _T_SOCKADDR
    ) -> None:
        eventgroup = self.eventgroup.for_service(service)
        if not eventgroup:  # pragma: nocover
            return
        # TODO support TCP event groups: application (or lib?) needs to open connection
        # before subscribe
        self.subscriber.subscribe_eventgroup(eventgroup, source)

    def service_stopped(
        self, service: someip.config.Service, source: _T_SOCKADDR
    ) -> None:
        eventgroup = self.eventgroup.for_service(service)
        if not eventgroup:  # pragma: nocover
            return
        # TODO support TCP event groups: application (or lib?) needs to close connection
        self.subscriber.stop_subscribe_eventgroup(eventgroup, source)


KT = typing.TypeVar("KT")
_T_CALLBACK = typing.Callable[[KT, _T_SOCKADDR], None]


class TimedStore(typing.Generic[KT]):
    def __init__(self, log):
        self.log = log
        self.store: typing.Dict[
            _T_SOCKADDR,
            typing.Dict[
                KT,
                typing.Tuple[
                    typing.Callable[[KT, _T_SOCKADDR], None],
                    typing.Optional[asyncio.Handle],
                ],
            ],
        ] = collections.defaultdict(dict)

    def refresh(
        self,
        ttl,
        address: _T_SOCKADDR,
        entry: KT,
        callback_new: _T_CALLBACK[KT],
        callback_expired: _T_CALLBACK[KT],
    ) -> None:
        try:
            _, old_timeout_handle = self.store[address].pop(entry)
            if old_timeout_handle:
                old_timeout_handle.cancel()
        except KeyError:
            # pop failed => new entry
            callback_new(entry, address)

        timeout_handle = None
        if ttl != TTL_FOREVER:
            timeout_handle = asyncio.get_event_loop().call_later(
                ttl, self._expired, address, entry
            )

        self.store[address][entry] = (callback_expired, timeout_handle)

    def stop(self, address: _T_SOCKADDR, entry: KT) -> None:
        try:
            callback, _timeout_handle = self.store[address].pop(entry)
        except KeyError:
            # race-condition: service was already stopped. don't notify again
            return

        if _timeout_handle:
            _timeout_handle.cancel()

        asyncio.get_event_loop().call_soon(callback, entry, address)

    def stop_all_for_address(self, address: _T_SOCKADDR) -> None:
        for entry, (callback, handle) in self.store[address].items():
            if handle:
                handle.cancel()
            asyncio.get_event_loop().call_soon(callback, entry, address)
        self.store[address].clear()

    def stop_all(self) -> None:
        for addr in self.store.keys():
            self.stop_all_for_address(addr)
        self.store.clear()

    def _expired(self, address: _T_SOCKADDR, entry: KT) -> None:
        try:
            callback, _ = self.store[address].pop(entry)
        except KeyError:  # pragma: nocover
            self.log.warning(
                "race-condition: entry %r timeout was not in store but triggered"
                " anyway. forgot to cancel?",
                entry,
            )
            return

        asyncio.get_event_loop().call_soon(callback, entry, address)

    def entries(self) -> typing.Iterator[KT]:
        return itertools.chain.from_iterable(x.keys() for x in self.store.values())


class ServiceDiscover:
    def __init__(self, sd: ServiceDiscoveryProtocol):
        self.sd = sd
        self.timings = sd.timings
        self.log = sd.log.getChild("discover")

        self.watched_services: typing.Dict[
            someip.config.Service,
            typing.Set[ClientServiceListener],
        ] = collections.defaultdict(set)
        self.watcher_all_services: typing.Set[ClientServiceListener] = set()

        self.found_services: TimedStore[someip.config.Service] = TimedStore(self.log)
        self.task: typing.Optional[asyncio.Task[None]] = None

    def start(self):
        if self.task is not None and not self.task.done():  # pragma: nocover
            return

        loop = asyncio.get_running_loop()
        self.task = loop.create_task(self.send_find_services())

    def stop(self):
        if self.task:  # pragma: nobranch
            self.task.cancel()
            asyncio.create_task(wait_cancelled(self.task))
            self.task = None

    def handle_offer(
        self, entry: someip.header.SOMEIPSDEntry, addr: _T_SOCKADDR
    ) -> None:
        if not self.is_watching_service(entry):
            return
        if entry.ttl == 0:
            self.service_offer_stopped(addr, entry)
        else:
            self.service_offered(addr, entry)

    def is_watching_service(self, entry: someip.header.SOMEIPSDEntry):
        if self.watcher_all_services:
            return True
        return any(s.matches_offer(entry) for s in self.watched_services.keys())

    def watch_service(
        self, service: someip.config.Service, listener: ClientServiceListener
    ) -> None:
        self.watched_services[service].add(listener)

        for addr, services in self.found_services.store.items():
            for s in services:
                if service.matches_service(s):
                    asyncio.get_event_loop().call_soon(
                        listener.service_offered, s, addr
                    )

    def stop_watch_service(
        self, service: someip.config.Service, listener: ClientServiceListener
    ) -> None:
        self.watched_services[service].remove(listener)

        # TODO verify if this makes sense
        for addr, services in self.found_services.store.items():
            for s in services:
                if service.matches_service(s):
                    asyncio.get_event_loop().call_soon(
                        listener.service_stopped, s, addr
                    )

    def watch_all_services(self, listener: ClientServiceListener) -> None:
        self.watcher_all_services.add(listener)

        for addr, services in self.found_services.store.items():
            for s in services:
                asyncio.get_event_loop().call_soon(listener.service_offered, s, addr)

    def stop_watch_all_services(self, listener: ClientServiceListener) -> None:
        self.watcher_all_services.remove(listener)

        # TODO verify if this makes sense
        for addr, services in self.found_services.store.items():
            for s in services:
                asyncio.get_event_loop().call_soon(listener.service_stopped, s, addr)

    def find_subscribe_eventgroup(self, eventgroup: someip.config.Eventgroup):
        self.watch_service(
            eventgroup.as_service(),
            AutoSubscribeServiceListener(self.sd.subscriber, eventgroup),
        )

    def stop_find_subscribe_eventgroup(self, eventgroup: someip.config.Eventgroup):
        self.stop_watch_service(
            eventgroup.as_service(),
            AutoSubscribeServiceListener(self.sd.subscriber, eventgroup),
        )

    def _service_found(self, service: someip.config.Service) -> bool:
        return any(service.matches_service(s) for s in self.found_services.entries())

    async def send_find_services(self):
        if not self.watched_services:
            return

        def _build_entries():
            return [
                service.create_find_entry(self.timings.FIND_TTL)
                for service in self.watched_services.keys()
                if not self._service_found(service)  # 4.2.1: SWS_SD_00365
            ]

        await asyncio.sleep(
            random.uniform(
                self.timings.INITIAL_DELAY_MIN, self.timings.INITIAL_DELAY_MAX
            )
        )
        find_entries = _build_entries()
        if not find_entries:
            return
        self.sd.send_sd(find_entries)  # 4.2.1: SWS_SD_00353

        for i in range(self.timings.REPETITIONS_MAX):
            await asyncio.sleep(
                (2 ** i) * self.timings.REPETITIONS_BASE_DELAY
            )  # 4.2.1: SWS_SD_00363

            find_entries = _build_entries()
            if not find_entries:
                return
            self.sd.send_sd(find_entries)  # 4.2.1: SWS_SD_00457

    def service_offered(self, addr: _T_SOCKADDR, entry: someip.header.SOMEIPSDEntry):
        service = someip.config.Service.from_offer_entry(entry)

        self.found_services.refresh(
            entry.ttl,
            addr,
            service,
            self._notify_service_offered,
            self._notify_service_stopped,
        )

    def connection_lost(self, exc: typing.Optional[Exception]) -> None:
        self.found_services.stop_all()

    def service_offer_stopped(
        self, addr: _T_SOCKADDR, entry: someip.header.SOMEIPSDEntry
    ) -> None:
        service = someip.config.Service.from_offer_entry(entry)

        self.found_services.stop(addr, service)

    def reboot_detected(self, addr: _T_SOCKADDR) -> None:
        # notify stop for each service of rebooted instance.
        # reboot_detected() is called before sd_message_received(), so any offered
        # service in this message will cause a new notify
        self.found_services.stop_all_for_address(addr)

    def _notify_service_offered(
        self, service: someip.config.Service, source: _T_SOCKADDR
    ) -> None:
        for service_filter, listeners in self.watched_services.items():
            if service_filter.matches_service(service):
                for listener in listeners:
                    listener.service_offered(service, source)
        for listener in self.watcher_all_services:
            listener.service_offered(service, source)

    def _notify_service_stopped(
        self, service: someip.config.Service, source: _T_SOCKADDR
    ) -> None:
        for service_filter, listeners in self.watched_services.items():
            if service_filter.matches_service(service):
                for listener in listeners:
                    listener.service_stopped(service, source)
        for listener in self.watcher_all_services:
            listener.service_stopped(service, source)


@dataclasses.dataclass(frozen=True)
class EventgroupSubscription:
    service_id: int
    instance_id: int
    major_version: int
    id: int
    counter: int
    ttl: int = dataclasses.field(compare=False)
    endpoints: typing.FrozenSet[
        someip.header.EndpointOption[typing.Any]
    ] = dataclasses.field(default_factory=frozenset)
    options: typing.Tuple[someip.header.SOMEIPSDOption, ...] = dataclasses.field(
        default_factory=tuple, compare=False
    )

    @classmethod
    def from_subscribe_entry(cls, entry: someip.header.SOMEIPSDEntry):
        endpoints = []
        options = []
        for option in entry.options:
            if isinstance(option, someip.header.EndpointOption):
                endpoints.append(option)
            else:
                options.append(option)

        return cls(
            service_id=entry.service_id,
            instance_id=entry.instance_id,
            major_version=entry.major_version,
            id=entry.eventgroup_id,
            counter=entry.eventgroup_counter,
            ttl=entry.ttl,
            endpoints=frozenset(endpoints),
            options=tuple(options),
        )

    def to_ack_entry(self):
        return someip.header.SOMEIPSDEntry(
            sd_type=someip.header.SOMEIPSDEntryType.SubscribeAck,
            service_id=self.service_id,
            instance_id=self.instance_id,
            major_version=self.major_version,
            ttl=self.ttl,
            minver_or_counter=(self.counter << 16) | self.id,
        )

    def to_nack_entry(self):
        return dataclasses.replace(self, ttl=0).to_ack_entry()


class NakSubscription(Exception):  # noqa: N818
    pass


class ServerServiceListener:
    def client_subscribed(
        self, subscription: EventgroupSubscription, source: _T_SOCKADDR
    ) -> None:
        """
        should raise someip.sd.NakSubscription if subscription should be rejected
        """
        ...

    def client_unsubscribed(
        self, subscription: EventgroupSubscription, source: _T_SOCKADDR
    ) -> None:
        ...


_T_SL = typing.Tuple[someip.config.Service, ServerServiceListener]


class ServiceAnnouncer:
    # TODO doc
    def __init__(self, sd: ServiceDiscoveryProtocol):
        self.sd = sd
        self.timings = sd.timings
        self.log = sd.log.getChild("announce")

        self.task: typing.Optional[asyncio.Task[None]] = None
        self.alive = False
        self._can_answer_offers = False
        self._last_multicast_offer: float = 0

        self.announcing_services: typing.List[_T_SL] = []
        self.subscriptions: TimedStore[EventgroupSubscription] = TimedStore(self.log)

    def announce_service(
        self, service: someip.config.Service, listener: ServerServiceListener
    ) -> None:
        if self.task is not None and not self.task.done():  # pragma: nocover
            self.log.warning("adding services without going through startup phase")
        self.announcing_services.append((service, listener))

    def stop_announce_service(
        self,
        service: someip.config.Service,
        listener: ServerServiceListener,
        send_stop=True,
    ) -> None:
        """
        stops announcing previously started service

        :param service: service definition of service to be stopped
        :param listener: listener of service to be stopped
        :raises ValueError: if the service was not announcing
        """
        self.announcing_services.remove((service, listener))
        if send_stop and self.task is not None and not self.task.done():
            asyncio.get_event_loop().call_soon(
                functools.partial(self._send_offers, ((service, listener),), stop=True),
            )

    @log_exceptions()
    async def handle_subscribe(
        self,
        entry: someip.header.SOMEIPSDEntry,
        addr: _T_SOCKADDR,
    ) -> None:
        subscription = EventgroupSubscription.from_subscribe_entry(entry)
        if entry.ttl == 0:
            self.eventgroup_subscribe_stopped(addr, subscription)
            return

        matching_listeners = [
            l for s, l in self.announcing_services if s.matches_subscribe(entry) and l
        ]
        if not matching_listeners:
            self.log.warning(
                "discarding subscribe for unknown service from %s: %s",
                format_address(addr),
                entry,
            )
            self._send_subscribe_nack(subscription, addr)
            return
        if len(matching_listeners) > 1:
            self.log.warning(
                "multiple configured services match subscribe %s from %s: %s",
                entry,
                format_address(addr),
                matching_listeners,
            )

        listener = matching_listeners[0]

        try:
            self.subscriptions.refresh(
                subscription.ttl,
                addr,
                subscription,
                listener.client_subscribed,
                listener.client_unsubscribed,
            )
        except NakSubscription:
            self._send_subscribe_nack(subscription, addr)
        else:
            self.sd.send_sd([subscription.to_ack_entry()], remote=addr)

    def eventgroup_subscribe_stopped(
        self, addr: _T_SOCKADDR, subscription: EventgroupSubscription
    ) -> None:
        self.subscriptions.stop(addr, subscription)

    def _send_subscribe_nack(
        self, subscription: EventgroupSubscription, addr: _T_SOCKADDR
    ) -> None:
        self.sd.send_sd([subscription.to_nack_entry()], remote=addr)

    @log_exceptions()
    async def handle_findservice(
        self,
        entry: someip.header.SOMEIPSDEntry,
        addr: _T_SOCKADDR,
        received_over_multicast: bool,
        unicast_supported: bool,
    ) -> None:
        # XXX spec is unclear on RequestResponseDelay behavior if new Find is received
        self.log.info("received from %s: %s", format_address(addr), entry)
        if not self._can_answer_offers:
            # 4.2.1 SWS_SD_00319
            self.log.info(
                "ignoring FindService from %s during Initial Wait Phase: %s",
                format_address(addr),
                entry,
            )
            return

        local_services = [
            s for s in self.announcing_services if s[0].matches_find(entry)
        ]
        if not local_services:
            return

        # 4.2.1 TR_SOMEIP_00423
        # unfortunately the spec is unclear on whether the multicast response should
        # refresh the CYCLIC_OFFER_DELAY timer when the multicast send condition is
        # fulfilled.
        # => assume no, since that would only work if all services were sent out
        time_since_last_offer = (
            asyncio.get_event_loop().time() - self._last_multicast_offer
        )
        answer_with_multicast = (
            time_since_last_offer > self.timings.CYCLIC_OFFER_DELAY / 2
            or not unicast_supported
        )

        # 4.2.1 TR_SOMEIP_00419
        if received_over_multicast or answer_with_multicast:
            # 4.2.1 TR_SOMEIP_00420 and TR_SOMEIP_00421
            await asyncio.sleep(
                random.uniform(
                    self.timings.REQUEST_RESPONSE_DELAY_MIN,
                    self.timings.REQUEST_RESPONSE_DELAY_MAX,
                )
            )

        # FIXME spec requires in 4.2.1 SWS_SD_00651 to pack responses to multiple Finds
        # together
        if answer_with_multicast:
            self._send_offers(local_services)
        else:
            self._send_offers(local_services, remote=addr)

    def start(self, loop=None):
        if self.task is not None and not self.task.done():  # pragma: nocover
            return
        if loop is None:  # pragma: nobranch
            loop = asyncio.get_event_loop()

        self._can_answer_offers = False
        self.task = loop.create_task(self._announce())

    def stop(self):
        if self.task:  # pragma: nobranch
            self.task.cancel()
            asyncio.create_task(wait_cancelled(self.task))
            self.task = None

            if not self.timings.CYCLIC_OFFER_DELAY:
                asyncio.get_event_loop().call_soon(
                    functools.partial(
                        self._send_offers, self.announcing_services, stop=True
                    ),
                )

    def connection_lost(self, exc: typing.Optional[Exception]) -> None:
        self.stop()
        self.subscriptions.stop_all()

    @log_exceptions()
    async def _announce(self) -> None:
        try:
            ttl = self.timings.ANNOUNCE_TTL
            if ttl is not TTL_FOREVER and (
                not self.timings.CYCLIC_OFFER_DELAY
                or self.timings.CYCLIC_OFFER_DELAY >= ttl
            ):
                self.log.warning(
                    "CYCLIC_OFFER_DELAY=%r too short for TTL=%r."
                    " expect connectivity issues",
                    self.timings.CYCLIC_OFFER_DELAY,
                    ttl,
                )
            await asyncio.sleep(
                random.uniform(
                    self.timings.INITIAL_DELAY_MIN, self.timings.INITIAL_DELAY_MAX
                )
            )
            self._send_offers(self.announcing_services)

            try:
                self._can_answer_offers = True
                for i in range(self.timings.REPETITIONS_MAX):
                    await asyncio.sleep((2 ** i) * self.timings.REPETITIONS_BASE_DELAY)
                    self._send_offers(self.announcing_services)

                if not self.timings.CYCLIC_OFFER_DELAY:  # 4.2.1 SWS_SD_00451
                    return

                while True:
                    # 4.2.1 SWS_SD_00450
                    await asyncio.sleep(self.timings.CYCLIC_OFFER_DELAY)
                    self._send_offers(self.announcing_services)
            finally:
                if self.timings.CYCLIC_OFFER_DELAY:
                    self._send_offers(self.announcing_services, stop=True)
        except asyncio.CancelledError:
            pass

    def _send_offers(
        self,
        services: typing.Collection[_T_SL],
        remote: _T_OPT_SOCKADDR = None,
        stop: bool = False,
    ):
        entries = [
            s.create_offer_entry(self.timings.ANNOUNCE_TTL if not stop else 0)
            for s, _ in services
        ]

        if not remote:
            self._last_multicast_offer = asyncio.get_event_loop().time()
        self.sd.send_sd(entries, remote=remote)

    def reboot_detected(self, addr: _T_SOCKADDR) -> None:
        self.subscriptions.stop_all_for_address(addr)
