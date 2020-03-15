import asyncio
import collections
import ipaddress
import logging
import random
import socket
import struct
import threading
import typing

import netifaces

import someip.header
import someip.config
from someip.utils import log_exceptions

LOG = logging.getLogger('someip.sd')
_T_IPADDR = typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
_T_SOCKADDR = typing.Tuple
_T_OPT_SOCKADDR = typing.Optional[typing.Tuple]


def _addr_to_ifindex(addr: _T_IPADDR) -> typing.Optional[int]:
    if isinstance(addr, ipaddress.IPv4Address):
        family = netifaces.AF_INET
    elif isinstance(addr, ipaddress.IPv6Address):
        family = netifaces.AF_INET6
    else:
        raise ValueError('required IPv4Address or IPv6Address')

    for ifindex, ifname in socket.if_nameindex():
        for if_addr in netifaces.ifaddresses(ifname).get(family, []):
            if_ip = ipaddress.ip_address(if_addr['addr'].split('%', 1)[0])
            if addr == if_ip:
                return ifindex

    return None


class SOMEIPDatagramProtocol:
    '''
    is actually not a subclass of asyncio.BaseProtocol or asyncio.DatagramProtocol,
    because datagram_received() has an additional parameter `multicast: bool`

    TODO: fix misleading name
    '''

    @classmethod
    async def create_unicast_endpoint(cls, *args,
                                      local_addr: _T_OPT_SOCKADDR = None,
                                      remote_addr: _T_OPT_SOCKADDR = None,
                                      loop=None,
                                      **kwargs):
        if loop is None:
            loop = asyncio.get_event_loop()
        protocol = cls(*args, **kwargs)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: DatagramProtocolAdapter(protocol, is_multicast=False),
            local_addr=local_addr, remote_addr=remote_addr,
        )
        protocol.transport = transport
        return transport, protocol

    def __init__(self, logger: str = 'someip'):
        self.log = logging.getLogger(logger)
        self.transport: asyncio.DatagramTransport = None
        self.session_storage = _SessionStorage()

        # default_addr=None means use connected address from socket
        self.default_addr: _T_OPT_SOCKADDR = None

    def datagram_received(self, data, addr: _T_SOCKADDR, multicast: bool) -> None:
        try:
            while data:
                parsed, data = someip.header.SOMEIPHeader.parse(data)
                self.message_received(parsed, addr, multicast)
        except someip.header.ParseError as exc:
            self.log.error('failed to parse SOME/IP datagram from %s: %r',
                           self.format_address(addr), data, exc_info=exc)

    @staticmethod
    def format_address(addr: _T_SOCKADDR) -> str:
        host, port = socket.getnameinfo(addr, socket.NI_NUMERICHOST | socket.NI_NUMERICSERV)
        host = ipaddress.ip_address(host)
        if isinstance(host, ipaddress.IPv4Address):
            return f'{host!s}:{port:s}'
        elif isinstance(host, ipaddress.IPv6Address):
            return f'[{host!s}]:{port:s}'
        else:
            raise NotImplementedError(f'unknown ip address format: {addr!r} -> {host!r}')

    def error_received(self, exc: typing.Optional[Exception]):
        self.log.exception('someip event listener protocol failed', exc_info=exc)

    def connection_lost(self, exc: typing.Optional[Exception]) -> None:
        self.log.exception('someip closed', exc_info=exc)

    def message_received(self,
                         someip_message: someip.header.SOMEIPHeader,
                         addr: _T_SOCKADDR,
                         multicast: bool) -> None:
        '''
        called when a well-formed SOME/IP datagram was received
        '''
        self.log.info('received from %s\n%s', self.format_address(addr), someip_message)
        pass

    def send(self, buf: bytes, remote: _T_OPT_SOCKADDR = None):
        # ideally, we'd use transport.write() and have the DGRAM socket connected to the
        # default_addr. However, after connect() the socket will not be bound to INADDR_ANY
        # anymore. so we store the multicast address as a default destination address on the
        # isntance and wrap the send calls with self.send
        if remote:
            self.transport.sendto(buf, remote)
        else:
            self.transport.sendto(buf, self.default_addr)

    def send_sd(self, msg: someip.header.SOMEIPSDHeader, remote: _T_OPT_SOCKADDR = None) -> None:
        msg.flag_reboot, session_id = self.session_storage.assign_outgoing(remote)

        hdr = someip.header.SOMEIPHeader(
            service_id=someip.header.SD_SERVICE,
            method_id=someip.header.SD_METHOD,
            client_id=0,
            session_id=session_id,
            interface_version=1,
            message_type=someip.header.SOMEIPMessageType.NOTIFICATION,
        )

        hdr.payload = msg.build()
        self.send(hdr.build(), remote)


class DatagramProtocolAdapter(asyncio.DatagramProtocol):
    def __init__(self, protocol: SOMEIPDatagramProtocol, is_multicast: bool):
        self.is_multicast = is_multicast
        self.protocol = protocol

    def datagram_received(self, data, addr: typing.Tuple[str, int]) -> None:
        self.protocol.datagram_received(data, addr, multicast=self.is_multicast)

    def error_received(self, exc: typing.Optional[Exception]) -> None:
        self.protocol.error_received(exc)

    def connection_lost(self, exc: typing.Optional[Exception]) -> None:
        self.protocol.connection_lost(exc)


class _BaseSDProtocol(SOMEIPDatagramProtocol):
    def __init__(self, logger: str):
        super().__init__(logger=logger)

    def message_received(self,
                         someip_message: someip.header.SOMEIPHeader,
                         addr: _T_SOCKADDR, multicast: bool) -> None:
        if someip_message.service_id != someip.header.SD_SERVICE \
                or someip_message.method_id != someip.header.SD_METHOD \
                or someip_message.message_type != someip.header.SOMEIPMessageType.NOTIFICATION:
            self.log.error('SD protocol received non-SD message: %s', someip_message)
            return

        try:
            sdhdr, rest = someip.header.SOMEIPSDHeader.parse(someip_message.payload)
        except someip.header.ParseError as exc:
            self.log.error('SD-message did not parse: %r', exc)
            return

        if self.session_storage.check_received(addr, multicast, sdhdr.flag_reboot,
                                               someip_message.session_id):
            self.reboot_detected(addr)

        # FIXME this will drop the SD Endpoint options, since they are not referenced by entries
        # see 4.2.1 TR_SOMEIP_00548
        sdhdr.resolve_options()
        self.sd_message_received(sdhdr, addr, multicast)

        if rest:
            self.log.warning('unparsed data after SD from %s: %r', self.format_address(addr), rest)

    def sd_message_received(self, sdhdr: someip.header.SOMEIPSDHeader,
                            addr: _T_SOCKADDR,
                            multicast: bool) -> None:
        '''
        called when a well-formed SOME/IP SD message was received
        '''
        raise NotImplementedError

    def reboot_detected(self, addr: _T_SOCKADDR) -> None:
        '''
        called when a rebooted endpoint was detected
        '''


class _SessionStorage:

    def __init__(self):
        self.incoming = {}
        self.outgoing = collections.defaultdict(lambda: (True, 1))
        self.outgoing_lock = threading.Lock()

    def check_received(self, sender: _T_SOCKADDR, multicast: bool,
                       flag: bool, session_id: int) -> bool:
        '''
        return true if a reboot was detected
        '''
        k = (sender, multicast)

        try:
            old_flag, old_session_id = self.incoming[k]

            if flag and (not old_flag or (old_session_id > 0 and old_session_id >= session_id)):
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
        # eg. when an application logic runs in a seperate therad from the SOMEIP stack event loop
        with self.outgoing_lock:
            flag, _id = self.outgoing[remote]
            if _id >= 0xffff:
                # 4.2.1, TR_SOMEIP_00521
                # 4.2.1, TR_SOMEIP_00255
                self.outgoing[remote] = (False, 1)
            else:
                self.outgoing[remote] = (flag, _id + 1)
        return flag, _id


class SubscriptionProtocol(_BaseSDProtocol):
    '''
    datagram protocol for subscribing to eventgroups via SOME/IP SD

    example:
        TODO
    '''

    def __init__(self, ttl=5):
        super().__init__(logger='someip.subscribe')
        if ttl == 0 or ttl == 0xffff:
            raise ValueError('ttl may not be 0 or 0xffff. set to None for "forever"')
        self.ttl = ttl
        self.ttl_offset = 2

        self.task = None
        self.alive = False

        self.subscribeentries: typing.Set[typing.Tuple[
            someip.config.Eventgroup,
            _T_SOCKADDR,
        ]] = set()

    def subscribe_eventgroup(self, eventgroup: someip.config.Eventgroup, endpoint: _T_SOCKADDR) \
            -> None:
        '''
        eventgroup:
          someip.config.Eventgroup that describes the eventgroup to subscribe to and the local
          endpoint that accepts the notifications
        endpoint:
          remote SD endpoint that will receive the subscription messages
        '''
        # relies on _subscribe() to send out the Subscribe messages in the next cycle.
        self.subscribeentries.add((eventgroup, endpoint))

        if self.ttl is None and self.alive:
            # when TTL=forever, _subscribe() task does not run continuously, so we need to send
            # individual subscribe entries directly
            asyncio.get_event_loop().call_soon(self._send_start_subscribe, endpoint, [eventgroup])

    def stop_subscribe_eventgroup(self, eventgroup: someip.config.Eventgroup,
                                  endpoint: _T_SOCKADDR) -> None:
        '''
        eventgroup:
          someip.config.Eventgroup that describes the eventgroup to unsubscribe from
        endpoint:
          remote SD endpoint that will receive the subscription messages
        '''
        try:
            self.subscribeentries.remove((eventgroup, endpoint))
        except KeyError:
            return

        self._send_stop_subscribe(endpoint, [eventgroup])

    def _send_stop_subscribe(self, remote: _T_SOCKADDR,
                             entries: typing.Sequence[someip.config.Eventgroup]) -> None:
        self._send_subscribe(0, remote, entries)

    def _send_start_subscribe(self, remote: _T_SOCKADDR,
                              entries: typing.Sequence[someip.config.Eventgroup]) -> None:
        self._send_subscribe(0xffffff if self.ttl is None else self.ttl, remote, entries)

    def _send_subscribe(self, ttl: int, remote: _T_SOCKADDR,
                        entries: typing.Sequence[someip.config.Eventgroup]) -> None:
        if not self.transport:
            return

        if not entries:
            return

        sdhdr = someip.header.SOMEIPSDHeader(
            flag_reboot=True,
            flag_unicast=True,
            entries=[e.create_subscribe_entry(ttl=ttl) for e in entries],
        )
        sdhdr.assign_option_indexes()

        self.send_sd(sdhdr, remote=remote)

    def start(self, loop=None):
        if self.task is not None or self.alive:
            return
        if loop is None:
            loop = asyncio.get_event_loop()

        self.alive = True
        self.task = loop.create_task(self._subscribe())

    def stop(self, send_stop_subscribe=True):
        self.alive = False

        if self.task:
            self.task.cancel()
            self.task = None

        if self.send_stop_subscribe:
            for endpoint, entries in self._group_entries().items():
                self._send_stop_subscribe(endpoint, entries)

    def _group_entries(self):
        endpoint_entries = collections.defaultdict(set)
        for eventgroup, endpoint in self.subscribeentries:
            endpoint_entries[endpoint].add(eventgroup)
        return endpoint_entries

    def connection_lost(self, exc: typing.Optional[Exception]) -> None:
        self.log.exception('connection lost. stopping subscribe task', exc_info=exc)
        self.stop(send_stop_subscribe=False)

    @log_exceptions()
    async def _subscribe(self):
        while self.alive:
            for endpoint, entries in self._group_entries().items():
                self._send_start_subscribe(endpoint, entries)

            if self.ttl is None:
                break

            if self.ttl_offset >= self.ttl:
                raise ValueError('ttl_offset too big')

            try:
                await asyncio.sleep(self.ttl - self.ttl_offset)
            except asyncio.CancelledError:
                break

    def sd_message_received(self, sdhdr: someip.header.SOMEIPSDHeader,
                            addr: _T_SOCKADDR,
                            multicast: bool) -> None:
        '''
        called when a well-formed SOME/IP SD message was received
        '''

        faddr = self.format_address(addr)

        for entry in sdhdr.entries:
            if entry.sd_type == someip.header.SOMEIPSDEntryType.SubscribeAck:
                if entry.ttl == 0:
                    self.log.info('received Subscribe NACK from %s: %s', faddr, entry)
                else:
                    self.log.info('received Subscribe ACK from %s: %s', faddr, entry)
            else:
                self.log.warning('unexpected entry received from %s: %s', faddr, entry)


class _BaseMulticastSDProtocol(_BaseSDProtocol):
    INITIAL_DELAY_MIN = 0.05  # in seconds
    INITIAL_DELAY_MAX = 0.5   # in seconds
    REQUEST_RESPONSE_DELAY_MIN = 0.05  # in seconds
    REQUEST_RESPONSE_DELAY_MAX = 0.5   # in seconds
    REPETITIONS_MAX = 4
    REPETITIONS_BASE_DELAY = 0.03  # in seconds
    CYCLIC_OFFER_DELAY = 10  # in seconds

    def __init__(self, multicast_addr: typing.Tuple[str, int], logger: str = 'someip.sd.abstract'):
        super().__init__(logger=logger)
        self.default_addr = multicast_addr

    @classmethod
    async def create_endpoints(cls, local_addr: _T_IPADDR, multicast_addr: _T_IPADDR,
                               port: int = 30490, ttl=1, loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        if not multicast_addr.is_multicast:
            raise ValueError('multicast_addr is not multicast')

        if isinstance(local_addr, ipaddress.IPv4Address):
            family = socket.AF_INET
        elif isinstance(local_addr, ipaddress.IPv6Address):
            family = socket.AF_INET6
        else:
            raise ValueError('local_addr must be ipv4 or ipv6 address')

        # since posix does not provide a portable interface to figure out what address a datagram
        # was received on, we need one unicast and one multicast socket
        prot = cls((str(multicast_addr), port))

        trsp_u, _ = await loop.create_datagram_endpoint(
            lambda: DatagramProtocolAdapter(prot, is_multicast=False),
            local_addr=(str(local_addr), port),
            family=family,
            proto=socket.IPPROTO_UDP,
            reuse_address=True,
            reuse_port=True,
        )
        prot.transport = trsp_u

        trsp_m, _ = await loop.create_datagram_endpoint(
            lambda: DatagramProtocolAdapter(prot, is_multicast=True),
            local_addr=((str(multicast_addr), port)),
            family=family,
            proto=socket.IPPROTO_UDP,
            reuse_address=True,
            reuse_port=True,
        )

        sock = trsp_m.get_extra_info('socket')

        if not sock:
            raise RuntimeError('trsp_m has no socket')

        ifindex = _addr_to_ifindex(local_addr)

        if isinstance(multicast_addr, ipaddress.IPv4Address):
            mreq = struct.pack('=4s4si', multicast_addr.packed, local_addr.packed, ifindex)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreq)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)

        if isinstance(multicast_addr, ipaddress.IPv6Address):
            mreq = struct.pack("=16sl", multicast_addr.packed, ifindex)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
            sock.setsockopt(socket.IPPROTO_IPV6,
                            socket.IPV6_MULTICAST_IF, struct.pack('=i', ifindex))
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)

        return trsp_u, trsp_m, prot


class ServiceListener:
    def service_offered(self, service: someip.config.Service) -> None: ...
    def service_stopped(self, service: someip.config.Service) -> None: ...


class ServiceDiscoveryProtocol(_BaseMulticastSDProtocol):
    '''
    datagram protocol for subscribing to eventgroups via SOME/IP SD

    example:
        TODO
    '''

    def __init__(self, multicast_addr: typing.Tuple[str, int], logger: str = 'someip.sd.discover'):
        super().__init__(logger=logger, multicast_addr=multicast_addr)
        self.watched_services: typing.Dict[
                someip.config.Service,
                typing.Set[ServiceListener],
        ] = collections.defaultdict(set)
        self.watcher_all_services: typing.Set[ServiceListener] = set()

        self.found_services: typing.Dict[
            _T_SOCKADDR,
            typing.Dict[someip.config.Service, typing.Optional[asyncio.Handle]],
        ] = collections.defaultdict(dict)

    def sd_message_received(self, sdhdr: someip.header.SOMEIPSDHeader,
                            addr: _T_SOCKADDR,
                            multicast: bool) -> None:
        '''
        called when a well-formed SOME/IP SD message was received
        '''
        LOG.debug('sd_message_received received from %s (multicast=%r): %s',
                  self.format_address(addr), multicast, sdhdr)

        for entry in sdhdr.entries:
            if entry.sd_type != someip.header.SOMEIPSDEntryType.OfferService:
                continue
            asyncio.get_event_loop().call_soon(self._handle_offer, addr, entry)

    def _handle_offer(self, addr: _T_SOCKADDR, entry: someip.header.SOMEIPSDEntry) -> None:
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

    def watch_service(self, service: someip.config.Service, listener: ServiceListener) -> None:
        self.watched_services[service].add(listener)

    def watch_all_services(self, listener: ServiceListener) -> None:
        self.watcher_all_services.add(listener)

    def _service_found(self, service: someip.config.Service) -> bool:
        for d in self.found_services.values():
            for s in d.keys():
                if service.matches_service(s):
                    return True
        return False

    async def send_find_services(self):
        if not self.watched_services:
            return

        await asyncio.sleep(random.uniform(self.INITIAL_DELAY_MIN, self.INITIAL_DELAY_MAX))

        for i in range(self.REPETITIONS_MAX):
            find_entries = [service.create_find_entry() for service in self.watched_services.keys()
                            if not self._service_found(service)]

            sdhdr = someip.header.SOMEIPSDHeader(
                flag_reboot=True,
                flag_unicast=True,
                entries=find_entries,
            )
            sdhdr.assign_option_indexes()
            self.send_sd(sdhdr)

            await asyncio.sleep((2**i) * self.REPETITIONS_BASE_DELAY)

    def service_offered(self, addr: _T_SOCKADDR, entry: someip.header.SOMEIPSDEntry):
        service = someip.config.Service.from_offer_entry(entry)

        timeout_handle: typing.Optional[asyncio.TimerHandle] = None
        if entry.ttl != 0xffff:
            timeout_handle = asyncio.get_event_loop().call_later(
                entry.ttl,
                self._service_timeout,
                addr,
                service,
            )

        try:
            old_timeout_handle = self.found_services[addr].pop(service)
            if old_timeout_handle:
                old_timeout_handle.cancel()
        except KeyError:
            # new service
            self._notify_service_offered(service)

        self.found_services[addr][service] = timeout_handle

    def connection_lost(self, exc: typing.Optional[Exception]) -> None:
        self.log.exception('connection lost. stopping service_timeout tasks', exc_info=exc)

        for services in self.found_services.values():
            for service, handle in services.items():
                asyncio.get_event_loop().call_soon(self._notify_service_stopped, service)
                if handle:
                    handle.cancel()
        self.found_services.clear()

    @log_exceptions('exception in _service_timeout for {0!r}')
    def _service_timeout(self, addr: _T_SOCKADDR, service: someip.config.Service) -> None:
        try:
            self.found_services[addr].pop(service)
        except KeyError:
            # race-condition: service was already stopped. don't notify again
            return

        self._notify_service_stopped(service)

    def service_offer_stopped(self, addr: _T_SOCKADDR, entry: someip.header.SOMEIPSDEntry) -> None:
        service = someip.config.Service.from_offer_entry(entry)

        try:
            _timeout_handle = self.found_services[addr].pop(service, None)
        except KeyError:
            # race-condition: service was already stopped. don't notify again
            return

        if _timeout_handle:
            _timeout_handle.cancel()
        self._notify_service_stopped(service)

    def reboot_detected(self, addr: _T_SOCKADDR) -> None:
        # notify stop for each service of rebooted instance.
        # reboot_detected() is called before sd_message_received(), so any offered service in this
        # message will cause a new notify
        for service, handle in self.found_services[addr].items():
            if handle:
                handle.cancel()
            self._notify_service_stopped(service)
        self.found_services[addr].clear()

    def _notify_service_offered(self, service: someip.config.Service) -> None:
        for service_filter, listeners in self.watched_services.items():
            if service_filter.matches_service(service):
                for listener in listeners:
                    listener.service_offered(service)
        for listener in self.watcher_all_services:
            listener.service_offered(service)

    def _notify_service_stopped(self, service: someip.config.Service) -> None:
        for service_filter, listeners in self.watched_services.items():
            if service_filter.matches_service(service):
                for listener in listeners:
                    listener.service_stopped(service)
        for listener in self.watcher_all_services:
            listener.service_stopped(service)


class ServiceAnnounceProtocol(_BaseMulticastSDProtocol):
    # TODO doc
    TTL = 3

    def __init__(self, multicast_addr: typing.Tuple[str, int], logger: str = 'someip.sd.announce'):
        super().__init__(logger=logger, multicast_addr=multicast_addr)

        self.task = None
        self.alive = False
        self._can_answer_offers = False
        self._last_multicast_offer: float = 0

        self.announcing_services: typing.Set[someip.config.Service] = set()

    def announce_service(self, service: someip.config.Service) -> None:
        self.announcing_services.add(service)

    def sd_message_received(self, sdhdr: someip.header.SOMEIPSDHeader,
                            addr: _T_SOCKADDR, multicast: bool) -> None:
        '''
        called when a well-formed SOME/IP SD message was received
        '''

        for entry in sdhdr.entries:
            if entry.sd_type == someip.header.SOMEIPSDEntryType.OfferService:
                # is handled by ServiceDiscoveryProtocol
                continue
            elif entry.sd_type == someip.header.SOMEIPSDEntryType.FindService:
                self.log.info('received from %s: %s', self.format_address(addr), entry)
                # XXX spec is unclear on RequestResponseDelay behavior if new Find is received
                asyncio.create_task(
                    self._handle_findservice(entry, addr, multicast, sdhdr.flag_unicast),
                )
            elif entry.sd_type == someip.header.SOMEIPSDEntryType.Subscribe:
                if multicast:
                    self.log.warning('discarding subscribe received over multicast from %s: %s',
                                     self.format_address(addr), entry)
                    continue
                self.log.info('received from %s: %s', self.format_address(addr), entry)
                # TODO handle Subscribe Eventgroup
            else:
                self.log.info('received unexpected from %s: %s', self.format_address(addr), entry)

    @log_exceptions()
    async def _handle_findservice(self, entry: someip.header.SOMEIPSDEntry,
                                  addr: _T_SOCKADDR,
                                  received_over_multicast: bool,
                                  unicast_supported: bool) -> None:
        if not self._can_answer_offers:
            # 4.2.1 SWS_SD_00319
            LOG.info('ignoring FindService from %s during Initial Wait Phase: %s',
                     self.format_address(addr), entry)
            return

        local_services = [s for s in self.announcing_services if s.matches_find(entry)]
        if not local_services:
            return

        # 4.2.1 TR_SOMEIP_00423
        # unfortunately the spec is unclear on whether the multicast response should
        # refresh the CYCLIC_OFFER_DELAY timer when the multicast send condition is fulfilled.
        # => assume no, since that would only work if all services were sent out
        time_since_last_offer = asyncio.get_event_loop().time() - self._last_multicast_offer
        answer_with_multicast = time_since_last_offer > self.CYCLIC_OFFER_DELAY/2 \
            or not unicast_supported

        # 4.2.1 TR_SOMEIP_00419
        if received_over_multicast or answer_with_multicast:
            # 4.2.1 TR_SOMEIP_00420 and TR_SOMEIP_00421
            await asyncio.sleep(random.uniform(self.REQUEST_RESPONSE_DELAY_MIN,
                                               self.REQUEST_RESPONSE_DELAY_MAX))

        # FIXME spec requires in 4.2.1 SWS_SD_00651 to pack responses to multiple Finds together
        if answer_with_multicast:
            self._send_offers(local_services)
        else:
            self._send_offers(local_services, remote=addr)

    def start(self, loop=None):
        if self.task is not None or self.alive:
            return
        if loop is None:
            loop = asyncio.get_event_loop()

        self.alive = True
        self._can_answer_offers = False
        self.task = loop.create_task(self._announce())

    def stop(self):
        self.alive = False

        if self.task:
            self.task.cancel()
            self.task = None

    def connection_lost(self, exc: typing.Optional[Exception]) -> None:
        self.log.exception('connection lost. stopping announce task', exc_info=exc)
        self.stop()

    @log_exceptions()
    async def _announce(self):
        try:
            await asyncio.sleep(random.uniform(self.INITIAL_DELAY_MIN, self.INITIAL_DELAY_MAX))
            self._send_offers(self.announcing_services)

            self._can_answer_offers = True
            for i in range(self.REPETITIONS_MAX):
                await asyncio.sleep((2**i) * self.REPETITIONS_BASE_DELAY)
                if not self.alive:
                    return
                self._send_offers(self.announcing_services)

            if not self.CYCLIC_OFFER_DELAY:  # SWS_SD_00451
                return

            while self.alive:
                await asyncio.sleep(self.CYCLIC_OFFER_DELAY)
                self._send_offers(self.announcing_services)
        except asyncio.CancelledError:
            pass
        finally:
            self._send_offers(self.announcing_services, stop=True)

    def _send_offers(self, services: typing.Sequence[someip.config.Service],
                     remote: _T_OPT_SOCKADDR = None,
                     stop: bool = False):
        entries = [s.create_offer_entry(self.TTL if not stop else 0) for s in services]

        sdhdr = someip.header.SOMEIPSDHeader(
            flag_reboot=True,
            flag_unicast=True,
            entries=entries,
        )
        sdhdr.assign_option_indexes()
        if not remote:
            self._last_multicast_offer = asyncio.get_event_loop().time()
        self.send_sd(sdhdr, remote=remote)

    def reboot_detected(self, addr: _T_SOCKADDR) -> None:
        # TODO remove Eventgroup subscriptions for endpoint
        pass
