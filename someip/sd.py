import asyncio
import ipaddress
import logging
import random
import socket
import struct
import typing

import netifaces

import someip.header
import someip.config

LOG = logging.getLogger('someip.sd')
_T_IPADDR = typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
_T_OPT_ADDR = typing.Optional[typing.Tuple[_T_IPADDR, int]]


def _sockaddr_to_endpoint(sockaddr: typing.Tuple, protocol=someip.header.L4Protocols) \
        -> someip.header.SOMEIPSDOption:
    host, port = socket.getnameinfo(sockaddr, socket.NI_NUMERICHOST | socket.NI_NUMERICSERV)
    nport = int(port)
    addr = ipaddress.ip_address(host)

    if isinstance(addr, ipaddress.IPv4Address):
        return someip.header.IPv4EndpointOption(address=addr, l4proto=protocol, port=nport)
    elif isinstance(addr, ipaddress.IPv6Address):
        return someip.header.IPv6EndpointOption(address=addr, l4proto=protocol, port=nport)
    else:
        raise TypeError('unsupported IP address family')


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

    def __init__(self, logger: str = 'someip'):
        self.log = logging.getLogger(logger)
        self.transport: asyncio.DatagramTransport = None

    def datagram_received(self, data, addr: typing.Tuple[str, int], multicast: bool) -> None:
        try:
            while data:
                parsed, data = someip.header.SOMEIPHeader.parse(data)
                self.message_received(parsed, addr, multicast)
        except someip.header.ParseError as exc:
            self.log.error('failed to parse SOME/IP datagram from %s:%d: %r',
                           addr[0], addr[1], data, exc_info=exc)

    def error_received(self, exc: BaseException):
        self.log.exception('someip event listener protocol failed', exc_info=exc)

    def message_received(self,
                         someip_message: someip.header.SOMEIPHeader,
                         addr: typing.Tuple[str, int],
                         multicast: bool) -> None:
        '''
        called when a well-formed SOME/IP datagram was received
        '''
        self.log.info('received from %s:%d\n%s', addr[0], addr[1], someip_message)
        pass


class DatagramProtocolAdapter(asyncio.DatagramProtocol):
    def __init__(self, protocol: SOMEIPDatagramProtocol, is_multicast: bool):
        self.is_multicast = is_multicast
        self.protocol = protocol

    def datagram_received(self, data, addr: typing.Tuple[str, int]) -> None:
        self.protocol.datagram_received(data, addr, multicast=self.is_multicast)

    def error_received(self, exc: BaseException) -> None:
        self.protocol.error_received(exc)


class _BaseSDProtocol(SOMEIPDatagramProtocol):
    def __init__(self, logger: str):
        super().__init__(logger=logger)

    def message_received(self,
                         someip_message: someip.header.SOMEIPHeader,
                         addr: typing.Tuple[str, int],
                         multicast: bool) -> None:

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

        # FIXME this will drop the SD Endpoint options, since they are not referenced by entries
        # see 4.2.1 TR_SOMEIP_00548
        sdhdr.resolve_options()
        self.sd_message_received(sdhdr, addr, multicast)

        if rest:
            self.log.warning('unparsed data after SD from %s:%d: %r', addr[0], addr[1], rest)

    def sd_message_received(self, sdhdr: someip.header.SOMEIPSDHeader,
                            addr: typing.Tuple[str, int],
                            multicast: bool) -> None:
        '''
        called when a well-formed SOME/IP SD message was received
        '''
        raise NotImplementedError


class SubscriptionProtocol(_BaseSDProtocol):
    '''
    datagram protocol for subscribing to eventgroups via SOME/IP SD

    example:
        transport, protocol = await SubscriptionProtocol.create_endpoint(local_addr=local_addr,
                                                                         remote_addr=remote_addr)

        protocol.subscribe_eventgroup(Eventgroup(service, instance, major_version, eventgroup_id))
        protocol.start(local_endpoint.getsockname())
    '''

    @classmethod
    async def create_endpoint(cls, local_addr: _T_IPADDR, remote_addr: _T_IPADDR,
                              port: int = 30490, local_port: int = 30490, service_ttl=3,
                              loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        protocol = cls(service_ttl)
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: DatagramProtocolAdapter(protocol, is_multicast=False),
            local_addr=(str(local_addr), local_port),
            remote_addr=(str(remote_addr), port),
        )
        protocol.transport = transport
        return transport, protocol

    def __init__(self, ttl=5):
        super().__init__(logger='someip.subscribe')
        if ttl == 0 or ttl == 0xffff:
            raise ValueError('ttl may not be 0 or 0xffff. set to None for "forever"')
        self.ttl = ttl
        self.ttl_offset = 2

        self.task = None
        self.alive = False

        self.endpoint_addr = None

        self.subscribeentries: typing.Set[someip.config.Eventgroup] = set()

    def subscribe_eventgroup(self, eventgroup: someip.config.Eventgroup):
        self.subscribeentries.add(eventgroup)

    def stop_subscribe_eventgroup(self, eventgroup: someip.config.Eventgroup):
        try:
            self.subscribeentries.remove(eventgroup)
        except KeyError:
            return

        self._send_stop_subscribe([eventgroup])

    def _send_stop_subscribe(self, entries: typing.Sequence[someip.config.Eventgroup]) -> None:
        if not self.transport:
            return

        sdhdr = someip.header.SOMEIPSDHeader(
            flag_reboot=True,
            flag_unicast=True,
            entries=[someip.header.SOMEIPSDEntry(
                sd_type=someip.header.SOMEIPSDEntryType.Subscribe,
                options_1=[],
                options_2=[],
                service_id=e.service_id,
                instance_id=e.instance_id,
                major_version=e.major_version,
                ttl=0,
                minver_or_counter=e.eventgroup_id,
            ) for e in entries],
        )
        sdhdr.assign_option_indexes()

        hdr = someip.header.SOMEIPHeader(
            service_id=someip.header.SD_SERVICE,
            method_id=someip.header.SD_METHOD,
            client_id=0,
            session_id=0,
            interface_version=1,
            message_type=someip.header.SOMEIPMessageType.NOTIFICATION,
        )

        hdr.payload = sdhdr.build()
        self.transport.sendto(hdr.build())

    def start(self, endpoint_addr: typing.Tuple, loop=None):
        if self.task is not None or self.alive:
            return
        if loop is None:
            loop = asyncio.get_event_loop()

        self.endpoint_addr = endpoint_addr

        self.alive = True
        self.task = loop.create_task(self._subscribe())

    async def stop(self, send_stop_subscribe=True):
        self.endpoint_addr = None
        self.alive = False

        if self.task:
            self.task.cancel()
            await self.task
            self.task = None

        if self.send_stop_subscribe:
            self._send_stop_subscribe(self.subscribeentries)

    async def _subscribe(self):
        try:
            endpoint_option = _sockaddr_to_endpoint(self.endpoint_addr,
                                                    someip.header.L4Protocols.UDP)

            sdhdr = someip.header.SOMEIPSDHeader(
                flag_reboot=True,
                flag_unicast=True,
                entries=[someip.header.SOMEIPSDEntry(
                        sd_type=someip.header.SOMEIPSDEntryType.Subscribe,
                        options_1=[endpoint_option],
                        options_2=[],
                        service_id=e.service_id,
                        instance_id=e.instance_id,
                        major_version=e.major_version,
                        ttl=0xffffff if self.ttl is None else self.ttl,
                        minver_or_counter=e.eventgroup_id,
                    ) for e in self.subscribeentries],
            )
            sdhdr.assign_option_indexes()

            hdr = someip.header.SOMEIPHeader(
                service_id=someip.header.SD_SERVICE,
                method_id=someip.header.SD_METHOD,
                client_id=0,
                session_id=0,
                interface_version=1,
                message_type=someip.header.SOMEIPMessageType.NOTIFICATION,
            )

            while self.alive:
                hdr.payload = sdhdr.build()
                self.transport.sendto(hdr.build())

                if self.ttl is None:
                    break

                if self.ttl_offset >= self.ttl:
                    raise ValueError('ttl_offset too big')

                try:
                    await asyncio.sleep(self.ttl - self.ttl_offset)
                except asyncio.CancelledError:
                    break

                hdr.session_id += 1
                if hdr.session_id >= 0x10000:
                    # Specification of Service Discovery, Autosar 4.3.1, SWS_SD_00036
                    hdr.session_id = 1

                    # Specification of Service Discovery, Autosar 4.3.1, SWS_SD_00151
                    sdhdr.flag_reboot = False
        except Exception:
            self.log.exception('exception in _subscribe')
            raise

    def sd_message_received(self, sdhdr: someip.header.SOMEIPSDHeader,
                            addr: typing.Tuple[str, int],
                            multicast: bool) -> None:
        '''
        called when a well-formed SOME/IP SD message was received
        '''

        for entry in sdhdr.entries:
            if entry.sd_type == someip.header.SOMEIPSDEntryType.SubscribeAck:
                if entry.ttl == 0:
                    self.log.info('received Subscribe NACK from %s:%d: %s', addr[0], addr[1], entry)
                else:
                    self.log.info('received Subscribe ACK from %s:%d: %s', addr[0], addr[1], entry)
            else:
                self.log.warning('unexpected entry received from %s:%d: %s',
                                 addr[0], addr[1], entry)


class _BaseMulticastSDProtocol(_BaseSDProtocol):
    INITIAL_DELAY_MIN = 0.05  # in seconds
    INITIAL_DELAY_MAX = 0.5   # in seconds
    REQUEST_RESPONSE_DELAY_MIN = 0.05  # in seconds
    REQUEST_RESPONSE_DELAY_MAX = 0.5   # in seconds
    REPETITIONS_MAX = 4
    REPETITIONS_BASE_DELAY = 0.03  # in seconds
    CYCLIC_OFFER_DELAY = 1  # in seconds

    def __init__(self, multicast_addr: typing.Tuple[str, int], logger: str = 'someip.sd.abstract'):
        super().__init__(logger=logger)
        self.multicast_addr = multicast_addr

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

    def _write(self, buf: bytes, remote: _T_OPT_ADDR = None):
        # ideally, we'd use transport.write() and have the DGRAM socket connected to the
        # multicast_addr. However, after connect() the socket will not be bound to INADDR_ANY
        # anymore. so we store the multicast address as a default destination address on the
        # isntance and wrap the send calls with _write
        if remote:
            self.transport.sendto(buf, (str(remote[0]), remote[1]))
        else:
            self.transport.sendto(buf, self.multicast_addr)


class ServiceDiscoveryProtocol(_BaseMulticastSDProtocol):
    '''
    datagram protocol for subscribing to eventgroups via SOME/IP SD

    example:
        transport, protocol = await ServiceDiscoveryProtocol.create_endpoint(
            local_addr=local_addr,
            multicast_addr=multicast_addr,
            port=port,
        )

        try:
            ...
        finally:
            transport.close()

    '''

    def __init__(self, multicast_addr: typing.Tuple[str, int], logger: str = 'someip.sd.discover'):
        super().__init__(logger=logger, multicast_addr=multicast_addr)
        self.watched_services: typing.Set[someip.config.Service] = set()
        self.found_services: typing.Dict[someip.config.Service, typing.Optional[asyncio.Task]] = {}

    def sd_message_received(self, sdhdr: someip.header.SOMEIPSDHeader,
                            addr: typing.Tuple[str, int],
                            multicast: bool) -> None:
        '''
        called when a well-formed SOME/IP SD message was received
        '''


        for entry in sdhdr.entries:
            if entry.sd_type != someip.header.SOMEIPSDEntryType.OfferService:
                continue
            asyncio.get_event_loop().call_soon(self._handle_offer, addr, entry)

    def _handle_offer(self, addr: typing.Tuple[str, int],
                      entry: someip.header.SOMEIPSDEntry) -> None:
        if not self.is_watching_service(entry):
            return
        if entry.ttl == 0:
            self.service_offer_stopped(addr, entry)
        else:
            self.service_offered(addr, entry)

    def is_watching_service(self, entry: someip.header.SOMEIPSDEntry):
        if not self.watched_services:
            return True
        return any(s.matches_offer(entry) for s in self.watched_services)

    def watch_service(self, service: someip.config.Service) -> None:
        self.watched_services.add(service)

    async def send_find_services(self):
        if not self.watched_services:
            return

        await asyncio.sleep(random.uniform(self.INITIAL_DELAY_MIN, self.INITIAL_DELAY_MAX))

        for i in range(self.REPETITIONS_MAX):
            find_entries = [service.create_find_entry() for service in self.watched_services
                            if not any(service.matches_service(s)
                                       for s in self.found_services.keys())]

            sdhdr = someip.header.SOMEIPSDHeader(
                flag_reboot=True,
                flag_unicast=True,
                entries=find_entries,
            )
            sdhdr.assign_option_indexes()

            hdr = someip.header.SOMEIPHeader(
                service_id=someip.header.SD_SERVICE,
                method_id=someip.header.SD_METHOD,
                client_id=0,
                session_id=0,
                interface_version=1,
                message_type=someip.header.SOMEIPMessageType.NOTIFICATION,
            )

            hdr.payload = sdhdr.build()
            self._write(hdr.build())

            await asyncio.sleep((2**i) * self.REPETITIONS_BASE_DELAY)

    def service_offered(self, addr: typing.Tuple[str, int], entry: someip.header.SOMEIPSDEntry):
        service = someip.config.Service.from_offer_entry(entry)

        timeout_task: typing.Optional[asyncio.Task] = None
        if entry.ttl != 0xffff:
            timeout_task = asyncio.create_task(self._service_timeout(service, entry.ttl))

        try:
            old_timeout_task = self.found_services.pop(service)
            if old_timeout_task:
                old_timeout_task.cancel()
        except KeyError:
            # new service
            self._notify_service_offered(service)

        self.found_services[service] = timeout_task

    async def _service_timeout(self, service, ttl) -> None:
        try:
            await asyncio.sleep(ttl)

            try:
                self.found_services.pop(service)
            except KeyError:
                # race-condition: service was already stopped. don't notify again
                return

            self._notify_service_stopped(service)
        except asyncio.CancelledError:
            pass
        except Exception:
            self.log.exception('exception in _service_timeout for %r', service)
            raise

    def service_offer_stopped(self, addr: typing.Tuple[str, int],
                              entry: someip.header.SOMEIPSDEntry) -> None:
        service = someip.config.Service.from_offer_entry(entry)

        try:
            _timeout_task = self.found_services.pop(service, None)
        except KeyError:
            # race-condition: service was already stopped. don't notify again
            return

        if _timeout_task:
            _timeout_task.cancel()
        self._notify_service_stopped(service)

    def _notify_service_offered(self, service: someip.config.Service) -> None:
        self.log.info('offer: %s', service)
        # TODO callback for stopped services
        pass

    def _notify_service_stopped(self, service: someip.config.Service) -> None:
        self.log.info('offer STOPPED: %s', service)
        # TODO callback for stopped services
        pass


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
                            addr: typing.Tuple[str, int],
                            multicast: bool) -> None:
        '''
        called when a well-formed SOME/IP SD message was received
        '''

        for entry in sdhdr.entries:
            if entry.sd_type == someip.header.SOMEIPSDEntryType.OfferService:
                # is handled by ServiceDiscoveryProtocol
                continue
            elif entry.sd_type == someip.header.SOMEIPSDEntryType.FindService:
                self.log.info('received from %s:%d: %s', addr[0], addr[1], entry)
                asyncio.create_task(
                    self._handle_findservice(entry, addr, multicast, sdhdr.flag_unicast)
                )
            elif entry.sd_type == someip.header.SOMEIPSDEntryType.Subscribe:
                self.log.info('received from %s:%d: %s', addr[0], addr[1], entry)
                # TODO handle Subscribe Eventgroup
            else:
                self.log.info('received unexpected from %s:%d: %s', addr[0], addr[1], entry)

    async def _handle_findservice(self, entry: someip.header.SOMEIPSDEntry,
                                  addr: typing.Tuple[str, int],
                                  received_over_multicast: bool,
                                  unicast_supported: bool) -> None:
        try:
            if not self._can_answer_offers:
                # 4.2.1 SWS_SD_00319
                LOG.info('ignoring FindService from %s:%d during Initial Wait Phase: %s',
                         addr[0], addr[1], entry)
                return

            parsed_addr = (ipaddress.ip_address(addr[0]), addr[1])
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

            if answer_with_multicast:
                self._send_offers(local_services)
            else:
                self._send_offers(local_services, remote=parsed_addr)
        except Exception:
            self.log.exception('exception in _handle_findservice')
            raise

    def start(self, loop=None):
        if self.task is not None or self.alive:
            return
        if loop is None:
            loop = asyncio.get_event_loop()

        self.alive = True
        self._can_answer_offers = False
        self.task = loop.create_task(self._announce())

    async def stop(self):
        self.alive = False

        if self.task:
            self.task.cancel()
            await self.task
            self.task = None

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
        except Exception:
            self.log.exception('exception in _announce')
            raise
        except asyncio.CancelledError:
            pass
        finally:
            self._send_offers(self.announcing_services, stop=True)

    def _send_offers(self, services: typing.Sequence[someip.config.Service],
                     remote: _T_OPT_ADDR = None,
                     stop: bool = False):
        entries = [s.create_offer_entry(self.TTL if not stop else 0) for s in services]

        sdhdr = someip.header.SOMEIPSDHeader(
            flag_reboot=True,
            flag_unicast=True,
            entries=entries,
        )
        sdhdr.assign_option_indexes()

        hdr = someip.header.SOMEIPHeader(
            service_id=someip.header.SD_SERVICE,
            method_id=someip.header.SD_METHOD,
            client_id=0,
            session_id=0,
            interface_version=1,
            message_type=someip.header.SOMEIPMessageType.NOTIFICATION,
        )

        hdr.payload = sdhdr.build()
        buf = hdr.build()
        if not remote:
            self._last_multicast_offer = asyncio.get_event_loop().time()
        self._write(buf, remote=remote)
