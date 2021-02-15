"""
Simple service implementation. Probably lacking a few things, such as multicast
eventgroups and more than basic option handling.

See ``tools/simpleservice.py`` for a basic usage example.
"""
from __future__ import annotations

import asyncio
import collections
import dataclasses
import functools
import warnings
import typing

from someip import header, config, sd, utils


_T_METHOD_HANDLER = typing.Callable[
    [header.SOMEIPHeader, header._T_SOCKNAME], typing.Optional[bytes]
]


class MalformedMessageError(Exception):
    pass


# TODO implement multicast events


class SimpleEventgroup:
    """
    set :attr:`values` to the current value, call :meth:`notify_once` to immediately
    notify subscribers about new value.

    New subscribers will be notified about the current :attr:`values`.
    """

    def __init__(
        self, service: SimpleService, id: int, interval: typing.Optional[float] = None
    ):
        """
        :param service: the service this group belongs to
        :param id: the event group ID that this group can be subscribed on
        """
        self.id = id
        self.service = service
        self.log = service.log.getChild(f"evgrp-{id:04x}")

        self.subscribed_endpoints: typing.Set[header.EndpointOption[typing.Any]] = set()

        self.notification_task: typing.Optional[asyncio.Task[None]] = None
        if interval:
            self.notification_task = asyncio.create_task(self.cyclic_notify(interval))

        self.has_clients = asyncio.Event()

        self.values: typing.Dict[int, bytes] = {}
        """
        the current value for each event to send out as notification payload.
        """

    @utils.log_exceptions()
    async def _notify_single(
        self, endpoint: header.EndpointOption[typing.Any], events: typing.Iterable[int]
    ) -> None:
        addr = await endpoint.addrinfo()

        msgbuf = bytearray()
        for event_id in events:
            payload = self.values[event_id]

            self.log.info("notifying 0x%04x to %r: %r", event_id, addr, payload)

            _, session_id = self.service.session_storage.assign_outgoing(addr)
            hdr = header.SOMEIPHeader(
                service_id=self.service.service_id,
                method_id=0x8000 | event_id,
                client_id=0,
                session_id=session_id,
                message_type=header.SOMEIPMessageType.NOTIFICATION,
                interface_version=self.service.version_major,
                payload=payload,
            )

            msgbuf += hdr.build()

        if msgbuf:
            self.service.send(msgbuf, addr)

    @utils.log_exceptions()
    async def _notify_all(self, events: typing.Iterable[int]):
        await asyncio.gather(
            *[
                self._notify_single(ep, events=events)
                for ep in self.subscribed_endpoints
            ]
        )

    def notify_once(self, events: typing.Iterable[int]):
        """
        Send a notification for all given event ids to all subscribers using the
        current event values set in :attr:`values`.
        """
        if not self.has_clients.is_set():
            return
        asyncio.create_task(self._notify_all(events=events))

    @utils.log_exceptions()
    async def cyclic_notify(self, interval: float) -> None:
        """
        Schedule notifications for all events to all subscribers with a given interval.
        This coroutine is scheduled as a task by :meth:`__init__` if given a
        non-zero interval.

        :param interval: how much time to wait before sending the next notification
        """
        while True:
            await self.has_clients.wait()

            # client subscription already sent first notification.
            # wait for one interval *before* sending next
            await asyncio.sleep(interval)

            await self._notify_all(events=self.values.keys())

    def subscribe(self, endpoint: header.EndpointOption[typing.Any]) -> None:
        """
        Called by :class:`SimpleService` when a new subscription for this eventgroup
        was received.

        Triggers a notification of the current value to be sent to the subscriber.
        """
        self.subscribed_endpoints.add(endpoint)
        self.has_clients.set()
        # send initial eventgroup notification
        asyncio.create_task(self._notify_single(endpoint, events=self.values.keys()))

    def unsubscribe(self, endpoint: header.EndpointOption[typing.Any]) -> None:
        """
        Called by :class:`SimpleService` when a subscription for this eventgroup
        runs out.
        """
        self.subscribed_endpoints.remove(endpoint)
        if not self.subscribed_endpoints:
            self.has_clients.clear()


class SimpleService(sd.SOMEIPDatagramProtocol, sd.ServerServiceListener):
    service_id: typing.ClassVar[int]
    version_major: typing.ClassVar[int]
    version_minor: typing.ClassVar[int]

    def __init__(self, instance_id: int):
        """
        override, call super().__init__() followed by :meth:`register_method`
        and :meth:`register_cyclic_eventgroup`
        """
        super().__init__()
        self.clients: typing.DefaultDict[
            int, typing.Set[sd.EventgroupSubscription]
        ] = collections.defaultdict(set)
        self.eventgroups: typing.Dict[int, SimpleEventgroup] = {}
        self.methods: typing.Dict[int, _T_METHOD_HANDLER] = {}
        self.instance_id: int = instance_id
        self.log = self.log.getChild(f"service-{self.service_id:04x}-{instance_id:04x}")

    def register_method(self, id: int, handler: _T_METHOD_HANDLER) -> None:
        """
        register a SOME/IP method with the given id on this service. Incoming
        requests matching the given id will be dispatched to the handler.

        Callbacks can raise :exc:`MalformedMessageError` to generate an error
        response with return code
        :data:`someip.header.SOMEIPReturnCode.E_MALFORMED_MESSAGE`

        :param id: the method ID
        :param handler: the callback to handle the request
        """
        if id in self.methods:
            raise KeyError(f"method with id {id:#x} already registered on {self}")
        self.methods[id] = handler

    def register_eventgroup(self, eventgroup: SimpleEventgroup) -> None:
        """
        register an eventgroup on this service. Incoming subscriptions will be
        handled and passed to the given eventgroup.

        :param eventgroup:
        """
        if eventgroup.id in self.eventgroups:
            raise KeyError(
                f"eventgroup with id {eventgroup.id:#x} already registered on {self}"
            )
        self.eventgroups[eventgroup.id] = eventgroup

    @functools.cached_property
    def _endpoint(self) -> header.SOMEIPSDOption:
        sockname = self.transport.get_extra_info("sockname")
        return config.Eventgroup._sockaddr_to_endpoint(sockname, header.L4Protocols.UDP)

    def as_config(self):
        return config.Service(
            self.service_id,
            self.instance_id,
            self.version_major,
            self.version_minor,
            options_1=(self._endpoint,),
            eventgroups=frozenset(self.eventgroups.keys()),
        )

    @classmethod
    async def start_datagram_endpoint(
        cls,
        instance_id: int,
        announcer: sd.ServiceAnnouncer,
        local_addr: sd._T_OPT_SOCKADDR = None,
    ):  # pragma: nocover
        """
        create a unicast datagram endpoint for this service and register it with
        the service discovery announcer.

        :param instance_id: the service instance ID for this service
        :param announcer: the SD protocol instance that will announce this service
        :param local_addr: a local address to bind to (default: any)
        """
        _, prot = await cls.create_unicast_endpoint(instance_id, local_addr=local_addr)

        prot.start_announce(announcer)

        return prot

    def start_announce(self, announcer: sd.ServiceAnnouncer):
        announcer.announce_service(self.as_config(), self)

    def stop_announce(self, announcer: sd.ServiceAnnouncer):
        announcer.stop_announce_service(self.as_config(), self)

    def stop(self):  # pragma: nocover
        self.transport.close()

    def message_received(
        self,
        someip_message: header.SOMEIPHeader,
        addr: header._T_SOCKNAME,
        multicast: bool,
    ) -> None:
        if multicast:
            warnings.warn(
                "Service packet received over multicast - this does not make sense."
                " You probably created the wrong type of socket for this service.",
                stacklevel=2,
            )
            return
        if someip_message.service_id != self.service_id:
            self.log.warning("received message for unknown service: %r", someip_message)
            self.send_error_response(
                someip_message, addr, header.SOMEIPReturnCode.E_UNKNOWN_SERVICE
            )
            return
        if someip_message.interface_version != self.version_major:
            self.log.warning(
                "received message for incompatible service version: %r", someip_message
            )
            self.send_error_response(
                someip_message, addr, header.SOMEIPReturnCode.E_WRONG_INTERFACE_VERSION
            )
            return

        method = self.methods.get(someip_message.method_id)
        if method is None:
            self.log.warning(
                "received message for unknown method id: %r", someip_message
            )
            self.send_error_response(
                someip_message, addr, header.SOMEIPReturnCode.E_UNKNOWN_METHOD
            )
            return

        if someip_message.message_type not in (
            header.SOMEIPMessageType.REQUEST,
            header.SOMEIPMessageType.REQUEST_NO_RETURN,
        ):
            self.log.warning(
                "received message with bad message type: %r", someip_message
            )
            self.send_error_response(
                someip_message, addr, header.SOMEIPReturnCode.E_WRONG_MESSAGE_TYPE
            )
            return

        if someip_message.return_code != header.SOMEIPReturnCode.E_OK:
            self.log.warning(
                "received message with bad return code: %r", someip_message
            )
            self.send_error_response(
                someip_message, addr, header.SOMEIPReturnCode.E_WRONG_MESSAGE_TYPE
            )
            return

        self.log.info(
            "%r calling %s: %r",
            addr,
            method,
            someip_message.payload,
        )
        try:
            response = method(someip_message, addr)
        except MalformedMessageError:
            self.send_error_response(
                someip_message, addr, header.SOMEIPReturnCode.E_MALFORMED_MESSAGE
            )
            return

        if (
            response is not None
            and someip_message.message_type == header.SOMEIPMessageType.REQUEST
        ):
            self.send_positive_response(someip_message, addr, payload=response)

    def send_error_response(
        self,
        msg: header.SOMEIPHeader,
        addr: header._T_SOCKNAME,
        return_code: header.SOMEIPReturnCode,
    ) -> None:
        resp = dataclasses.replace(
            msg,
            message_type=header.SOMEIPMessageType.ERROR,
            return_code=return_code,
            payload=b"",
        )
        self.send(resp.build(), addr)

    def send_positive_response(
        self,
        msg: header.SOMEIPHeader,
        addr: header._T_SOCKNAME,
        payload: bytes = b"",
    ) -> None:
        resp = dataclasses.replace(
            msg, message_type=header.SOMEIPMessageType.RESPONSE, payload=payload
        )
        self.send(resp.build(), addr)

    def client_subscribed(
        self,
        subscription: sd.EventgroupSubscription,
        source: header._T_SOCKNAME,
    ) -> None:
        try:
            evgrp = self.eventgroups.get(subscription.id)
            assert (
                evgrp
            ), f"{self}.client_subscribed called with unknown subscription id"
            if len(subscription.endpoints) != 1:
                self.log.error(
                    "client tried to subscribe with multiple endpoints from %r:\n%s",
                    source,
                    subscription,
                )
                raise sd.NakSubscription
            self.log.info("client_subscribed from %r: %s", source, subscription)

            ep = next(iter(subscription.endpoints))
            evgrp.subscribe(ep)
        except Exception as exc:
            self.log.exception(
                "client_subscribed from %r: %s failed", source, subscription
            )
            raise sd.NakSubscription from exc

    def client_unsubscribed(
        self, subscription: sd.EventgroupSubscription, source: header._T_SOCKNAME
    ) -> None:
        try:
            evgrp = self.eventgroups.get(subscription.id)
            assert (
                evgrp
            ), f"{self}.client_unsubscribed called with unknown subscription id"
            ep = next(iter(subscription.endpoints))
            evgrp.unsubscribe(ep)
            self.log.info("client_unsubscribed from %r: %s", source, subscription)
        except KeyError:
            self.log.warning(
                "client_unsubscribed unknown from %r: %s", source, subscription
            )
