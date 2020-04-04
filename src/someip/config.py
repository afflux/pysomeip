from __future__ import annotations

import dataclasses
import ipaddress
import socket
import typing

import someip.header


_T_ADDR = typing.Tuple[typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address], int]
_T_SOCKNAME = typing.Union[typing.Tuple[str, int], typing.Tuple[str, int, int, int]]


@dataclasses.dataclass(frozen=True)
class Eventgroup:
    service_id: int
    instance_id: int
    major_version: int
    eventgroup_id: int

    sockname: _T_SOCKNAME

    protocol: someip.header.L4Protocols

    def create_subscribe_entry(self, ttl=3, counter=0):
        endpoint_option = self._sockaddr_to_endpoint(self.sockname, self.protocol)
        return someip.header.SOMEIPSDEntry(
            sd_type=someip.header.SOMEIPSDEntryType.Subscribe,
            service_id=self.service_id,
            instance_id=self.instance_id,
            major_version=self.major_version,
            ttl=ttl,
            minver_or_counter=(counter << 16) | self.eventgroup_id,
            options_1=(endpoint_option,),
        )

    def for_service(self, service: Service) -> typing.Optional[Eventgroup]:
        if not self.as_service().matches_offer(service.create_offer_entry()):
            return None
        return dataclasses.replace(
            self, instance_id=service.instance_id, major_version=service.major_version,
        )

    def as_service(self):
        return Service(
            service_id=self.service_id,
            instance_id=self.instance_id,
            major_version=self.major_version,
        )

    @staticmethod
    def _sockaddr_to_endpoint(
        sockname: _T_SOCKNAME, protocol: someip.header.L4Protocols
    ) -> someip.header.SOMEIPSDOption:
        host, port = socket.getnameinfo(
            sockname, socket.NI_NUMERICHOST | socket.NI_NUMERICSERV
        )
        nport = int(port)
        naddr = ipaddress.ip_address(host)

        if isinstance(naddr, ipaddress.IPv4Address):
            return someip.header.IPv4EndpointOption(
                address=naddr, l4proto=protocol, port=nport
            )
        elif isinstance(naddr, ipaddress.IPv6Address):
            return someip.header.IPv6EndpointOption(
                address=naddr, l4proto=protocol, port=nport
            )
        else:  # pragma: nocover
            raise TypeError("unsupported IP address family")

    def __str__(self) -> str:  # pragma: nocover
        return (
            f"eventgroup={self.eventgroup_id:04x} service=0x{self.service_id:04x},"
            f" instance=0x{self.instance_id:04x}, version={self.major_version}"
            f" addr={self.sockname!r} proto={self.protocol.name}"
        )


@dataclasses.dataclass(frozen=True)
class Service:
    service_id: int
    instance_id: int = dataclasses.field(default=0xFFFF)
    major_version: int = dataclasses.field(default=0xFF)
    minor_version: int = dataclasses.field(default=0xFFFFFFFF)

    options_1: typing.Tuple[someip.header.SOMEIPSDOption, ...] = dataclasses.field(
        default_factory=tuple, compare=False
    )
    options_2: typing.Tuple[someip.header.SOMEIPSDOption, ...] = dataclasses.field(
        default_factory=tuple, compare=False
    )

    eventgroups: typing.Tuple[int, ...] = dataclasses.field(default_factory=tuple)

    def matches_offer(self, entry: someip.header.SOMEIPSDEntry) -> bool:
        if entry.sd_type != someip.header.SOMEIPSDEntryType.OfferService:
            raise ValueError("entry is no OfferService")

        if self.service_id != entry.service_id:
            return False

        if self.instance_id != 0xFFFF and self.instance_id != entry.instance_id:
            return False
        if self.major_version != 0xFF and self.major_version != entry.major_version:
            return False
        if (
            self.minor_version != 0xFFFFFFFF
            and self.minor_version != entry.service_minor_version
        ):
            return False
        return True

    def matches_find(self, entry: someip.header.SOMEIPSDEntry) -> bool:
        if entry.sd_type != someip.header.SOMEIPSDEntryType.FindService:
            raise ValueError("entry is no FindService")

        if self.service_id != entry.service_id:
            return False

        if entry.instance_id != 0xFFFF and self.instance_id != entry.instance_id:
            return False
        if entry.major_version != 0xFF and self.major_version != entry.major_version:
            return False
        if (
            entry.service_minor_version != 0xFFFFFFFF
            and self.minor_version != entry.service_minor_version
        ):
            return False
        return True

    def matches_subscribe(self, entry: someip.header.SOMEIPSDEntry) -> bool:
        if entry.sd_type != someip.header.SOMEIPSDEntryType.Subscribe:
            raise ValueError("entry is no Subscribe")

        if self.service_id != entry.service_id:
            return False

        if self.instance_id != 0xFFFF and self.instance_id != entry.instance_id:
            return False

        if self.major_version != 0xFF and self.major_version != entry.major_version:
            return False

        return entry.eventgroup_id in self.eventgroups

    def matches_service(self, other: Service) -> bool:
        if self.service_id != other.service_id:
            return False

        if (
            self.instance_id != 0xFFFF
            and other.instance_id != 0xFFFF
            and self.instance_id != other.instance_id
        ):
            return False

        if (
            self.major_version != 0xFF
            and other.major_version != 0xFF
            and self.major_version != other.major_version
        ):
            return False

        if (
            self.minor_version != 0xFFFFFFFF
            and other.minor_version != 0xFFFFFFFF
            and self.minor_version != other.minor_version
        ):
            return False

        return True

    def create_find_entry(self, ttl=3):
        return someip.header.SOMEIPSDEntry(
            sd_type=someip.header.SOMEIPSDEntryType.FindService,
            service_id=self.service_id,
            instance_id=self.instance_id,
            major_version=self.major_version,
            ttl=ttl,
            minver_or_counter=self.minor_version,
        )

    def create_offer_entry(self, ttl=3):
        return someip.header.SOMEIPSDEntry(
            sd_type=someip.header.SOMEIPSDEntryType.OfferService,
            service_id=self.service_id,
            instance_id=self.instance_id,
            major_version=self.major_version,
            ttl=ttl,
            minver_or_counter=self.minor_version,
            options_1=tuple(self.options_1),
            options_2=tuple(self.options_2),
        )

    def __str__(self) -> str:  # pragma: nocover
        version = f"{self.major_version}.{self.minor_version}"

        s_options_1 = (
            ", ".join(str(o) for o in self.options_1) if self.options_1 else ""
        )
        s_options_2 = (
            ", ".join(str(o) for o in self.options_2) if self.options_2 else ""
        )

        return (
            f"service=0x{self.service_id:04x}, instance=0x{self.instance_id:04x},"
            f" version={version}, options_1=[{s_options_1}], options_2=[{s_options_2}]"
        )

    @classmethod
    def from_offer_entry(cls, entry: someip.header.SOMEIPSDEntry) -> Service:
        if entry.sd_type != someip.header.SOMEIPSDEntryType.OfferService:
            raise ValueError("entry is no OfferService")
        if not entry.options_resolved:
            raise ValueError("entry must have resolved options")
        return cls(
            entry.service_id,
            entry.instance_id,
            entry.major_version,
            entry.service_minor_version,
            options_1=tuple(entry.options_1),
            options_2=tuple(entry.options_2),
        )
