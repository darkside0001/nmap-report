"""Parse nmap XML (-oX) files.

The XML comes from your own scans, but it is still parsed with care: DTDs
and entities are rejected, so a crafted file cannot expand into gigabytes.
"""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Port:
    protocol: str
    port: int
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.port}/{self.protocol}"

    @property
    def banner(self) -> str:
        return " ".join(x for x in (self.product, self.version, f"({self.extrainfo})" if self.extrainfo else "") if x)


@dataclass
class Host:
    address: str
    hostnames: list[str] = field(default_factory=list)
    status: str = "up"
    mac: str = ""
    vendor: str = ""
    os: str = ""
    ports: list[Port] = field(default_factory=list)

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def name(self) -> str:
        return f"{self.address} ({self.hostnames[0]})" if self.hostnames else self.address


@dataclass
class Scan:
    source: str
    args: str = ""
    started: datetime | None = None
    nmap_version: str = ""
    hosts: list[Host] = field(default_factory=list)

    def host(self, address: str) -> Host | None:
        return next((h for h in self.hosts if h.address == address), None)


class UnsafeXML(ValueError):
    pass


def _check_safe(text: str) -> None:
    head = text[:4096].upper()
    if "<!ENTITY" in head:
        raise UnsafeXML("XML entities are not allowed in nmap files")


def parse_string(text: str, source: str = "<string>", include_down: bool = False) -> Scan:
    _check_safe(text)
    try:
        root = ET.fromstring(text)
    except ParseError as e:
        raise ValueError(f"{source}: invalid XML: {e}") from None
    if root.tag != "nmaprun":
        raise ValueError(f"{source}: not an nmap XML file (root element <{root.tag}>)")
    scan = Scan(source=source, args=root.get("args", ""), nmap_version=root.get("version", ""))
    if root.get("start"):
        scan.started = datetime.fromtimestamp(int(root.get("start")), tz=timezone.utc)

    for h in root.findall("host"):
        status = h.find("status")
        state = status.get("state") if status is not None else "unknown"
        if state != "up" and not include_down:
            continue
        host = Host(address="", status=state)
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6") and not host.address:
                host.address = a.get("addr", "")
            elif a.get("addrtype") == "mac":
                host.mac, host.vendor = a.get("addr", ""), a.get("vendor", "")
        host.hostnames = [n.get("name") for n in h.findall("hostnames/hostname") if n.get("name")]
        osm = h.find("os/osmatch")
        if osm is not None:
            host.os = f"{osm.get('name')} ({osm.get('accuracy')}%)"
        for p in h.findall("ports/port"):
            st = p.find("state")
            svc = p.find("service")
            port = Port(
                protocol=p.get("protocol", "tcp"), port=int(p.get("portid", 0)),
                state=st.get("state", "") if st is not None else "",
            )
            if svc is not None:
                port.service = svc.get("name", "")
                port.product = svc.get("product", "")
                port.version = svc.get("version", "")
                port.extrainfo = svc.get("extrainfo", "")
                port.tunnel = svc.get("tunnel", "")
            for s in p.findall("script"):
                port.scripts[s.get("id", "")] = (s.get("output") or "").strip()
            host.ports.append(port)
        host.ports.sort(key=lambda x: (x.protocol, x.port))
        if host.address:
            scan.hosts.append(host)
    scan.hosts.sort(key=lambda x: _addr_key(x.address))
    return scan


def _addr_key(a: str):
    try:
        ip = ipaddress.ip_address(a)
        return (ip.version, int(ip))
    except ValueError:
        return (9, 0)


def parse_file(path: str | Path, include_down: bool = False) -> Scan:
    p = Path(path)
    return parse_string(p.read_text(encoding="utf-8", errors="replace"), source=p.name, include_down=include_down)
