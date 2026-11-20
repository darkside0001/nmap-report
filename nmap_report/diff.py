"""Compare two scans of the same network."""

from __future__ import annotations

from dataclasses import dataclass, field

from .parser import Host, Port, Scan


@dataclass
class PortChange:
    host: str
    port: str
    before: str
    after: str


@dataclass
class ScanDiff:
    old: Scan
    new: Scan
    new_hosts: list[Host] = field(default_factory=list)
    gone_hosts: list[Host] = field(default_factory=list)
    opened: list[tuple[Host, Port]] = field(default_factory=list)
    closed: list[tuple[Host, Port]] = field(default_factory=list)
    changed: list[PortChange] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.new_hosts or self.gone_hosts or self.opened or self.closed or self.changed)

    def to_dict(self) -> dict:
        return {
            "old": self.old.source, "new": self.new.source,
            "new_hosts": [{"host": h.address, "open_ports": [p.key for p in h.open_ports]} for h in self.new_hosts],
            "gone_hosts": [h.address for h in self.gone_hosts],
            "opened": [{"host": h.address, "port": p.key, "service": p.service, "banner": p.banner} for h, p in self.opened],
            "closed": [{"host": h.address, "port": p.key, "service": p.service} for h, p in self.closed],
            "changed": [vars(c) for c in self.changed],
        }


def _describe(p: Port) -> str:
    return " ".join(x for x in (p.service, p.banner) if x) or "unknown"


def diff(old: Scan, new: Scan) -> ScanDiff:
    d = ScanDiff(old, new)
    old_by = {h.address: h for h in old.hosts}
    new_by = {h.address: h for h in new.hosts}
    d.new_hosts = [h for a, h in new_by.items() if a not in old_by]
    d.gone_hosts = [h for a, h in old_by.items() if a not in new_by]
    for addr, nh in new_by.items():
        oh = old_by.get(addr)
        if not oh:
            continue
        op = {p.key: p for p in oh.open_ports}
        np = {p.key: p for p in nh.open_ports}
        d.opened += [(nh, p) for k, p in np.items() if k not in op]
        d.closed += [(oh, p) for k, p in op.items() if k not in np]
        for k in np.keys() & op.keys():
            a, b = _describe(op[k]), _describe(np[k])
            if a != b:
                d.changed.append(PortChange(addr, k, a, b))
    d.changed.sort(key=lambda c: (c.host, int(c.port.split("/")[0])))
    d.opened.sort(key=lambda x: (x[0].address, x[1].port))
    d.closed.sort(key=lambda x: (x[0].address, x[1].port))
    return d
