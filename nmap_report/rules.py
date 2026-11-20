"""Risk rules for exposed services.

The list focuses on what I find most often on small business networks and
VPS: databases and admin interfaces open to the world, cleartext protocols,
and CCTV / IoT devices (DVRs, NVRs, cameras) reachable from outside.
"""

from __future__ import annotations

from dataclasses import dataclass

from .parser import Host, Port

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    why: str
    fix: str
    ports: tuple[int, ...] = ()
    services: tuple[str, ...] = ()
    protocol: str = "tcp"
    product_hint: str = ""   # if nmap detected a product, it must contain this



RULES: list[Rule] = [
    # Unauthenticated-by-default data stores and APIs
    Rule("NR-001", "critical", "Docker API exposed", "Anyone who reaches the Docker API gets root on the host.",
         "Never expose 2375/2376. Use SSH or a VPN to manage Docker.", (2375, 2376), ("docker",)),
    Rule("NR-002", "critical", "Redis exposed", "Redis has no authentication by default and is routinely wiped or used for RCE.",
         "Bind to 127.0.0.1, set requirepass / ACLs, firewall the port.", (6379,), ("redis",)),
    Rule("NR-003", "critical", "MongoDB exposed", "Open MongoDB instances are a top source of data leaks and ransom notes.",
         "Bind to localhost or a private network and enable authentication.", (27017, 27018), ("mongodb", "mongod")),
    Rule("NR-004", "critical", "Elasticsearch exposed", "Elasticsearch without security leaks every indexed document.",
         "Enable xpack security and restrict the port to the app servers.", (9200, 9300), ("elasticsearch",)),
    Rule("NR-005", "high", "Memcached exposed", "Memcached leaks cached data and is abused for UDP amplification DDoS.",
         "Bind to 127.0.0.1 and disable UDP (-U 0).", (11211,), ("memcache", "memcached")),
    # Databases
    Rule("NR-010", "high", "Database port exposed",
         "Databases should only be reachable from the application servers. Exposed ones are brute-forced constantly.",
         "Firewall the port to known IPs or move it to a private network / SSH tunnel.",
         (3306, 5432, 1433, 1521, 5984), ("mysql", "postgresql", "ms-sql-s", "oracle-tns", "couchdb")),
    # Remote administration
    Rule("NR-020", "high", "Telnet enabled", "Telnet sends passwords in cleartext. Often a sign of an IoT device or old switch.",
         "Disable Telnet and use SSH.", (23, 2323), ("telnet",)),
    Rule("NR-021", "high", "RDP exposed", "Internet-facing RDP is one of the main ransomware entry points.",
         "Put RDP behind a VPN or RD Gateway with MFA, enable NLA.", (3389,), ("ms-wbt-server",)),
    Rule("NR-022", "high", "VNC exposed", "VNC often has weak or no passwords and no encryption.",
         "Tunnel VNC over SSH or a VPN.", (5900, 5901), ("vnc",)),
    Rule("NR-023", "high", "SMB / NetBIOS exposed", "SMB on the internet invites worms (WannaCry) and credential attacks.",
         "Block 139/445 at the edge.", (139, 445), ("microsoft-ds", "netbios-ssn")),
    Rule("NR-024", "medium", "MS RPC exposed", "RPC endpoint mapper leaks information about Windows hosts.",
         "Block 135 at the edge.", (135,), ("msrpc",)),
    Rule("NR-025", "low", "SSH exposed", "Expected on servers, but it will be brute-forced.",
         "Use keys only, disable root login, add fail2ban. See linux-hardening-audit.", (22,), ("ssh",)),
    # Cleartext / legacy
    Rule("NR-030", "medium", "FTP enabled", "FTP sends credentials in cleartext; anonymous login is common.",
         "Use SFTP instead, or FTPS with anonymous login disabled.", (21,), ("ftp",)),
    Rule("NR-031", "medium", "TFTP enabled", "TFTP has no authentication at all; often exposes device configs.",
         "Disable TFTP or restrict it to the management VLAN.", (69,), ("tftp",), "udp"),
    Rule("NR-032", "medium", "SNMP exposed", "SNMP v1/v2c with 'public' community leaks the full device config.",
         "Use SNMPv3 or restrict to the monitoring server.", (161,), ("snmp",), "udp"),
    Rule("NR-033", "medium", "NFS / rpcbind exposed", "NFS exports are often world-readable.",
         "Restrict exports and firewall 111/2049.", (111, 2049), ("rpcbind", "nfs")),
    Rule("NR-034", "medium", "LDAP without TLS", "Directory queries and binds travel in cleartext.",
         "Use LDAPS (636) or StartTLS and block 389 at the edge.", (389,), ("ldap",)),
    # CCTV / IoT / OT
    Rule("NR-040", "high", "Hikvision SDK / service port exposed",
         "Port 8000 on Hikvision DVR/NVR/cameras is targeted by botnets and known auth-bypass bugs.",
         "Do not port-forward CCTV devices. Use the vendor P2P service or a VPN, update firmware.", (8000,), (),
         product_hint="hikvision"),
    Rule("NR-041", "high", "Dahua DVR service port exposed",
         "Port 37777 on Dahua devices has a long history of authentication bypass vulnerabilities.",
         "Close the port-forward, use a VPN, update firmware.", (37777, 37778), (),
         product_hint="dahua"),
    Rule("NR-042", "medium", "RTSP video stream exposed", "Camera streams are often viewable without a password.",
         "Require authentication on RTSP and do not expose 554 to the internet.", (554, 8554), ("rtsp",)),
    Rule("NR-043", "high", "MQTT broker exposed", "MQTT brokers often allow anonymous publish/subscribe to IoT topics.",
         "Require auth and TLS (8883), restrict by IP.", (1883,), ("mqtt",)),
    Rule("NR-044", "critical", "Industrial protocol exposed", "Modbus / BACnet / S7 have no authentication: anyone can read or write values.",
         "Industrial devices must never be on the internet. Isolate them behind a firewall.", (502, 102, 47808, 20000), ("modbus", "bacnet", "iso-tsap")),
    # Web
    Rule("NR-050", "low", "Plain HTTP service", "Traffic and logins on this port are not encrypted.",
         "Redirect to HTTPS (see web-sec-check).", (80, 8080, 8008, 8888), ("http", "http-proxy", "http-alt")),
]


@dataclass
class Risk:
    host: Host
    port: Port
    rule: Rule

    def to_dict(self) -> dict:
        return {"host": self.host.address, "hostnames": self.host.hostnames, "port": self.port.key,
                "service": self.port.service, "banner": self.port.banner, "rule": self.rule.id,
                "severity": self.rule.severity, "title": self.rule.title, "why": self.rule.why,
                "fix": self.rule.fix}


def _matches(rule: Rule, port: Port) -> bool:
    if port.state != "open":
        return False
    if port.service == "http" and port.tunnel == "ssl":
        return False  # HTTPS on an odd port is not "plain HTTP"
    if rule.product_hint and port.product and rule.product_hint not in port.product.lower():
        return False
    if port.service and port.service in rule.services:
        return True
    return port.protocol == rule.protocol and port.port in rule.ports


def assess(hosts: list[Host], rules: list[Rule] | None = None) -> list[Risk]:
    rules = rules or RULES
    out = []
    for h in hosts:
        for p in h.open_ports:
            for r in rules:
                if _matches(r, p):
                    out.append(Risk(h, p, r))
                    break  # one rule per port, the first (most specific) wins
    out.sort(key=lambda r: (SEVERITY_ORDER[r.rule.severity], r.host.address, r.port.port))
    return out
