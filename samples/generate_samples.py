"""Generate two synthetic nmap -sV -oX scans of a small office network.

The second scan, two weeks later, contains typical drift: a new Redis port on
the database server, a forgotten Docker host, an nginx upgrade, a printer
removed and RDP closed. Addresses are private (192.168.10.0/24).
"""

from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import quoteattr as q

BASE = {
    "192.168.10.1": ("gw.office.lan", [(22, "ssh", "Dropbear sshd", "2022.83", ""), (53, "domain", "dnsmasq", "2.89", ""),
                                       (80, "http", "lighttpd", "", ""), (443, "https", "lighttpd", "", "ssl")]),
    "192.168.10.10": ("web01.office.lan", [(22, "ssh", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.10", "Ubuntu Linux; protocol 2.0"),
                                           (80, "http", "nginx", "1.18.0", "Ubuntu"), (443, "http", "nginx", "1.18.0", "ssl")]),
    "192.168.10.20": ("db01.office.lan", [(22, "ssh", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.10", "Ubuntu Linux; protocol 2.0"),
                                          (3306, "mysql", "MySQL", "8.0.36-0ubuntu0.22.04.1", "")]),
    "192.168.10.30": ("nvr.office.lan", [(80, "http", "Hikvision IP camera httpd", "", ""), (554, "rtsp", "Hikvision 7513 POE IP camera rtspd", "", ""),
                                         (8000, "http-alt", "Hikvision DVR SDK", "", "")]),
    "192.168.10.31": ("", [(80, "http", "Dahua DVR httpd", "", ""), (37777, "unknown", "Dahua DVR", "", "")]),
    "192.168.10.40": ("acct-pc.office.lan", [(135, "msrpc", "Microsoft Windows RPC", "", ""), (139, "netbios-ssn", "Microsoft Windows netbios-ssn", "", ""),
                                             (445, "microsoft-ds", "", "", ""), (3389, "ms-wbt-server", "Microsoft Terminal Services", "", "")]),
    "192.168.10.50": ("printer.office.lan", [(23, "telnet", "HP JetDirect telnetd", "", ""), (80, "http", "HP LaserJet http config", "", ""),
                                             (9100, "jetdirect", "", "", "")]),
}


def week2(hosts):
    h = {k: (n, list(p)) for k, (n, p) in hosts.items()}
    h["192.168.10.10"] = (h["192.168.10.10"][0], [(22, "ssh", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.10", "Ubuntu Linux; protocol 2.0"),
                                                  (80, "http", "nginx", "1.24.0", "Ubuntu"), (443, "http", "nginx", "1.24.0", "ssl")])
    h["192.168.10.20"][1].append((6379, "redis", "Redis key-value store", "7.0.15", ""))
    h["192.168.10.40"] = (h["192.168.10.40"][0], [p for p in h["192.168.10.40"][1] if p[0] != 3389])
    del h["192.168.10.50"]
    h["192.168.10.60"] = ("build01.office.lan", [(22, "ssh", "OpenSSH", "9.6p1 Ubuntu 3ubuntu13.5", "Ubuntu Linux; protocol 2.0"),
                                                 (2375, "docker", "Docker", "26.1.3", "API 1.45")])
    return h


def render(hosts, when: datetime) -> str:
    ts = int(when.timestamp())
    args = "nmap -sV -T4 -oX scan.xml 192.168.10.0/24"
    out = ['<?xml version="1.0" encoding="UTF-8"?>', "<!DOCTYPE nmaprun>",
           f'<nmaprun scanner="nmap" args={q(args)} start="{ts}" startstr="{when:%a %b %d %H:%M:%S %Y}" version="7.95" xmloutputversion="1.05">',
           '<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>']
    for addr, (name, ports) in hosts.items():
        out.append(f'<host starttime="{ts}" endtime="{ts + 40}"><status state="up" reason="arp-response" reason_ttl="0"/>')
        out.append(f'<address addr="{addr}" addrtype="ipv4"/>')
        out.append("<hostnames>" + (f'<hostname name="{name}" type="PTR"/>' if name else "") + "</hostnames><ports>")
        out.append(f'<extraports state="closed" count="{1000 - len(ports)}"><extrareasons reason="reset" count="{1000 - len(ports)}"/></extraports>')
        for port, svc, product, version, extra in ports:
            tunnel = ' tunnel="ssl"' if extra == "ssl" else ""
            extra_attr = f" extrainfo={q(extra)}" if extra and extra != "ssl" else ""
            out.append(f'<port protocol="tcp" portid="{port}"><state state="open" reason="syn-ack" reason_ttl="64"/>'
                       f'<service name="{svc}" product={q(product)} version={q(version)}{extra_attr}{tunnel} method="probed" conf="10"/></port>')
        out.append("</ports></host>")
    # one host that was down, as nmap writes it with -Pn / list scans
    out.append(f'<host><status state="down" reason="no-response" reason_ttl="0"/><address addr="192.168.10.99" addrtype="ipv4"/></host>')
    out.append(f'<runstats><finished time="{ts + 95}" elapsed="95" exit="success"/><hosts up="{len(hosts)}" down="1" total="{len(hosts) + 1}"/></runstats></nmaprun>')
    return "\n".join(out) + "\n"


here = Path(__file__).parent
(here / "scan-2026-11-01.xml").write_text(render(BASE, datetime(2026, 11, 1, 2, 0, tzinfo=timezone.utc)))
(here / "scan-2026-11-15.xml").write_text(render(week2(BASE), datetime(2026, 11, 15, 2, 0, tzinfo=timezone.utc)))
print("wrote samples/scan-2026-11-01.xml and samples/scan-2026-11-15.xml")
