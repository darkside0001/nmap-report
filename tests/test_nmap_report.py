import json
from pathlib import Path

import pytest

from nmap_report.cli import main
from nmap_report.diff import diff
from nmap_report.parser import UnsafeXML, parse_file, parse_string
from nmap_report.report import to_html, to_markdown
from nmap_report.rules import assess

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
OLD = SAMPLES / "scan-2026-11-01.xml"
NEW = SAMPLES / "scan-2026-11-15.xml"


def xml(ports, addr="10.0.0.1", state="up"):
    p = "".join(
        f'<port protocol="{proto}" portid="{n}"><state state="{st}"/><service name="{svc}" product="{prod}"{extra}/></port>'
        for n, proto, st, svc, prod, extra in ports)
    return (f'<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun args="nmap x" start="1700000000" version="7.95">'
            f'<host><status state="{state}"/><address addr="{addr}" addrtype="ipv4"/><ports>{p}</ports></host></nmaprun>')


def test_parse_sample():
    scan = parse_file(NEW)
    assert len(scan.hosts) == 7  # the down host is skipped
    db = scan.host("192.168.10.20")
    assert db.hostnames == ["db01.office.lan"]
    assert [p.key for p in db.open_ports] == ["22/tcp", "3306/tcp", "6379/tcp"]
    assert db.open_ports[2].banner == "Redis key-value store 7.0.15"
    assert scan.started.year == 2026


def test_include_down_hosts():
    assert len(parse_file(NEW, include_down=True).hosts) == 8


def test_rejects_entities():
    evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>'
    with pytest.raises(UnsafeXML):
        parse_string(evil)


def test_rejects_non_nmap_and_broken_xml():
    with pytest.raises(ValueError):
        parse_string("<html></html>")
    with pytest.raises(ValueError):
        parse_string("<nmaprun><host>")


def ids(scan):
    return [(r.port.key, r.rule.id) for r in assess(scan.hosts)]


def test_rules_by_port_and_service():
    scan = parse_string(xml([
        (6379, "tcp", "open", "redis", "", ""),
        (2222, "tcp", "open", "telnet", "", ""),        # telnet on an odd port, matched by service
        (3306, "tcp", "filtered", "mysql", "", ""),     # not open: ignored
        (8443, "tcp", "open", "http", "nginx", ' tunnel="ssl"'),  # HTTPS: not plain HTTP
    ]))
    assert ids(scan) == [("6379/tcp", "NR-002"), ("2222/tcp", "NR-020")]


def test_product_hint_avoids_false_positive():
    other = parse_string(xml([(8000, "tcp", "open", "http", "Werkzeug httpd", "")]))
    assert ids(other) == [("8000/tcp", "NR-050")]  # just plain HTTP, not Hikvision
    hik = parse_string(xml([(8000, "tcp", "open", "http-alt", "Hikvision DVR SDK", "")]))
    assert ids(hik) == [("8000/tcp", "NR-040")]


def test_risks_sorted_by_severity():
    risks = assess(parse_file(NEW).hosts)
    sev = [r.rule.severity for r in risks]
    order = ["critical", "high", "medium", "low"]
    assert sev == sorted(sev, key=order.index)
    assert sev[:2] == ["critical", "critical"]


def test_diff():
    d = diff(parse_file(OLD), parse_file(NEW))
    assert [h.address for h in d.new_hosts] == ["192.168.10.60"]
    assert [h.address for h in d.gone_hosts] == ["192.168.10.50"]
    assert [(h.address, p.key) for h, p in d.opened] == [("192.168.10.20", "6379/tcp")]
    assert [(h.address, p.key) for h, p in d.closed] == [("192.168.10.40", "3389/tcp")]
    assert [(c.host, c.port) for c in d.changed] == [("192.168.10.10", "80/tcp"), ("192.168.10.10", "443/tcp")]
    assert diff(parse_file(NEW), parse_file(NEW)).empty


def test_html_escapes_banners():
    scan = parse_string(xml([(80, "tcp", "open", "http", "&lt;script&gt;alert(1)&lt;/script&gt;", "")]))
    out = to_html(scan, assess(scan.hosts))
    assert "<script>" not in out and "&lt;script&gt;" in out


def test_markdown_sanitises_cells():
    scan = parse_string(xml([(80, "tcp", "open", "http", "evil | injected", "")]))
    assert "evil \\| injected" in to_markdown(scan, assess(scan.hosts))


def test_cli_formats(tmp_path, capsys):
    out = tmp_path / "r.html"
    assert main([str(NEW), "--diff", str(OLD), "-f", "html", "-o", str(out)]) == 0
    assert "Changes since" in out.read_text()
    assert main([str(NEW), "-f", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["risks"]["critical"] == 2


def test_cli_fail_on(capsys):
    assert main([str(NEW), "--fail-on", "critical"]) == 1
    assert main([str(OLD), "--fail-on", "critical"]) == 0
    assert main([str(NEW), "--diff", str(NEW), "--fail-on", "critical"]) == 1  # risks still there
    assert main([str(OLD), "--diff", str(OLD), "--fail-on", "critical"]) == 0


def test_cli_errors(tmp_path):
    bad = tmp_path / "x.xml"
    bad.write_text("not xml")
    assert main([str(bad)]) == 2
    assert main([str(tmp_path / "missing.xml")]) == 2
