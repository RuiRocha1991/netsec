from __future__ import annotations

import re

ip: str = "192.168.0.43"
port: int = 22
is_blocked: bool = False
packets: float = 1_024.5

msg: str = f"Ligação SSH: {ip}:{port} -> bloqueado={is_blocked}"
print(msg)

threat_score: int = 87
country: str = "Russia"
print(f"IP: {ip:<20} Score: {threat_score:3d}/100 País: {country}")


geo_country: str | None = None
print(f"País: {geo_country or 'desconhecido'}")

ips: list[str] = [
    "192.168.0.10", "192.168.0.20", "1.2.3.4",
    "10.0.0.1", "8.8.8.8", "185.220.101.1"
]

private_ips: list[str] = [
    ip for ip in ips
    if ip.startswith(("192.", "10.", "172."))
]

print(f"\nIps privados: {private_ips}")

PORTS: list[int] = [22, 80, 443, 23, 3389, 8080]
DANGEROUS: set[int] = {23, 3389, 445, 5900, 1433}

port_risk: dict[int, str] = {
     p: ("🔴 alto" if p in DANGEROUS else "🟢 normal")
    for p in PORTS
}

print("\nRisco por porto:")
for port, risk in port_risk.items():
    print(f"  {port:5d} → {risk}")

log_lines: list[str] = [
    "1.2.3.4 block 443", "5.6.7.8 pass 80",
    "1.2.3.4 block 22",  "9.9.9.9 block 3389",
    "5.6.7.8 block 443"
]

unique_blocked: set[str] = {
    line.split()[0] for line in log_lines if "block" in line
}
print(f"\nIPs únicos bloqueados: {unique_blocked}")
print(f"Total: {len(unique_blocked)} IPs distintos")


log_line: str = "1.2.3.4 443 tcp block"
src_ip, dst_port, protocol, action = log_line.split()
print(f"\n {action} {protocol} de {src_ip} -> porto {dst_port}")

fields: list[str] = ["5", "0", "0", "em0", "block", "tcp", "1.2.3.4"]
rule_num, *_ignored, src = fields
print(f"Regra: {rule_num} | Origem: {src}")

a, b = "192.168.0.1", "10.0.0.1"
a, b = b, a
print(f"Swap: a={a} b={b}")

log_entries: list[str] = [
    "block in em0 tcp 185.220.101.1:54321 -> 192.168.0.43:22",
    "pass in em0 udp 8.8.8.8:53 -> 192.168.0.10:1024",
    "block in em0 tcp 1.2.3.4:12345 -> 192.168.0.43:3389",
]

PATTERN = re.compile(
    r"(?P<action>block|pass).*?(?P<src>\d+\.\d+\.\d+\.\d+):(?P<sport>\d+)"
    r".*?(?P<dst>\d+\.\d+\.\d+\.\d+):(?P<dport>\d+)"
)

print("\nParsing com walrus:")
for entry in log_entries:
    if m := PATTERN.search(entry):  # assign + test numa linha
        icon = "🔴" if m.group("action") == "block" else "🟢"
        print(f"  {icon} {m.group('action'):5} {m.group('src'):18} → porto {m.group('dport')}")
