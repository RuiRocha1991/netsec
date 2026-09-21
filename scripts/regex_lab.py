from __future__ import annotations
import re

# ── Non-capturing groups (?:...) ──────────────────────────────────────────
# Agrupar para alternância sem criar grupo de captura
PROTO_RE = re.compile(r"(?:tcp|udp|icmp)", re.IGNORECASE)
for line in ["proto=TCP", "proto=udp", "proto=HTTP"]:
    m = PROTO_RE.search(line)
    print(f"{line:20} → {'match' if m else 'sem match'}")

# ── re.VERBOSE — regex legível com comentários ────────────────────────────
IP_RE = re.compile(r"""
    (?P<oct1>\d{1,3}) \.   # primeiro octeto
    (?P<oct2>\d{1,3}) \.   # segundo
    (?P<oct3>\d{1,3}) \.   # terceiro
    (?P<oct4>\d{1,3})      # quarto
""", re.VERBOSE)

test_ips = ["192.168.10.50", "não é ip", "1.2.3.4"]
for ip in test_ips:
    m = IP_RE.search(ip)
    if m:
        print(f"{ip} → oct1={m.group('oct1')} oct4={m.group('oct4')}")

# ── findall vs finditer ────────────────────────────────────────────────────
log = "block 1.2.3.4:22 block 5.6.7.8:3389 pass 9.9.9.9:443"
# findall devolve lista de strings
ips = re.findall(r"\d+\.\d+\.\d+\.\d+", log)
print(f"\nIPs encontrados: {ips}")

# finditer devolve iterador de Match objects (melhor para logs grandes)
for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+):(\d+)", log):
    print(f"  IP={m.group(1):15} porto={m.group(2)}")
