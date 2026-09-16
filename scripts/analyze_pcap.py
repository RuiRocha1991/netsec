# scripts/analyze_pcap.py
from __future__ import annotations
import pyshark
from collections import Counter


def analyze_capture(pcap_path: str) -> None:
    cap = pyshark.FileCapture(pcap_path, keep_packets=False)

    src_ips: Counter[str] = Counter()
    dst_ports: Counter[str] = Counter()
    dns_queries: list[str] = []
    protocols: Counter[str] = Counter()

    for pkt in cap:
        try:
            if hasattr(pkt, "ip"):
                src_ips[pkt.ip.src] += 1
            if hasattr(pkt, "tcp"):
                dst_ports[pkt.tcp.dstport] += 1
            if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
                dns_queries.append(pkt.dns.qry_name)
            protocols[pkt.highest_layer] += 1
        except AttributeError:
            pass

    cap.close()

    print("=== TOP 10 IPs DE ORIGEM ===")
    for ip, count in src_ips.most_common(10):
        print(f"  {ip:20} {count:6} pacotes")

    print("\n=== TOP 10 PORTOS DESTINO ===")
    for port, count in dst_ports.most_common(10):
        print(f"  Porto {port:6} {count:6} pacotes")

    print("\n=== DOMÍNIOS DNS CONSULTADOS ===")
    for domain in sorted(set(dns_queries)):
        print(f"  {domain}")

    print("\n=== PROTOCOLOS ===")
    for proto, count in protocols.most_common():
        print(f"  {proto:20} {count:6} pacotes")


if __name__ == "__main__":
    analyze_capture("data/captures/dia3_capture.pcapng")