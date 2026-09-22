from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd  # noqa: E402

from src.db.storage import EventStorage  # noqa: E402


def main() -> None:
    storage = EventStorage()
    total = storage.count()
    if total == 0:
        print("Sem eventos na BD. Corre primeiro: python scripts/ingest_log.py")
        return

    print(f"=== ANÁLISE DE {total} EVENTOS ===\n")

    # ── Top portos atacados ────────────────────────────────────────────────
    print("TOP 10 PORTOS ATACADOS (externos bloqueados):")
    for row in storage.top_targeted_ports(10):
        bar = "█" * min(row["total"], 40)
        print(f"  Porto {row['dst_port']:5d}  {row['total']:4d}  {bar}")

    # ── Distribuição de protocolos ─────────────────────────────────────────
    print("\nDISTRIBUIÇÃO DE PROTOCOLOS:")
    for row in storage.protocol_breakdown():
        print(f"  {row['protocol']:6} {row['action']:5}  {row['total']:4d}")

    # ── Port scans detectados ──────────────────────────────────────────────
    scans = storage.potential_port_scans(threshold=5)
    if scans:
        print("\nPOSSÍVEIS PORT SCANS (≥5 portos distintos):")
        for row in scans:
            print(
                f"  {row['src_ip']:<20} {row['unique_ports']:3d} portos únicos"
                f"  ({row['total']} tentativas)"
            )
    else:
        print("\nSem port scans detectados.")

    # ── Análise com Pandas ────────────────────────────────────────────────
    print("\n=== ANÁLISE PANDAS ===")
    df = storage.as_dataframe()

    # Eventos por hora
    df["hour"] = df["timestamp"].dt.hour
    by_hour = df.groupby("hour")["action"].count()
    print("\nEventos por hora:")
    for hour, count in by_hour.items():
        bar = "█" * (count // 2)
        print(f"  {hour:02d}h  {count:4d}  {bar}")

    # Bloqueios por zona de origem
    print("\nBloqueios por zona de origem:")
    blocks_by_zone = (
        df[df["action"] == "block"]
        .groupby("src_zone")["id"]
        .count()
        .sort_values(ascending=False)
    )
    for zone, count in blocks_by_zone.items():
        print(f"  {zone:<12} {count:4d}")

    # Tabela cruzada protocolo × acção
    print("\nTabela protocolo × acção:")
    pivot = pd.pivot_table(
        df, values="id", index="protocol",
        columns="action", aggfunc="count", fill_value=0
    )
    print(pivot.to_string())


if __name__ == "__main__":
    main()
