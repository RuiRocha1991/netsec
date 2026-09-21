from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.db.storage import EventStorage  # noqa: E402
from src.parsers.pfsense_parser import parse_file  # noqa: E402


def ingest(log_path: Path, db_path: Path) -> None:
    print(f"A ler {log_path}...")
    entries = parse_file(str(log_path))
    print(f"  {len(entries)} linhas válidas encontradas")

    storage = EventStorage(db_path)
    inserted = storage.insert_many(entries)
    print(f"  {inserted} eventos inseridos em {db_path}")

    stats = storage.stats()
    high_prio = sum(1 for e in entries if e.is_high_priority)

    print()
    print("=== SUMÁRIO DO FICHEIRO ===")
    print(f"  Total eventos:    {len(entries)}")
    print(f"  Alta prioridade:  {high_prio}")
    print(f"  Bloqueados:       {sum(1 for e in entries if e.action == 'block')}")
    print(f"  Permitidos:       {sum(1 for e in entries if e.action == 'pass')}")
    print()
    print("=== TOP 5 IPs BLOQUEADOS ===")
    for row in storage.top_blocked_ips(5):
        print(f"  {row['src_ip']:<20} {row['total']:>4} bloqueios")
    print()
    print(f"=== BASE DE DADOS: {stats['total']} eventos totais ===")


if __name__ == "__main__":
    log_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/logs/test_pfsense.log")
    db_path  = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("data/netsec.db")
    ingest(log_path, db_path)
