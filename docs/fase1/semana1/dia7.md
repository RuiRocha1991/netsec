# Dia 7 — Pipeline completo: ficheiro de log → SQLite

**Fase:** 1 · **Semana:** 1 · **Estado:** ✅ Concluído

---

## Prompt de contexto

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura: pfSense com zonas GREEN(192.168.10.x)/IOT(40.x)/DMZ(30.x).

Dias 1-6 concluídos. Estado do projecto:
- src/models/network_utils.py — NetworkZone, is_private(), get_network_zone(),
  is_dangerous_port(), classify_event(), DANGEROUS_PORTS (inclui porta 22)
- src/models/log_entry.py — dataclass LogEntry com __post_init__, is_high_priority,
  risk_score, to_dict(), to_json()
- src/parsers/pfsense_parser.py — parse_line(), parse_file(), TCP/UDP/ICMP IPv4
- scripts/analyze_pcap.py — análise .pcap com pyshark
- tests/: 64 testes, todos a passar
- Packages: pyshark
- Git: 9 commits no branch netsec-0

Quero continuar para o Dia 7: pipeline completo — ler ficheiro .log pfSense,
parsear todas as linhas, persistir em SQLite, imprimir sumário.
```

---

## Objectivo

Fechar a Semana 1 com o primeiro pipeline de ponta a ponta:

```
ficheiro .log pfSense
       ↓
pfsense_parser.parse_file()
       ↓
LogEntry objects
       ↓
src/db/storage.py (SQLite)
       ↓
scripts/ingest_log.py imprime sumário
```

No final, tens um script que lê qualquer ficheiro de log pfSense real e persiste os eventos em base de dados.

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `sqlite3` (stdlib) | Criar tabela, inserir rows, queries |
| Context manager `with conn:` | Auto-commit/rollback — como try-finally em Java |
| `pathlib.Path` | Caminhos de ficheiro — mais seguro que strings |
| `dataclasses.asdict()` | Converter LogEntry em dict para inserir no SQLite |
| `@contextmanager` | Criar gestor de contexto para a ligação SQLite |
| Generator expression | `sum(1 for e in entries if e.is_high_priority)` |

---

## Steps

### Step 1 — Criar package `src/db/`

```bash
touch src/db/__init__.py
```

---

### Step 2 — `src/db/storage.py`

```python
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from src.models.log_entry import LogEntry

_DEFAULT_DB = Path("data/netsec.db")


class EventStorage:
    """Persiste e consulta LogEntry num ficheiro SQLite."""

    def __init__(self, db_path: Path = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ── Gestão da ligação ──────────────────────────────────────────────────

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # aceder a colunas por nome
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── Schema ─────────────────────────────────────────────────────────────

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT    NOT NULL,
                    action          TEXT    NOT NULL,
                    interface       TEXT    NOT NULL,
                    protocol        TEXT    NOT NULL,
                    src_ip          TEXT    NOT NULL,
                    src_port        INTEGER NOT NULL,
                    dst_ip          TEXT    NOT NULL,
                    dst_port        INTEGER NOT NULL,
                    src_zone        TEXT    NOT NULL,
                    dst_zone        TEXT    NOT NULL,
                    is_src_private  INTEGER NOT NULL,
                    is_dangerous    INTEGER NOT NULL,
                    classification  TEXT    NOT NULL,
                    geo_country     TEXT,
                    abuse_score     INTEGER,
                    ingested_at     TEXT    DEFAULT (datetime('now'))
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)"
            )

    # ── Escrita ────────────────────────────────────────────────────────────

    def insert(self, entry: LogEntry) -> int:
        """Insere um LogEntry e devolve o id gerado."""
        d = entry.to_dict()
        with self._conn() as conn:
            cur = conn.execute("""
                INSERT INTO events (
                    timestamp, action, interface, protocol,
                    src_ip, src_port, dst_ip, dst_port,
                    src_zone, dst_zone, is_src_private, is_dangerous,
                    classification, geo_country, abuse_score
                ) VALUES (
                    :timestamp, :action, :interface, :protocol,
                    :src_ip, :src_port, :dst_ip, :dst_port,
                    :src_zone, :dst_zone, :is_src_private, :is_dangerous,
                    :classification, :geo_country, :abuse_score
                )
            """, d)
            return cur.lastrowid  # type: ignore[return-value]

    def insert_many(self, entries: list[LogEntry]) -> int:
        """Insere vários LogEntry em batch. Devolve o número de linhas inseridas."""
        if not entries:
            return 0
        rows = [entry.to_dict() for entry in entries]
        with self._conn() as conn:
            conn.executemany("""
                INSERT INTO events (
                    timestamp, action, interface, protocol,
                    src_ip, src_port, dst_ip, dst_port,
                    src_zone, dst_zone, is_src_private, is_dangerous,
                    classification, geo_country, abuse_score
                ) VALUES (
                    :timestamp, :action, :interface, :protocol,
                    :src_ip, :src_port, :dst_ip, :dst_port,
                    :src_zone, :dst_zone, :is_src_private, :is_dangerous,
                    :classification, :geo_country, :abuse_score
                )
            """, rows)
        return len(rows)

    # ── Leitura ────────────────────────────────────────────────────────────

    def count(self) -> int:
        with self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
            return row[0]

    def recent(self, limit: int = 20) -> list[sqlite3.Row]:
        """Devolve os últimos N eventos, mais recente primeiro."""
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()

    def top_blocked_ips(self, limit: int = 10) -> list[sqlite3.Row]:
        """IPs de origem com mais bloqueios."""
        with self._conn() as conn:
            return conn.execute("""
                SELECT src_ip, COUNT(*) as total
                FROM events
                WHERE action = 'block'
                GROUP BY src_ip
                ORDER BY total DESC
                LIMIT ?
            """, (limit,)).fetchall()

    def stats(self) -> dict[str, int]:
        """Estatísticas gerais da base de dados."""
        with self._conn() as conn:
            total     = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            blocked   = conn.execute("SELECT COUNT(*) FROM events WHERE action='block'").fetchone()[0]
            high_prio = conn.execute(
                "SELECT COUNT(*) FROM events WHERE classification LIKE 'HIGH%'"
            ).fetchone()[0]
        return {"total": total, "blocked": blocked, "high_priority": high_prio}
```

---

### Step 3 — Gerador de log de teste

Para testar sem um pfSense real, cria um ficheiro de log com linhas realistas:

```bash
mkdir -p data/logs
```

```python
# scripts/generate_test_log.py
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path


def _rand_ip(prefix: str) -> str:
    return f"{prefix}.{random.randint(1, 254)}"


def _filterlog_line(dt: datetime, action: str, proto: str,
                    src_ip: str, dst_ip: str,
                    src_port: int, dst_port: int) -> str:
    proto_id = {"tcp": 6, "udp": 17, "icmp": 1}[proto]
    ts = dt.strftime("%b %d %H:%M:%S")
    csv_base = f"5,,,0,em0,match,{action},in,4,0x0,,64,1234,0,none,{proto_id},{proto},60"
    if proto in ("tcp", "udp"):
        return f"{ts} pfsense filterlog[1]: {csv_base},{src_ip},{dst_ip},{src_port},{dst_port},0"
    return f"{ts} pfsense filterlog[1]: {csv_base},{src_ip},{dst_ip},8,0"


def generate(path: Path, n: int = 200) -> None:
    external_ips = ["203.0.113.1", "185.220.101.45", "1.2.3.4", "91.108.4.1", "77.88.8.8"]
    internal_ips = [_rand_ip("192.168.10") for _ in range(5)]
    iot_ips      = [_rand_ip("192.168.40") for _ in range(3)]

    dangerous_ports = [22, 3389, 445, 23]
    common_ports    = [80, 443, 53, 8080]

    start = datetime(2026, 9, 17, 8, 0, 0)
    lines: list[str] = []

    for i in range(n):
        dt = start + timedelta(seconds=i * 30)
        action = random.choice(["block", "block", "block", "pass"])
        proto  = random.choice(["tcp", "tcp", "udp", "icmp"])

        if action == "block":
            src_ip   = random.choice(external_ips)
            dst_ip   = random.choice(internal_ips)
            dst_port = random.choice(dangerous_ports + common_ports)
        else:
            src_ip   = random.choice(internal_ips + iot_ips)
            dst_ip   = random.choice(["8.8.8.8", "1.1.1.1", "93.184.216.34"])
            dst_port = random.choice(common_ports)

        src_port = random.randint(1024, 65535)

        lines.append(_filterlog_line(dt, action, proto, src_ip, dst_ip, src_port, dst_port))
        # intercalar linhas de outros processos (parser deve ignorar)
        if i % 10 == 0:
            lines.append(f"{dt.strftime('%b %d %H:%M:%S')} pfsense sshd[99]: session opened")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Geradas {n} entradas em {path}")


if __name__ == "__main__":
    generate(Path("data/logs/test_pfsense.log"))
```

```bash
python scripts/generate_test_log.py
# Geradas 200 entradas em data/logs/test_pfsense.log
```

---

### Step 4 — `scripts/ingest_log.py`

```python
from __future__ import annotations

import sys
from pathlib import Path

from src.db.storage import EventStorage
from src.parsers.pfsense_parser import parse_file


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
```

```bash
python scripts/ingest_log.py
```

Output esperado:
```
A ler data/logs/test_pfsense.log...
  182 linhas válidas encontradas
  182 eventos inseridos em data/netsec.db

=== SUMÁRIO DO FICHEIRO ===
  Total eventos:    182
  Alta prioridade:  47
  Bloqueados:       137
  Permitidos:       45

=== TOP 5 IPs BLOQUEADOS ===
  203.0.113.1          31 bloqueios
  185.220.101.45       28 bloqueios
  ...

=== BASE DE DADOS: 182 eventos totais ===
```

> Correr uma segunda vez — o total da BD deve duplicar (364), porque insere novamente os mesmos eventos.

---

### Step 5 — `tests/test_storage.py`

```python
from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from src.db.storage import EventStorage
from src.models.log_entry import LogEntry


def _make_entry(action: str = "block", src_ip: str = "1.2.3.4",
                dst_port: int = 22) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 9, 17, 10, 0, 0),
        action=action,
        interface="em0",
        protocol="tcp",
        src_ip=src_ip,
        src_port=54321,
        dst_ip="192.168.10.50",
        dst_port=dst_port,
    )


@pytest.fixture
def storage(tmp_path: Path) -> EventStorage:
    return EventStorage(tmp_path / "test.db")


class TestInsert:
    def test_insert_returns_id(self, storage: EventStorage) -> None:
        entry_id = storage.insert(_make_entry())
        assert entry_id == 1

    def test_count_after_insert(self, storage: EventStorage) -> None:
        storage.insert(_make_entry())
        storage.insert(_make_entry())
        assert storage.count() == 2

    def test_insert_many(self, storage: EventStorage) -> None:
        entries = [_make_entry() for _ in range(5)]
        inserted = storage.insert_many(entries)
        assert inserted == 5
        assert storage.count() == 5

    def test_insert_many_empty(self, storage: EventStorage) -> None:
        assert storage.insert_many([]) == 0


class TestQueries:
    def test_recent_returns_list(self, storage: EventStorage) -> None:
        storage.insert(_make_entry())
        rows = storage.recent(10)
        assert len(rows) == 1

    def test_top_blocked_ips(self, storage: EventStorage) -> None:
        storage.insert(_make_entry(src_ip="1.1.1.1"))
        storage.insert(_make_entry(src_ip="1.1.1.1"))
        storage.insert(_make_entry(src_ip="2.2.2.2"))
        rows = storage.top_blocked_ips(5)
        assert rows[0]["src_ip"] == "1.1.1.1"
        assert rows[0]["total"] == 2

    def test_stats(self, storage: EventStorage) -> None:
        storage.insert(_make_entry(action="block"))
        storage.insert(_make_entry(action="pass"))
        s = storage.stats()
        assert s["total"] == 2
        assert s["blocked"] == 1
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 64 + 9 = 73 testes a passar

ruff check src/
mypy src/db/storage.py --strict

git add src/db/__init__.py src/db/storage.py \
        scripts/generate_test_log.py scripts/ingest_log.py \
        tests/test_storage.py
git commit -m "feat: dia 7 — SQLite storage e pipeline ingest log→BD"
```

---

## Checklist

- [ ] `src/db/__init__.py` criado
- [ ] `src/db/storage.py` — `EventStorage` com `insert`, `insert_many`, `count`, `recent`, `top_blocked_ips`, `stats`
- [ ] `scripts/generate_test_log.py` — gera 200 linhas de log realistas
- [ ] `scripts/ingest_log.py` — lê ficheiro, parseia, persiste, imprime sumário
- [ ] `tests/test_storage.py` — 9 testes passando
- [ ] `python -m pytest tests/ -v` → 73 passed
- [ ] `ruff check src/` sem erros
- [ ] Correr `ingest_log.py` duas vezes e confirmar que BD duplica
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/db/__init__.py` | Package db |
| `src/db/storage.py` | EventStorage — CRUD SQLite para LogEntry |
| `scripts/generate_test_log.py` | Gera ficheiro de log pfSense de teste |
| `scripts/ingest_log.py` | Pipeline: log → parse → SQLite → sumário |
| `tests/test_storage.py` | 9 testes de storage |

**Conceitos:**

| Conceito | Aplicação |
|---|---|
| `sqlite3` | Criar tabela, inserir, query |
| `@contextmanager` | Gerir ligação SQLite com auto-commit |
| `conn.row_factory = sqlite3.Row` | Aceder a colunas por nome (`row['src_ip']`) |
| `executemany()` | Inserção em batch — mais rápido que N inserts |
| `pathlib.Path` | Caminhos de ficheiro type-safe |
| Generator expression | `sum(1 for e in entries if e.is_high_priority)` |

**Próximo dia:** Dia 8 — suporte IPv6 no parser + regex avançado
