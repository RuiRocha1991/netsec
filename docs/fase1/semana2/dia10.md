# Dia 10 — Queries SQLite avançadas + Pandas

**Fase:** 1 · **Semana:** 2 · **Estado:** ✅ Concluído

---

## Prompt de contexto

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura: pfSense com zonas GREEN(192.168.10.x)/IOT(40.x)/DMZ(30.x).

Dias 1-9 concluídos. Estado do projecto:
- src/parsers/pfsense_parser.py — parse_line() IPv4+IPv6, parse_file()
- src/parsers/syslog_server.py — SyslogServer UDP com threading + queue
- src/db/storage.py — EventStorage SQLite, insert_many(), top_blocked_ips(), stats()
- scripts/: ingest_log.py, generate_test_log.py, run_syslog_server.py, send_test_syslog.py
- tests/: 81 testes, todos a passar
- Packages: pyshark

Quero continuar para o Dia 10: queries SQLite avançadas e análise com Pandas.
```

---

## Objectivo

Adicionar queries analíticas ao `EventStorage` e usar Pandas para análise exploratória dos logs:

- Top IPs atacantes por zona de origem
- Distribuição de protocolos e portos
- Timeline de ataques por hora
- Detecção simples de port scan (muitos portos diferentes do mesmo IP)

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `pandas.read_sql()` | Carregar resultado de query SQL num DataFrame |
| `DataFrame.groupby()` | Agrupar e agregar — equivalente ao GROUP BY SQL |
| `DataFrame.pivot_table()` | Tabela cruzada — e.g. protocolo × acção |
| `DataFrame.resample()` | Agrupar por intervalo de tempo (hora, minuto) |
| `strftime` em SQL | `strftime('%H', timestamp)` para agrupar por hora |

---

## Steps

### Step 1 — Instalar Pandas

```bash
pip install pandas
pip freeze | grep pandas >> /dev/null
# adicionar ao pyproject.toml
```

Adicionar ao `pyproject.toml` em `[project.optional-dependencies]`:
```toml
analysis = ["pandas"]
```

---

### Step 2 — Adicionar queries a `src/db/storage.py`

Adicionar os métodos seguintes à classe `EventStorage`:

```python
def events_by_hour(self) -> list[sqlite3.Row]:
    """Contagem de bloqueios agrupada por hora do dia."""
    with self._conn() as conn:
        return conn.execute("""
            SELECT
                strftime('%H', timestamp) AS hour,
                COUNT(*) AS total,
                SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) AS blocked
            FROM events
            GROUP BY hour
            ORDER BY hour
        """).fetchall()

def top_targeted_ports(self, limit: int = 10) -> list[sqlite3.Row]:
    """Portos destino mais atacados (apenas bloqueios externos)."""
    with self._conn() as conn:
        return conn.execute("""
            SELECT dst_port, COUNT(*) AS total
            FROM events
            WHERE action = 'block'
              AND src_zone = 'EXTERNAL'
              AND dst_port > 0
            GROUP BY dst_port
            ORDER BY total DESC
            LIMIT ?
        """, (limit,)).fetchall()

def protocol_breakdown(self) -> list[sqlite3.Row]:
    """Distribuição de protocolos — contagem por protocolo e acção."""
    with self._conn() as conn:
        return conn.execute("""
            SELECT protocol, action, COUNT(*) AS total
            FROM events
            GROUP BY protocol, action
            ORDER BY total DESC
        """).fetchall()

def potential_port_scans(self, threshold: int = 10) -> list[sqlite3.Row]:
    """IPs que tentaram mais de N portos distintos — indício de port scan."""
    with self._conn() as conn:
        return conn.execute("""
            SELECT src_ip, COUNT(DISTINCT dst_port) AS unique_ports, COUNT(*) AS total
            FROM events
            WHERE action = 'block'
              AND src_zone = 'EXTERNAL'
            GROUP BY src_ip
            HAVING unique_ports >= ?
            ORDER BY unique_ports DESC
        """, (threshold,)).fetchall()

def as_dataframe(self):  # type: ignore[return]
    """Carrega todos os eventos num DataFrame Pandas."""
    import sqlite3
    import pandas as pd
    conn = sqlite3.connect(self.db_path)
    df = pd.read_sql(
        "SELECT * FROM events ORDER BY timestamp",
        conn,
        parse_dates=["timestamp"],
    )
    conn.close()
    return df
```

---

### Step 3 — `scripts/analyze_logs.py`

Script de análise exploratória:

```python
from __future__ import annotations

import pandas as pd

from src.db.storage import EventStorage


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
        print(f"\nPOSSÍVEIS PORT SCANS (≥5 portos distintos):")
        for row in scans:
            print(f"  {row['src_ip']:<20} {row['unique_ports']:3d} portos únicos  ({row['total']} tentativas)")
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
```

```bash
# Garantir que há dados na BD:
python scripts/ingest_log.py

# Correr análise:
python scripts/analyze_logs.py
```

Output esperado:
```
=== ANÁLISE DE 182 EVENTOS ===

TOP 10 PORTOS ATACADOS:
  Porto    22    31  ███████████████
  Porto  3389    28  ██████████████
  ...

POSSÍVEIS PORT SCANS:
  203.0.113.1          7 portos únicos  (31 tentativas)
```

---

### Step 4 — Testes para as novas queries

Adicionar ao `tests/test_storage.py`:

```python
class TestAnalyticsQueries:
    def test_top_targeted_ports(self, storage: EventStorage) -> None:
        storage.insert(_make_entry(dst_port=22))
        storage.insert(_make_entry(dst_port=22))
        storage.insert(_make_entry(dst_port=3389))
        rows = storage.top_targeted_ports(5)
        assert rows[0]["dst_port"] == 22
        assert rows[0]["total"] == 2

    def test_protocol_breakdown(self, storage: EventStorage) -> None:
        storage.insert(_make_entry())
        rows = storage.protocol_breakdown()
        assert len(rows) >= 1
        assert rows[0]["protocol"] == "tcp"

    def test_potential_port_scans_detected(self, storage: EventStorage) -> None:
        # mesmo IP, 6 portos distintos
        for port in [22, 23, 80, 443, 3389, 8080]:
            storage.insert(_make_entry(dst_port=port))
        scans = storage.potential_port_scans(threshold=5)
        assert len(scans) == 1
        assert scans[0]["unique_ports"] == 6

    def test_potential_port_scans_below_threshold(self, storage: EventStorage) -> None:
        for port in [22, 23]:
            storage.insert(_make_entry(dst_port=port))
        scans = storage.potential_port_scans(threshold=5)
        assert len(scans) == 0

    def test_as_dataframe(self, storage: EventStorage) -> None:
        import pandas as pd
        storage.insert(_make_entry())
        df = storage.as_dataframe()
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 1
        assert "src_ip" in df.columns
```

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 81 + 5 = 86 testes

ruff check src/
git add src/db/storage.py scripts/analyze_logs.py tests/test_storage.py pyproject.toml
git commit -m "feat: dia 10 — queries analíticas SQLite e análise Pandas"
```

---

## Checklist

- [x] Pandas instalado e em `pyproject.toml`
- [x] 4 métodos novos em `EventStorage`: `events_by_hour`, `top_targeted_ports`, `protocol_breakdown`, `potential_port_scans`
- [x] `as_dataframe()` carrega eventos em DataFrame
- [x] `scripts/analyze_logs.py` corre e mostra output com tabelas e barras
- [x] Port scans detectados no ficheiro de teste
- [x] 5 testes novos a passar
- [x] `python -m pytest tests/ -v` → 84 passed
- [x] Git commit realizado

---

## Resumo — alterações feitas

**Ficheiros alterados/criados:**

| Ficheiro | Descrição |
|---|---|
| `src/db/storage.py` | +4 queries analíticas + `as_dataframe()` |
| `scripts/analyze_logs.py` | Análise exploratória com tabelas e Pandas |
| `tests/test_storage.py` | +5 testes de queries analíticas |
| `pyproject.toml` | Dependência pandas |

**Próximo dia:** Dia 11 — motor de regras YAML — alertas configuráveis sem alterar código
