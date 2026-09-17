# Dia 12 — AbuseIPDB — threat intelligence

**Fase:** 1 · **Semana:** 2 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura: pfSense com zonas GREEN(192.168.10.x)/IOT(40.x)/DMZ(30.x).

Dias 1-11 concluídos. Estado do projecto:
- src/parsers/pfsense_parser.py — parse_line() IPv4+IPv6
- src/parsers/syslog_server.py — servidor UDP + motor de regras
- src/db/storage.py — EventStorage SQLite com queries analíticas
- src/analyzers/rule_engine.py — RuleEngine YAML
- data/rules.yaml — 6 regras configuradas
- tests/: 94 testes, todos a passar
- Packages: pyshark, pandas, pyyaml

Quero continuar para o Dia 12: integração com AbuseIPDB para enriquecer IPs
externos com score de reputação.
```

---

## Objectivo

Enriquecer `LogEntry.abuse_score` com dados reais da API AbuseIPDB:

- Dado um IP externo, consultar a API e obter o `abuseConfidenceScore` (0–100)
- Cache local em SQLite para não repetir queries (limite free: 1000/dia)
- Integrar no pipeline: ao parsear uma linha, enriquecer o IP de origem

**AbuseIPDB free tier:** 1000 queries/dia · necessita registo em abuseipdb.com

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `requests` library | Chamadas HTTP à API REST |
| `python-dotenv` | Carregar API keys de `.env` sem hardcode |
| `os.getenv()` | Ler variáveis de ambiente |
| Cache com SQLite | Tabela `ip_cache` para evitar queries repetidas |
| `time.time()` | TTL da cache — só re-consultar após N horas |
| `requests.Session` | Reutilizar ligação HTTP — mais eficiente em volume |

---

## Steps

### Step 1 — Instalar packages e configurar API key

```bash
pip install requests python-dotenv
```

Adicionar ao `pyproject.toml`:
```toml
analysis = ["pandas", "pyyaml", "requests", "python-dotenv"]
```

Criar `.env` (nunca commitar — já está no `.gitignore`):
```bash
cp .env.example .env
# editar .env e preencher:
# ABUSEIPDB_API_KEY=coloca_aqui_a_tua_key
```

Registar em [abuseipdb.com](https://www.abuseipdb.com/) → Account → API → Create Key

---

### Step 2 — `src/analyzers/threat_intel.py`

```python
from __future__ import annotations

import logging
import os
import sqlite3
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_API_URL  = "https://api.abuseipdb.com/api/v2/check"
_CACHE_DB = Path("data/ip_cache.db")
_TTL_SECS = 24 * 3600  # re-consultar após 24h


class ThreatIntel:
    """Consulta AbuseIPDB e mantém cache local em SQLite."""

    def __init__(
        self,
        api_key: str | None = None,
        cache_path: Path = _CACHE_DB,
    ) -> None:
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "")
        self.cache_path = cache_path
        self.session = requests.Session()
        self.session.headers["Key"] = self.api_key
        self.session.headers["Accept"] = "application/json"
        self._init_cache()

    # ── Cache ──────────────────────────────────────────────────────────────

    def _init_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with self._cache_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ip_cache (
                    ip           TEXT PRIMARY KEY,
                    abuse_score  INTEGER NOT NULL,
                    country_code TEXT,
                    queried_at   REAL NOT NULL
                )
            """)

    def _cache_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.cache_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _get_cached(self, ip: str) -> sqlite3.Row | None:
        with self._cache_conn() as conn:
            row = conn.execute(
                "SELECT * FROM ip_cache WHERE ip = ?", (ip,)
            ).fetchone()
        if row and (time.time() - row["queried_at"]) < _TTL_SECS:
            return row
        return None

    def _set_cache(self, ip: str, score: int, country: str | None) -> None:
        with self._cache_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO ip_cache (ip, abuse_score, country_code, queried_at)
                VALUES (?, ?, ?, ?)
            """, (ip, score, country, time.time()))

    # ── API ────────────────────────────────────────────────────────────────

    def check_ip(self, ip: str) -> tuple[int, str | None]:
        """Devolve (abuse_score, country_code). Usa cache se disponível."""
        cached = self._get_cached(ip)
        if cached is not None:
            return cached["abuse_score"], cached["country_code"]

        if not self.api_key:
            logger.warning("ABUSEIPDB_API_KEY não configurada — a usar score 0")
            return 0, None

        try:
            resp = self.session.get(
                _API_URL,
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score   = data.get("abuseConfidenceScore", 0)
            country = data.get("countryCode")
            self._set_cache(ip, score, country)
            logger.debug("AbuseIPDB %s → score=%d country=%s", ip, score, country)
            return score, country
        except requests.RequestException as exc:
            logger.warning("AbuseIPDB erro para %s: %s", ip, exc)
            return 0, None

    def enrich(self, ip: str) -> dict[str, int | str | None]:
        """Devolve dict com abuse_score e geo_country para um IP."""
        score, country = self.check_ip(ip)
        return {"abuse_score": score, "geo_country": country}
```

---

### Step 3 — Integrar no `ingest_log.py`

Actualizar `scripts/ingest_log.py` para enriquecer IPs externos antes de inserir:

```python
from src.analyzers.threat_intel import ThreatIntel
from src.models.network_utils import NetworkZone

# No início do ingest():
intel = ThreatIntel()

# Antes do insert_many, enriquecer IPs externos:
print("A enriquecer IPs externos com AbuseIPDB...")
enriched = 0
for entry in entries:
    if entry.src_zone == NetworkZone.EXTERNAL:
        score, country = intel.check_ip(entry.src_ip)
        # LogEntry é dataclass — usar replace() para criar cópia com campos alterados
        import dataclasses
        entries[entries.index(entry)] = dataclasses.replace(
            entry, abuse_score=score, geo_country=country
        )
        enriched += 1

print(f"  {enriched} IPs externos enriquecidos")
```

---

### Step 4 — `tests/test_threat_intel.py`

```python
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.analyzers.threat_intel import ThreatIntel


@pytest.fixture
def intel(tmp_path: Path) -> ThreatIntel:
    return ThreatIntel(api_key="test_key", cache_path=tmp_path / "cache.db")


class TestThreatIntel:
    def test_no_api_key_returns_zero(self, tmp_path: Path) -> None:
        intel = ThreatIntel(api_key="", cache_path=tmp_path / "cache.db")
        score, country = intel.check_ip("1.2.3.4")
        assert score == 0
        assert country is None

    def test_cache_hit_avoids_api_call(self, intel: ThreatIntel) -> None:
        # Popular a cache manualmente
        intel._set_cache("1.2.3.4", 87, "RU")
        with patch.object(intel.session, "get") as mock_get:
            score, country = intel.check_ip("1.2.3.4")
            mock_get.assert_not_called()
        assert score == 87
        assert country == "RU"

    def test_api_called_when_no_cache(self, intel: ThreatIntel) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {"abuseConfidenceScore": 95, "countryCode": "CN"}
        }
        mock_resp.raise_for_status.return_value = None
        with patch.object(intel.session, "get", return_value=mock_resp):
            score, country = intel.check_ip("5.6.7.8")
        assert score == 95
        assert country == "CN"

    def test_cache_populated_after_api_call(self, intel: ThreatIntel) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {"abuseConfidenceScore": 50, "countryCode": "BR"}
        }
        mock_resp.raise_for_status.return_value = None
        with patch.object(intel.session, "get", return_value=mock_resp):
            intel.check_ip("9.9.9.9")
        # Segunda chamada deve usar cache
        with patch.object(intel.session, "get") as mock_get:
            score, _ = intel.check_ip("9.9.9.9")
            mock_get.assert_not_called()
        assert score == 50

    def test_api_error_returns_zero(self, intel: ThreatIntel) -> None:
        import requests
        with patch.object(intel.session, "get", side_effect=requests.ConnectionError()):
            score, country = intel.check_ip("1.2.3.4")
        assert score == 0
```

---

### Step 5 — Verificar com API real (opcional)

```bash
# Com ABUSEIPDB_API_KEY preenchido no .env:
python -c "
from src.analyzers.threat_intel import ThreatIntel
intel = ThreatIntel()
# IP de teste público com histórico de abuso
score, country = intel.check_ip('185.220.101.45')
print(f'Score: {score}/100  País: {country}')
"
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 94 + 5 = 99 testes

ruff check src/
git add src/analyzers/threat_intel.py tests/test_threat_intel.py pyproject.toml
git commit -m "feat: dia 12 — AbuseIPDB threat intel com cache SQLite"
```

---

## Checklist

- [ ] `requests` e `python-dotenv` instalados
- [ ] `.env` criado com `ABUSEIPDB_API_KEY` (não vai para git)
- [ ] `ThreatIntel` implementado com cache SQLite (TTL 24h)
- [ ] 5 testes com mocks a passar (sem consumir quota da API real)
- [ ] `python -m pytest tests/ -v` → 99 passed
- [ ] `ruff check src/` sem erros
- [ ] (Opcional) Testado com API real — IP conhecido retorna score > 0
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/analyzers/threat_intel.py` | ThreatIntel — AbuseIPDB + cache SQLite |
| `tests/test_threat_intel.py` | 5 testes com mocks |

**Packages:** `requests`, `python-dotenv`

**Próximo dia:** Dia 13 — GeoIP com MaxMind GeoLite2 — enriquecer IPs com país e cidade
