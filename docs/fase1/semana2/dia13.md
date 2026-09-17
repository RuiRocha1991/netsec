# Dia 13 — GeoIP com MaxMind GeoLite2

**Fase:** 1 · **Semana:** 2 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura: pfSense com zonas GREEN(192.168.10.x)/IOT(40.x)/DMZ(30.x).

Dias 1-12 concluídos. Estado do projecto:
- src/parsers/pfsense_parser.py — IPv4+IPv6
- src/parsers/syslog_server.py — servidor UDP
- src/db/storage.py — EventStorage SQLite com queries analíticas
- src/analyzers/rule_engine.py — RuleEngine YAML
- src/analyzers/threat_intel.py — AbuseIPDB com cache
- tests/: 99 testes, todos a passar
- Packages: pyshark, pandas, pyyaml, requests, python-dotenv

Quero continuar para o Dia 13: GeoIP com MaxMind GeoLite2 — enriquecer IPs
externos com país e cidade offline (sem API calls).
```

---

## Objectivo

A AbuseIPDB devolve o país, mas tem limite de 1000 queries/dia. O MaxMind GeoLite2 é uma base de dados local (ficheiro .mmdb) que resolve GeoIP offline — ilimitado e instantâneo.

**Vantagem:** uma vez descarregado o ficheiro, zero latência e zero limite de queries.

```
IP externo → GeoLite2 Country DB (local) → país em <1ms
```

**Registo obrigatório:** maxmind.com/en/geolite2 (gratuito) → download `GeoLite2-Country.mmdb`

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `geoip2` library | Interface Python para ficheiros .mmdb MaxMind |
| `.mmdb` format | Base de dados binária MaxMind — leitura muito rápida |
| `geoip2.errors.AddressNotFoundError` | IP não encontrado na base (redes privadas, etc.) |
| `functools.lru_cache` | Cache em memória por IP — evitar re-leituras do ficheiro |
| `Path.exists()` | Verificar se o ficheiro mmdb foi descarregado |

---

## Steps

### Step 1 — Instalar geoip2 e descarregar base de dados

```bash
pip install geoip2
```

Adicionar ao `pyproject.toml`:
```toml
analysis = ["pandas", "pyyaml", "requests", "python-dotenv", "geoip2"]
```

**Descarregar o ficheiro GeoLite2:**

1. Registar em maxmind.com/en/geolite2 (gratuito)
2. Download → GeoLite2 Country → formato GZIP
3. Extrair o ficheiro `.mmdb`:

```bash
mkdir -p data/geoip
# substituir pelo caminho real do download:
tar -xzf ~/Downloads/GeoLite2-Country_*.tar.gz -C /tmp/
cp /tmp/GeoLite2-Country_*/GeoLite2-Country.mmdb data/geoip/

ls -lh data/geoip/GeoLite2-Country.mmdb
# deve mostrar ~7MB
```

Adicionar ao `.gitignore` (ficheiro grande e com actualizações mensais):
```bash
echo "data/geoip/*.mmdb" >> .gitignore
```

Adicionar ao `.env.example`:
```
GEOIP_DB_PATH=data/geoip/GeoLite2-Country.mmdb
```

---

### Step 2 — `src/analyzers/geoip.py`

```python
from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path

import geoip2.database
import geoip2.errors

logger = logging.getLogger(__name__)

_DEFAULT_DB = Path(os.getenv("GEOIP_DB_PATH", "data/geoip/GeoLite2-Country.mmdb"))


class GeoIP:
    """Resolve país e continente de um IP usando MaxMind GeoLite2 (offline)."""

    def __init__(self, db_path: Path = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._reader: geoip2.database.Reader | None = None
        if not db_path.exists():
            logger.warning(
                "GeoLite2 não encontrado em %s — GeoIP desactivado. "
                "Ver docs/fase1/semana2/dia13.md para instruções de download.",
                db_path,
            )

    def _get_reader(self) -> geoip2.database.Reader | None:
        if self._reader is None and self.db_path.exists():
            self._reader = geoip2.database.Reader(str(self.db_path))
        return self._reader

    @lru_cache(maxsize=4096)
    def country_code(self, ip: str) -> str | None:
        """Devolve código ISO do país (ex: 'PT', 'RU') ou None."""
        reader = self._get_reader()
        if reader is None:
            return None
        try:
            response = reader.country(ip)
            return response.country.iso_code
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception as exc:
            logger.debug("GeoIP erro para %s: %s", ip, exc)
            return None

    @lru_cache(maxsize=4096)
    def country_name(self, ip: str) -> str | None:
        """Devolve nome do país em inglês ou None."""
        reader = self._get_reader()
        if reader is None:
            return None
        try:
            response = reader.country(ip)
            return response.country.name
        except (geoip2.errors.AddressNotFoundError, Exception):
            return None

    def enrich(self, ip: str) -> dict[str, str | None]:
        """Devolve dict com geo_country para integrar no LogEntry."""
        return {"geo_country": self.country_code(ip)}

    def close(self) -> None:
        if self._reader:
            self._reader.close()
            self._reader = None
```

---

### Step 3 — Integrar GeoIP no `ThreatIntel`

Actualizar `src/analyzers/threat_intel.py` para combinar AbuseIPDB + GeoIP:

```python
# Adicionar ao __init__:
from src.analyzers.geoip import GeoIP
# ...
self.geoip = GeoIP()

# Actualizar enrich():
def enrich(self, ip: str) -> dict[str, int | str | None]:
    """Combina AbuseIPDB score + GeoIP país."""
    score, abuse_country = self.check_ip(ip)
    # Preferir GeoIP local (offline, mais rápido) para o país
    geo_country = self.geoip.country_code(ip) or abuse_country
    return {"abuse_score": score, "geo_country": geo_country}
```

---

### Step 4 — `tests/test_geoip.py`

```python
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.analyzers.geoip import GeoIP


@pytest.fixture
def geoip_no_db(tmp_path: Path) -> GeoIP:
    """GeoIP sem ficheiro mmdb — simula ambiente sem download."""
    return GeoIP(db_path=tmp_path / "nonexistent.mmdb")


class TestGeoIPNoDb:
    def test_country_code_returns_none_without_db(self, geoip_no_db: GeoIP) -> None:
        result = geoip_no_db.country_code("1.2.3.4")
        assert result is None

    def test_enrich_returns_none_without_db(self, geoip_no_db: GeoIP) -> None:
        result = geoip_no_db.enrich("1.2.3.4")
        assert result == {"geo_country": None}


class TestGeoIPWithMock:
    def test_country_code_from_reader(self, tmp_path: Path) -> None:
        geoip = GeoIP(db_path=tmp_path / "fake.mmdb")
        # Simular que o ficheiro existe e o reader devolve resultado
        mock_response = MagicMock()
        mock_response.country.iso_code = "PT"
        mock_reader = MagicMock()
        mock_reader.country.return_value = mock_response
        geoip._reader = mock_reader
        # Criar ficheiro vazio para o Path.exists() passar
        (tmp_path / "fake.mmdb").touch()
        result = geoip.country_code("1.2.3.4")
        assert result == "PT"

    def test_address_not_found_returns_none(self, tmp_path: Path) -> None:
        import geoip2.errors
        geoip = GeoIP(db_path=tmp_path / "fake.mmdb")
        mock_reader = MagicMock()
        mock_reader.country.side_effect = geoip2.errors.AddressNotFoundError("")
        geoip._reader = mock_reader
        (tmp_path / "fake.mmdb").touch()
        result = geoip.country_code("192.168.1.1")
        assert result is None

    def test_lru_cache_avoids_repeat_reads(self, tmp_path: Path) -> None:
        geoip = GeoIP(db_path=tmp_path / "fake.mmdb")
        mock_response = MagicMock()
        mock_response.country.iso_code = "DE"
        mock_reader = MagicMock()
        mock_reader.country.return_value = mock_response
        geoip._reader = mock_reader
        (tmp_path / "fake.mmdb").touch()
        geoip.country_code("8.8.8.8")
        geoip.country_code("8.8.8.8")  # segunda chamada — deve usar cache
        assert mock_reader.country.call_count == 1  # só chamado uma vez
```

---

### Step 5 — Testar com base de dados real (se disponível)

```bash
python -c "
from src.analyzers.geoip import GeoIP
geo = GeoIP()
test_ips = [
    ('8.8.8.8',        'EUA'),
    ('185.220.101.45', 'Nó Tor — provavelmente DE'),
    ('1.2.3.4',        'APNIC'),
    ('192.168.10.1',   'Privado — deve devolver None'),
]
for ip, esperado in test_ips:
    code = geo.country_code(ip)
    name = geo.country_name(ip)
    print(f'{ip:<20} → {str(code):4} {str(name):20} ({esperado})')
"
```

---

### Step 6 — Actualizar `scripts/analyze_logs.py` com dados GeoIP

Adicionar secção ao script:

```python
# No final do main():
print("\n=== TOP PAÍSES DE ATAQUE ===")
country_blocks = (
    df[df["action"] == "block"]
    .groupby("geo_country")["id"]
    .count()
    .sort_values(ascending=False)
    .head(10)
)
for country, count in country_blocks.items():
    flag = country if country else "??"
    print(f"  {flag:<5} {count:4d}")
```

---

### Step 7 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 99 + 4 = 103 testes

ruff check src/
git add src/analyzers/geoip.py tests/test_geoip.py \
        src/analyzers/threat_intel.py .gitignore .env.example pyproject.toml
git commit -m "feat: dia 13 — GeoIP MaxMind GeoLite2 offline com lru_cache"
```

---

## Checklist

- [ ] `geoip2` instalado
- [ ] `data/geoip/GeoLite2-Country.mmdb` descarregado (se conta MaxMind criada)
- [ ] `GeoIP` implementado com `lru_cache` e graceful handling sem ficheiro
- [ ] `ThreatIntel.enrich()` combina AbuseIPDB + GeoIP
- [ ] 4 testes a passar com mocks (funciona sem ficheiro mmdb)
- [ ] `python -m pytest tests/ -v` → 103 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/analyzers/geoip.py` | GeoIP com lru_cache, graceful sem DB |
| `tests/test_geoip.py` | 4 testes com mocks |
| `src/analyzers/threat_intel.py` | Enrich combina AbuseIPDB + GeoIP |
| `data/geoip/` | Pasta para o ficheiro .mmdb (não vai para git) |

**Próximo dia:** Dia 14 — pipeline completo Semana 2 e revisão geral
