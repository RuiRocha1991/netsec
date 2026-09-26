# Dia 13 — GeoIP com MaxMind GeoLite2

**Fase:** 1 · **Semana:** 2 · **Estado:** 🔄 Em curso

---

## Prompt de contexto

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura: pfSense com zonas GREEN(192.168.10.x)/IOT(40.x)/DMZ(30.x).

Dias 1-12 concluídos. Estado do projecto:
- src/parsers/pfsense_parser.py — parse_line() IPv4+IPv6
- src/parsers/syslog_server.py — servidor UDP + motor de regras
- src/db/storage.py — EventStorage SQLite com queries analíticas
- src/analyzers/rule_engine.py — RuleEngine YAML
- src/analyzers/threat_intel.py — ThreatIntel: AbuseIPDB + cache SQLite (TTL 24h)
- data/rules.yaml — 6 regras configuradas
- tests/: 97 testes, todos a passar
- Packages: pyshark, pandas, pyyaml, requests, python-dotenv

LogEntry tem campos abuse_score (int | None) e geo_country (str | None).
O ThreatIntel.enrich() já preenche geo_country com o código ISO do país
via AbuseIPDB. Mas para obter cidade, ASN e coordenadas precisamos da
base de dados GeoLite2 da MaxMind (offline, sem quota).

Quero continuar para o Dia 13: GeoIP com MaxMind GeoLite2 para enriquecer
IPs com país, cidade e ASN sem depender de chamadas à API.
```

---

## Objectivo

Enriquecer `LogEntry` com localização geográfica completa (país, cidade, ASN)
usando a base de dados local GeoLite2 da MaxMind:

- Dado um IP externo, determinar país + cidade + ASN/ISP **offline**, sem quota
- Integrar com `ThreatIntel`: um único `enrich()` devolve score *e* geo
- Actualizar `LogEntry` com campos `geo_city` e `geo_asn`
- Integrar no pipeline `ingest_log.py`

**Porque importa para o NetGuard AI:** saber que um IP é da Rússia (AbuseIPDB)
é diferente de saber que é de um datacenter em Moscovo pertencente ao AS12389
(Rostelecom) — essa granularidade permite ao LLM gerar alertas muito mais
contextualizados: *"IP 185.220.x.x — Tor exit node, AS4766, Rússia, score 98,
tentou SSH na DMZ"*. Além disso, a GeoLite2 funciona **offline** — não consome
quota, não tem latência de rede, não há risco de o serviço estar em baixo.

---

## Como funciona

**GeoIP = base de dados de mapeamento IP → localização.** A MaxMind mantém
bases de dados pagas (GeoIP2) e gratuitas (GeoLite2). As bases `.mmdb`
(MaxMind DB) são ficheiros binários indexados por prefixo de rede (CIDR):
uma pesquisa é O(log n) — extremamente rápida mesmo com milhões de entradas.

```
IP externo ──► geoip2.database.Reader(GeoCity.mmdb)
                   │
                   ├── país   (ISO 3166-1 alpha-2, ex: "RU")
                   ├── cidade (ex: "Moscow")
                   └── subdivisions[0] (ex: "Moscow")

IP externo ──► geoip2.database.Reader(GeoASN.mmdb)
                   │
                   ├── autonomous_system_number (ex: 12389)
                   └── autonomous_system_organization (ex: "Rostelecom")
```

**Analogia Java:** o `Reader` é como um `javax.persistence.EntityManager` read-only
— abre um ficheiro, mantém-no em memória mapeada, e executa queries rápidas.
É thread-safe e deve ser reutilizado (não criar um por request).

**Porquê offline:**

| Online (AbuseIPDB geo) | Offline (GeoLite2) |
|---|---|
| Score + país incluídos | País + cidade + ASN |
| Latência de rede (5–500ms) | Latência < 1ms (I/O local) |
| Quota 1000/dia | Sem quota |
| Depende da internet | Funciona em air-gap |
| Base actualizada continuamente | Actualizar mensalmente (cron) |

**Trade-offs e limites:**

| Limite | Consequência | Mitigação |
|---|---|---|
| Precisão < 100% ao nível cidade | Cidade errada para IPs de VPN/Tor | Usar como contexto, não como prova |
| `.mmdb` não vai para git (ficheiro grande) | Novo dev precisa de o descarregar | Documentar download no README |
| Licença CC BY-SA 4.0 | Obriga a atribuição se redistribuído | OK para uso interno; atenção em produto público |
| IPs privados não têm geo | `AddressNotFoundError` | `try/except` — devolver `None` |

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `geoip2` library | Pesquisa em ficheiros `.mmdb` |
| Context manager (`with`) para ficheiros binários | `geoip2.database.Reader` |
| `try/except geoip2.errors.AddressNotFoundError` | IPs privados não têm geo |
| `dataclasses.fields()` | Introspecção dos campos de `LogEntry` |
| Atualização incremental de dataclass | `dataclasses.replace()` com múltiplos campos |

---

## Steps

### Step 1 — Registar e descarregar GeoLite2

1. Criar conta gratuita em [maxmind.com](https://www.maxmind.com/en/geolite2/signup)
2. Em *My Account → GeoIP2 / GeoLite2 → Download Files* descarregar:
   - `GeoLite2-City.mmdb` (localidade)
   - `GeoLite2-ASN.mmdb` (ASN/ISP)
3. Colocar em `data/geoip/`:

```bash
mkdir -p data/geoip
# Copiar os ficheiros .mmdb para data/geoip/
```

> Os ficheiros `.mmdb` **não vão para git** — já estão no `.gitignore` via `data/`.

---

### Step 2 — Instalar package

```bash
pip install geoip2
```

Adicionar ao `pyproject.toml` (secção `analysis`):
```toml
analysis = ["pandas", "pyyaml", "requests", "python-dotenv", "geoip2"]
```

---

### Step 3 — `src/analyzers/geo_lookup.py`

```python
from __future__ import annotations

import logging
from pathlib import Path

import geoip2.database
import geoip2.errors

logger = logging.getLogger(__name__)

_GEO_DIR  = Path("data/geoip")
_CITY_DB  = _GEO_DIR / "GeoLite2-City.mmdb"
_ASN_DB   = _GEO_DIR / "GeoLite2-ASN.mmdb"


class GeoLookup:
    """Pesquisa offline de país, cidade e ASN usando GeoLite2."""

    def __init__(
        self,
        city_db: Path = _CITY_DB,
        asn_db: Path  = _ASN_DB,
    ) -> None:
        self._city_reader: geoip2.database.Reader | None = None
        self._asn_reader:  geoip2.database.Reader | None = None
        if city_db.exists():
            self._city_reader = geoip2.database.Reader(str(city_db))
        else:
            logger.warning("GeoLite2-City.mmdb não encontrado em %s", city_db)
        if asn_db.exists():
            self._asn_reader = geoip2.database.Reader(str(asn_db))
        else:
            logger.warning("GeoLite2-ASN.mmdb não encontrado em %s", asn_db)

    def lookup(self, ip: str) -> dict[str, str | int | None]:
        """Devolve dict com country, city, asn_number, asn_org para um IP."""
        result: dict[str, str | int | None] = {
            "geo_country": None,
            "geo_city": None,
            "geo_asn": None,
        }
        if self._city_reader is not None:
            try:
                city = self._city_reader.city(ip)
                result["geo_country"] = city.country.iso_code
                result["geo_city"]    = city.city.name
            except geoip2.errors.AddressNotFoundError:
                pass  # IP privado ou não catalogado
        if self._asn_reader is not None:
            try:
                asn = self._asn_reader.asn(ip)
                result["geo_asn"] = (
                    f"AS{asn.autonomous_system_number} {asn.autonomous_system_organization}"
                )
            except geoip2.errors.AddressNotFoundError:
                pass
        return result

    def close(self) -> None:
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()

    def __enter__(self) -> GeoLookup:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
```

---

### Step 4 — Actualizar `LogEntry` com novos campos

Abrir `src/models/log_entry.py` e adicionar dois campos opcionais:

```python
geo_city: str | None = None
geo_asn:  str | None = None
```

(junto a `abuse_score` e `geo_country` já existentes)

---

### Step 5 — Integrar em `ThreatIntel.enrich()`

Actualizar `src/analyzers/threat_intel.py` para receber o resultado da
`GeoLookup` e fundir com o score da AbuseIPDB:

```python
from src.analyzers.geo_lookup import GeoLookup

# No __init__:
self.geo = GeoLookup()

# No enrich():
def enrich(self, ip: str) -> dict[str, int | str | None]:
    score, country = self.check_ip(ip)
    geo = self.geo.lookup(ip)
    return {
        "abuse_score": score,
        "geo_country": country or geo["geo_country"],
        "geo_city":    geo["geo_city"],
        "geo_asn":     geo["geo_asn"],
    }
```

> `country or geo["geo_country"]` — preferimos o país da AbuseIPDB (já
> disponível da query anterior); se não houver, usamos o da GeoLite2.

---

### Step 6 — Actualizar `ingest_log.py`

O pipeline já chama `intel.enrich()` — só precisa de passar também `geo_city`
e `geo_asn` ao `dataclasses.replace()`:

```python
enriched_data = intel.enrich(entry.src_ip)
entry = dataclasses.replace(entry, **enriched_data)
```

---

### Step 7 — `tests/test_geo_lookup.py`

```python
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.analyzers.geo_lookup import GeoLookup


class TestGeoLookup:
    def test_returns_none_when_no_db(self, tmp_path: Path) -> None:
        geo = GeoLookup(
            city_db=tmp_path / "nonexistent.mmdb",
            asn_db=tmp_path  / "nonexistent.mmdb",
        )
        result = geo.lookup("1.2.3.4")
        assert result["geo_country"] is None
        assert result["geo_city"]    is None
        assert result["geo_asn"]     is None

    def test_city_lookup_mocked(self) -> None:
        mock_city = MagicMock()
        mock_city.country.iso_code = "RU"
        mock_city.city.name        = "Moscow"

        geo = GeoLookup.__new__(GeoLookup)
        geo._city_reader = MagicMock()
        geo._city_reader.city.return_value = mock_city
        geo._asn_reader  = None

        result = geo.lookup("185.220.101.45")
        assert result["geo_country"] == "RU"
        assert result["geo_city"]    == "Moscow"
        assert result["geo_asn"]     is None

    def test_asn_lookup_mocked(self) -> None:
        mock_asn = MagicMock()
        mock_asn.autonomous_system_number       = 12389
        mock_asn.autonomous_system_organization = "Rostelecom"

        geo = GeoLookup.__new__(GeoLookup)
        geo._city_reader = None
        geo._asn_reader  = MagicMock()
        geo._asn_reader.asn.return_value = mock_asn

        result = geo.lookup("185.220.101.45")
        assert result["geo_asn"] == "AS12389 Rostelecom"

    def test_private_ip_returns_none(self) -> None:
        import geoip2.errors

        geo = GeoLookup.__new__(GeoLookup)
        geo._city_reader = MagicMock()
        geo._city_reader.city.side_effect = geoip2.errors.AddressNotFoundError("")
        geo._asn_reader  = None

        result = geo.lookup("192.168.1.1")
        assert result["geo_country"] is None
```

---

### Step 8 — Verificar com ficheiros reais (opcional)

```bash
python -c "
from src.analyzers.geo_lookup import GeoLookup
with GeoLookup() as geo:
    result = geo.lookup('185.220.101.45')
    print(result)
"
# Esperado (com .mmdb descarregados):
# {'geo_country': 'DE', 'geo_city': 'Frankfurt', 'geo_asn': 'AS4766 ...'}
```

---

### Step 9 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 97 + 4 = 101 testes

ruff check src/
git add src/analyzers/geo_lookup.py src/models/log_entry.py \
        src/analyzers/threat_intel.py scripts/ingest_log.py \
        tests/test_geo_lookup.py pyproject.toml
git commit -m "feat: dia 13 — GeoIP com MaxMind GeoLite2 (cidade + ASN offline)"
```

---

## Onde inova

Os operadores telecom sabem que um IP é externo. O NetGuard AI sabe que é
`AS12389 Rostelecom, Moscovo, score 98, 1.2k reports` — e o LLM consegue
explicar ao cliente: *"Este IP pertence a uma rede russa com longa história
de ataques SSH. O bloqueio foi automático."*

- **Contexto rico ao LLM (Semana 8):** país + cidade + ASN entram no prompt —
  o relatório deixa de ser genérico
- **Feature engineering para ML (Semana 6):** ASN é um sinal forte — alguns
  AS são sistematicamente abusivos
- **Funciona offline:** num cliente sem internet estável (fábrica, barco),
  a geo continua a funcionar

---

## Checklist

- [ ] Conta MaxMind criada e `.mmdb` descarregados para `data/geoip/`
- [ ] `geoip2` instalado e em `pyproject.toml`
- [ ] `GeoLookup` implementado com `city` e `asn`
- [ ] `LogEntry` actualizado com `geo_city` e `geo_asn`
- [ ] `ThreatIntel.enrich()` funde AbuseIPDB + GeoLite2
- [ ] 4 testes com mocks a passar (sem precisar dos `.mmdb`)
- [ ] `python -m pytest tests/ -v` → 101 passed
- [ ] `ruff check src/` sem erros
- [ ] (Opcional) Testado com ficheiros reais — IP externo retorna cidade
- [ ] Consegues explicar por palavras tuas a diferença entre GeoLite2 e AbuseIPDB?
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/analyzers/geo_lookup.py` | `GeoLookup` — pesquisa offline cidade + ASN |
| `src/models/log_entry.py` | Novos campos `geo_city`, `geo_asn` |
| `src/analyzers/threat_intel.py` | `enrich()` funde AbuseIPDB + GeoLite2 |
| `scripts/ingest_log.py` | Pipeline passa todos os campos de enrich() |
| `tests/test_geo_lookup.py` | 4 testes com mocks |

**O que aprendeste:** *(preencher após conclusão)*

**Exercício de reflexão:** o `GeoLookup` abre os ficheiros `.mmdb` no
`__init__` e mantém-nos abertos. Que vantagem tem isso face a abrir o
ficheiro em cada `lookup()`? Em que situação poderia ser um problema?
(Dica: pensa em memória RAM e em ficheiros actualizados por um cron job.)

**Próximo dia:** Dia 14 — Anomaly detection com Isolation Forest (ML)
