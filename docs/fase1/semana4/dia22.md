# Dia 22 — InfluxDB: conceitos e client Python

**Fase:** 1 · **Semana:** 4 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-21 concluídos — Semana 3 fechada (tag `semana3`). Estado do projecto:
- src/api/ — FastAPI completa com auth API key
- src/parsers/ingest_pipeline.py — pipeline partilhado UDP + webhook
- src/alerts/telegram_notifier.py — alertas Telegram
- src/db/storage.py — EventStorage SQLite (fonte de verdade dos eventos)
- tests/: 145 testes, todos a passar
- Packages: fastapi, uvicorn, pydantic, httpx, requests, python-dotenv,
  pyyaml, geoip2

Quero continuar para o Dia 22: introduzir o InfluxDB como base de dados de
séries temporais para métricas (eventos/min, contagens por zona) — SQLite
fica para os dados relacionais (eventos individuais), InfluxDB para agregados
ao longo do tempo, que é o que o Grafana consome melhor.
```

---

## Objectivo

SQLite guarda eventos individuais — óptimo para queries relacionais (`WHERE src_ip = ...`), mau para "quantos eventos por minuto nas últimas 24h" a escala. Hoje instalamos o InfluxDB (base de dados de séries temporais) e escrevemos o primeiro client Python.

```
EventStorage (SQLite) ── fonte de verdade, queries relacionais
InfluxDB               ── métricas agregadas ao longo do tempo → Grafana
```

Equivalente Java: pensa no InfluxDB como um "Elasticsearch para números ao longo do tempo" — optimizado para `INSERT` em massa e queries por janela temporal, não para joins.

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `influxdb-client` (SDK oficial v2) | Client Python para InfluxDB |
| `Point` builder | Construir um ponto de série temporal (measurement, tags, fields, time) |
| Tags vs Fields | Tags são indexados (para filtrar), fields são os valores numéricos |
| `WriteApi` síncrona vs batching | Escrever ponto a ponto vs em lote |
| Flux query language | Linguagem de query do InfluxDB (diferente de SQL) |

---

## Steps

### Step 1 — Instalar InfluxDB (Docker, mais simples para desenvolvimento)

```bash
docker run -d --name influxdb \
  -p 8086:8086 \
  -v influxdb-data:/var/lib/influxdb2 \
  -e DOCKER_INFLUXDB_INIT_MODE=setup \
  -e DOCKER_INFLUXDB_INIT_USERNAME=admin \
  -e DOCKER_INFLUXDB_INIT_PASSWORD=netguard_dev_pw \
  -e DOCKER_INFLUXDB_INIT_ORG=netguard \
  -e DOCKER_INFLUXDB_INIT_BUCKET=events \
  -e DOCKER_INFLUXDB_INIT_ADMIN_TOKEN=netguard_dev_token_troca_em_producao \
  influxdb:2.7
```

Confirmar: `http://192.168.0.43:8086` (UI web do InfluxDB).

Adicionar ao `.env.example`:
```
INFLUXDB_URL=http://localhost:8086
INFLUXDB_TOKEN=netguard_dev_token_troca_em_producao
INFLUXDB_ORG=netguard
INFLUXDB_BUCKET=events
```

---

### Step 2 — Instalar o client Python

```bash
pip install influxdb-client
```

`pyproject.toml`:
```toml
[project.optional-dependencies]
metrics = ["influxdb-client"]
```

---

### Step 3 — `src/metrics/__init__.py` e `src/metrics/influx_client.py`

```bash
mkdir -p src/metrics
touch src/metrics/__init__.py
```

```python
from __future__ import annotations

import os

from dotenv import load_dotenv
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

load_dotenv()


class MetricsClient:
    """Wrapper fino sobre o client oficial InfluxDB — escrita de pontos."""

    def __init__(
        self,
        url: str | None = None,
        token: str | None = None,
        org: str | None = None,
        bucket: str | None = None,
    ) -> None:
        self.url = url or os.getenv("INFLUXDB_URL", "http://localhost:8086")
        self.token = token or os.getenv("INFLUXDB_TOKEN", "")
        self.org = org or os.getenv("INFLUXDB_ORG", "netguard")
        self.bucket = bucket or os.getenv("INFLUXDB_BUCKET", "events")
        self._client = InfluxDBClient(url=self.url, token=self.token, org=self.org)
        self._write_api = self._client.write_api(write_options=SYNCHRONOUS)

    def write_event(
        self,
        action: str,
        src_zone: str,
        dst_zone: str,
        classification: str,
        protocol: str,
    ) -> None:
        """Escreve um ponto de métrica para um evento — measurement 'events'."""
        point = (
            Point("events")
            .tag("action", action)
            .tag("src_zone", src_zone)
            .tag("dst_zone", dst_zone)
            .tag("severity", classification.split(":")[0])
            .tag("protocol", protocol)
            .field("count", 1)
        )
        self._write_api.write(bucket=self.bucket, record=point, write_precision=WritePrecision.S)

    def close(self) -> None:
        self._client.close()
```

Nota de design: `field("count", 1)` — cada evento escreve `count=1`; o Grafana soma/agrupa por janela temporal (`sum()` numa janela de 1 minuto = eventos/min). Tags (`action`, `src_zone`, etc.) são indexados — permitem filtrar sem varrer todos os dados.

---

### Step 4 — Testar a ligação

```bash
python -c "
from src.metrics.influx_client import MetricsClient
m = MetricsClient()
m.write_event('block', 'EXTERNAL', 'GREEN', 'HIGH: ssh', 'tcp')
print('Ponto escrito com sucesso')
m.close()
"
```

Verificar na UI do InfluxDB (`Data Explorer` → bucket `events`) que o ponto aparece.

---

### Step 5 — `tests/test_metrics_client.py`

Os testes não devem depender de um InfluxDB real a correr — usar mocks do `write_api`:

```python
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.metrics.influx_client import MetricsClient


@pytest.fixture
def metrics(monkeypatch: pytest.MonkeyPatch) -> MetricsClient:
    monkeypatch.setenv("INFLUXDB_TOKEN", "fake_token")
    with patch("src.metrics.influx_client.InfluxDBClient"):
        client = MetricsClient()
        client._write_api = MagicMock()
        return client


class TestMetricsClient:
    def test_write_event_calls_write_api(self, metrics: MetricsClient) -> None:
        metrics.write_event("block", "EXTERNAL", "GREEN", "HIGH: ssh", "tcp")
        metrics._write_api.write.assert_called_once()

    def test_write_event_uses_configured_bucket(self, metrics: MetricsClient) -> None:
        metrics.write_event("pass", "GREEN", "EXTERNAL", "INFO: dns", "udp")
        call_kwargs = metrics._write_api.write.call_args.kwargs
        assert call_kwargs["bucket"] == metrics.bucket

    def test_default_bucket_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("INFLUXDB_BUCKET", "custom_bucket")
        with patch("src.metrics.influx_client.InfluxDBClient"):
            client = MetricsClient()
        assert client.bucket == "custom_bucket"

    def test_close_closes_client(self, metrics: MetricsClient) -> None:
        metrics._client = MagicMock()
        metrics.close()
        metrics._client.close.assert_called_once()
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 145 + 4 = 149 testes

ruff check src/
mypy src/metrics/ --strict --ignore-missing-imports

git add src/metrics/ tests/test_metrics_client.py pyproject.toml .env.example
git commit -m "feat: dia 22 — client InfluxDB para métricas de séries temporais"
```

---

## Checklist

- [ ] InfluxDB a correr em Docker, UI acessível em `:8086`
- [ ] Bucket `events`, org `netguard`, token guardados em `.env`
- [ ] `influxdb-client` instalado
- [ ] `MetricsClient.write_event()` escreve pontos com tags + field `count`
- [ ] Ponto visível no Data Explorer do InfluxDB
- [ ] 4 testes com mocks a passar (sem dependência de InfluxDB real)
- [ ] `python -m pytest tests/ -v` → 149 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/metrics/__init__.py` | Package metrics |
| `src/metrics/influx_client.py` | `MetricsClient` — write_event() |
| `tests/test_metrics_client.py` | 4 testes com mocks |

**Próximo dia:** Dia 23 — escrever métricas de eventos no InfluxDB a partir do pipeline
