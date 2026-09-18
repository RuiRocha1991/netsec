# Dia 27 — Alertas Grafana + testes de integração do writer InfluxDB

**Fase:** 1 · **Semana:** 4 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-26 concluídos. Estado do projecto:
- Dashboard Grafana com 6 painéis (eventos/min, bloqueios, severidade,
  top IPs, tráfego entre zonas, alertas HIGH/CRITICAL)
- src/metrics/influx_client.py — MetricsClient com tags src_ip, src_zone, etc.
- tests/: 158 testes (todos com mocks — nenhum contra InfluxDB real)

Quero continuar para o Dia 27: alertas nativos do Grafana (notificação quando
a taxa de bloqueios dispara) e o primeiro teste de integração real contra um
InfluxDB a correr de verdade (marcado como `integration`, skip automático se
não estiver acessível).
```

---

## Objectivo

Até agora os únicos alertas são os do `RuleEngine` (Telegram). Hoje adicionamos uma camada de alerta baseada em **anomalias de volume** — não "este IP é malicioso" mas "há um pico de bloqueios anormal", que o `RuleEngine` por regra fixa não apanha bem. O Grafana tem alerting nativo, ideal para isto.

Também fechamos uma dívida técnica: os testes do `MetricsClient` desde o Dia 22 só usam mocks — nunca confirmámos contra um InfluxDB real que os pontos escritos são efectivamente lidos de volta correctamente.

---

## Conceitos novos

| Conceito | Onde é usado |
|---|---|
| Grafana Alert rules | Condição sobre uma query Flux + threshold + duração |
| Contact points | Para onde o alerta é enviado (Telegram, reutilizando o bot do Dia 18) |
| `pytest.mark.integration` + `pytest.importorskip`/skip condicional | Testes que só correm se a dependência externa estiver disponível |
| `socket.create_connection` com timeout curto | Verificar rapidamente se um serviço está acessível antes de testar contra ele |

---

## Steps

### Step 1 — Grafana Alert rule: pico de bloqueios

**Alerting → Alert rules → New alert rule**

- **Query (Flux):**
```flux
from(bucket: "events")
  |> range(start: -5m)
  |> filter(fn: (r) => r._measurement == "events")
  |> filter(fn: (r) => r.action == "block")
  |> filter(fn: (r) => r._field == "count")
  |> aggregateWindow(every: 1m, fn: sum, createEmpty: true)
  |> mean()
```
- **Condição:** `IS ABOVE 50` (mais de 50 bloqueios/minuto em média nos últimos 5 min — ajustável por cliente)
- **Evaluate every:** 1m, **for:** 2m (evita alertas por picos de 1 minuto isolados)
- **Labels:** `severity=warning`, `team=netguard`

---

### Step 2 — Contact point Telegram

**Alerting → Contact points → New contact point**

- **Integration:** Telegram
- **Bot API Token:** o mesmo `TELEGRAM_BOT_TOKEN` do Dia 18
- **Chat ID:** o mesmo `TELEGRAM_CHAT_ID`
- **Message:** template por defeito, ou customizar com `{{ .CommonLabels.alertname }}`

**Notification policy:** rotear alertas com `team=netguard` para este contact point.

---

### Step 3 — Exportar a alert rule para provisioning

**Alerting → Alert rules → (a regra) → Export → provisioning YAML**

Guardar em `deploy/grafana/provisioning/alerting/rules.yaml`:

```yaml
apiVersion: 1

groups:
  - orgId: 1
    name: netguard-alerts
    folder: NetGuard AI
    interval: 1m
    rules:
      - uid: netguard-block-spike
        title: "Pico de bloqueios"
        condition: C
        for: 2m
        labels:
          severity: warning
          team: netguard
        annotations:
          summary: "Mais de 50 bloqueios/min em média nos últimos 5 minutos"
        data:
          - refId: A
            datasourceUid: influxdb-netguard
            model:
              query: |
                from(bucket: "events")
                  |> range(start: -5m)
                  |> filter(fn: (r) => r._measurement == "events")
                  |> filter(fn: (r) => r.action == "block")
                  |> filter(fn: (r) => r._field == "count")
                  |> aggregateWindow(every: 1m, fn: sum, createEmpty: true)
                  |> mean()
          - refId: C
            datasourceUid: "-100"
            model:
              type: threshold
              conditions:
                - evaluator: {type: gt, params: [50]}
```

---

### Step 4 — Helper de disponibilidade para testes de integração

```python
# tests/integration_helpers.py
from __future__ import annotations

import socket


def service_reachable(host: str, port: int, timeout: float = 1.0) -> bool:
    """Verifica rapidamente se um serviço TCP está acessível — para skip condicional."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
```

---

### Step 5 — `tests/test_influx_integration.py`

```python
from __future__ import annotations

import time

import pytest

from src.metrics.influx_client import MetricsClient
from tests.integration_helpers import service_reachable

_INFLUX_UP = service_reachable("localhost", 8086)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _INFLUX_UP, reason="InfluxDB não acessível em localhost:8086"),
]


@pytest.fixture
def metrics() -> MetricsClient:
    client = MetricsClient()
    yield client
    client.close()


class TestInfluxIntegration:
    def test_write_and_query_point(self, metrics: MetricsClient) -> None:
        marker_ip = f"10.99.99.{int(time.time()) % 255}"
        metrics.write_event("block", "EXTERNAL", "GREEN", "HIGH: teste_integração", "tcp",
                            src_ip=marker_ip)
        # InfluxDB é eventualmente consistente para leitura logo após escrita — pequeno wait
        time.sleep(1)

        query = f'''
        from(bucket: "{metrics.bucket}")
          |> range(start: -1m)
          |> filter(fn: (r) => r._measurement == "events")
          |> filter(fn: (r) => r.src_ip == "{marker_ip}")
        '''
        query_api = metrics._client.query_api()
        tables = query_api.query(query, org=metrics.org)
        records = [record for table in tables for record in table.records]
        assert len(records) >= 1

    def test_bucket_configured_correctly(self, metrics: MetricsClient) -> None:
        buckets_api = metrics._client.buckets_api()
        bucket = buckets_api.find_bucket_by_name(metrics.bucket)
        assert bucket is not None
```

> `pytestmark` com `skipif` aplica-se a todos os testes da classe/módulo — se o InfluxDB não estiver a correr (ex: máquina CI sem Docker), estes testes aparecem como `SKIPPED`, não `FAILED`. Correr localmente com o InfluxDB do Dia 22 activo para os validar de verdade.

---

### Step 6 — Registar o marker e correr

```toml
# pyproject.toml
[tool.pytest.ini_options]
markers = [
    "integration: testes que sobem um servidor real (mais lentos)",
]
```

```bash
python -m pytest tests/ -v
# 158 + 2 = 160 testes (2 novos, SKIPPED se InfluxDB não estiver a correr)

python -m pytest tests/test_influx_integration.py -v
# com InfluxDB a correr: 2 passed
```

---

### Step 7 — Qualidade e commit

```bash
ruff check src/
git add deploy/grafana/provisioning/alerting/ tests/integration_helpers.py \
        tests/test_influx_integration.py pyproject.toml
git commit -m "feat: dia 27 — alertas Grafana provisionados + testes integração InfluxDB"
```

---

## Checklist

- [ ] Alert rule "Pico de bloqueios" criada e testada (gerar tráfego alto e confirmar disparo)
- [ ] Contact point Telegram ligado à alert rule
- [ ] Alert rule exportada para `deploy/grafana/provisioning/alerting/rules.yaml`
- [ ] `service_reachable()` helper para skip condicional
- [ ] 2 testes de integração real contra InfluxDB (skip se indisponível)
- [ ] `python -m pytest tests/ -v` → 160 (SKIPPED ou passed consoante ambiente)
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `deploy/grafana/provisioning/alerting/rules.yaml` | Alert rule "pico de bloqueios" |
| `tests/integration_helpers.py` | `service_reachable()` |
| `tests/test_influx_integration.py` | 2 testes contra InfluxDB real |

**Próximo dia:** Dia 28 — revisão da Semana 4: dashboard completo em tempo real
