# Dia 25 — Provisioning Grafana como código (dashboards-as-code)

**Fase:** 1 · **Semana:** 4 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-24 concluídos. Estado do projecto:
- Grafana a correr em Docker com dashboard "NetGuard AI — Overview" criado
  manualmente na UI (Dia 24)
- InfluxDB com datasource configurado
- tests/: 153 testes, todos a passar

Quero continuar para o Dia 25: converter o dashboard criado manualmente em
ficheiros de provisioning versionados em git — para que qualquer instalação
nova de cliente (multi-tenant, arquitectura do CLAUDE.md) tenha o dashboard
pronto automaticamente, sem trabalho manual na UI.
```

---

## Objectivo

Um dashboard criado à mão na UI não é reproduzível — cada instalação nova de cliente teria de repetir os passos do Dia 24. Hoje isso fica em ficheiros YAML + JSON versionados em `deploy/grafana/`, carregados automaticamente pelo Grafana no arranque.

```
deploy/grafana/
├── provisioning/
│   ├── datasources/influxdb.yaml   ← datasource automático
│   └── dashboards/dashboards.yaml  ← aponta para a pasta de dashboards
└── dashboards/
    └── netguard-overview.json      ← o dashboard do Dia 24, exportado
```

---

## Conceitos novos

| Conceito | Onde é usado |
|---|---|
| Grafana provisioning | Ficheiros YAML lidos no arranque para configurar datasources/dashboards |
| Dashboard JSON model | Representação declarativa completa de um dashboard |
| Variáveis de ambiente em YAML (`$VAR`) | Grafana substitui `$INFLUXDB_TOKEN` por env var no arranque |
| Bind mounts Docker | Montar `deploy/grafana/provisioning` dentro do container |

---

## Steps

### Step 1 — Estrutura de pastas

```bash
mkdir -p deploy/grafana/provisioning/datasources
mkdir -p deploy/grafana/provisioning/dashboards
mkdir -p deploy/grafana/dashboards
```

---

### Step 2 — `deploy/grafana/provisioning/datasources/influxdb.yaml`

```yaml
apiVersion: 1

datasources:
  - name: InfluxDB-NetGuard
    type: influxdb
    access: proxy
    url: http://influxdb:8086
    isDefault: true
    jsonData:
      version: Flux
      organization: netguard
      defaultBucket: events
      tlsSkipVerify: true
    secureJsonData:
      token: $INFLUXDB_TOKEN
    editable: false
```

`$INFLUXDB_TOKEN` é resolvido a partir da variável de ambiente do container Grafana (Grafana ≥ 9 suporta expansão de env vars em ficheiros de provisioning).

---

### Step 3 — `deploy/grafana/provisioning/dashboards/dashboards.yaml`

```yaml
apiVersion: 1

providers:
  - name: NetGuard AI
    orgId: 1
    folder: "NetGuard AI"
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards/netguard
```

---

### Step 4 — Exportar o dashboard do Dia 24 para JSON

Na UI: **Dashboard → Settings (⚙) → JSON Model → copiar tudo**

Guardar em `deploy/grafana/dashboards/netguard-overview.json`. Estrutura resumida (o JSON real tem muito mais detalhe — este é o essencial anotado):

```json
{
  "title": "NetGuard AI — Overview",
  "uid": "netguard-overview",
  "tags": ["netguard"],
  "timezone": "browser",
  "refresh": "10s",
  "panels": [
    {
      "title": "Eventos por minuto",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 0},
      "targets": [{
        "query": "from(bucket: \"events\") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r._measurement == \"events\") |> filter(fn: (r) => r._field == \"count\") |> aggregateWindow(every: 1m, fn: sum, createEmpty: false)"
      }]
    },
    {
      "title": "Total de bloqueios",
      "type": "stat",
      "gridPos": {"h": 4, "w": 8, "x": 0, "y": 8},
      "targets": [{
        "query": "from(bucket: \"events\") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r._measurement == \"events\") |> filter(fn: (r) => r.action == \"block\") |> filter(fn: (r) => r._field == \"count\") |> sum()"
      }]
    },
    {
      "title": "Eventos por severidade",
      "type": "bargauge",
      "gridPos": {"h": 4, "w": 8, "x": 8, "y": 8},
      "targets": [{
        "query": "from(bucket: \"events\") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r._measurement == \"events\") |> filter(fn: (r) => r._field == \"count\") |> group(columns: [\"severity\"]) |> sum()"
      }]
    }
  ]
}
```

> Move este ficheiro para `deploy/grafana/dashboards/netguard/netguard-overview.json` — o `path` do provider aponta para a subpasta `netguard`.

---

### Step 5 — `docker-compose.grafana.yml` (para desenvolvimento local)

```yaml
services:
  influxdb:
    image: influxdb:2.7
    ports: ["8086:8086"]
    environment:
      DOCKER_INFLUXDB_INIT_MODE: setup
      DOCKER_INFLUXDB_INIT_USERNAME: admin
      DOCKER_INFLUXDB_INIT_PASSWORD: ${INFLUXDB_PASSWORD}
      DOCKER_INFLUXDB_INIT_ORG: netguard
      DOCKER_INFLUXDB_INIT_BUCKET: events
      DOCKER_INFLUXDB_INIT_ADMIN_TOKEN: ${INFLUXDB_TOKEN}
    volumes: ["influxdb-data:/var/lib/influxdb2"]

  grafana:
    image: grafana/grafana-oss:latest
    ports: ["3000:3000"]
    environment:
      INFLUXDB_TOKEN: ${INFLUXDB_TOKEN}
      GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_ADMIN_PASSWORD}
    volumes:
      - grafana-data:/var/lib/grafana
      - ./deploy/grafana/provisioning:/etc/grafana/provisioning
      - ./deploy/grafana/dashboards:/etc/grafana/provisioning/dashboards
    depends_on: [influxdb]

volumes:
  influxdb-data:
  grafana-data:
```

> Este compose é só para InfluxDB+Grafana — o compose completo com o agente Python vem na Semana 11 (Docker).

---

### Step 6 — Recriar do zero e validar provisioning

```bash
docker compose -f docker-compose.grafana.yml down -v  # limpar estado manual do Dia 24
docker compose -f docker-compose.grafana.yml up -d

# aguardar arranque e confirmar que o dashboard já existe sem passos manuais
sleep 5
curl -s -u admin:$GRAFANA_ADMIN_PASSWORD http://localhost:3000/api/dashboards/uid/netguard-overview | python -m json.tool | head -20
```

---

### Step 7 — Teste de validação do JSON (sanity check em Python)

Não é possível testar o Grafana em si nos testes `pytest` (é infraestrutura, não código da aplicação) — mas vale a pena validar que o JSON do dashboard é sintacticamente válido e tem os campos esperados, como guarda-corpo contra commits quebrados:

```python
# tests/test_grafana_provisioning.py
from __future__ import annotations

import json
from pathlib import Path


class TestGrafanaProvisioning:
    def test_dashboard_json_is_valid(self) -> None:
        path = Path("deploy/grafana/dashboards/netguard/netguard-overview.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["uid"] == "netguard-overview"

    def test_dashboard_has_expected_panels(self) -> None:
        path = Path("deploy/grafana/dashboards/netguard/netguard-overview.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        titles = {p["title"] for p in data["panels"]}
        assert {"Eventos por minuto", "Total de bloqueios", "Eventos por severidade"} <= titles
```

---

### Step 8 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 153 + 2 = 155 testes

git add deploy/grafana/ docker-compose.grafana.yml tests/test_grafana_provisioning.py
git commit -m "feat: dia 25 — Grafana provisionado como código (datasource + dashboard)"
```

---

## Checklist

- [ ] `deploy/grafana/provisioning/datasources/influxdb.yaml` com token via env var
- [ ] `deploy/grafana/provisioning/dashboards/dashboards.yaml` — provider aponta para pasta
- [ ] Dashboard exportado para `deploy/grafana/dashboards/netguard/netguard-overview.json`
- [ ] `docker compose down -v && up -d` recria tudo sem passos manuais na UI
- [ ] 2 testes de validação do JSON a passar
- [ ] `python -m pytest tests/ -v` → 155 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `deploy/grafana/provisioning/datasources/influxdb.yaml` | Datasource automático |
| `deploy/grafana/provisioning/dashboards/dashboards.yaml` | Provider de dashboards |
| `deploy/grafana/dashboards/netguard/netguard-overview.json` | Dashboard exportado |
| `docker-compose.grafana.yml` | InfluxDB + Grafana para dev local |
| `tests/test_grafana_provisioning.py` | 2 testes de validação JSON |

**Próximo dia:** Dia 26 — painéis: eventos/min, top IPs, mapa de zonas, alertas HIGH
