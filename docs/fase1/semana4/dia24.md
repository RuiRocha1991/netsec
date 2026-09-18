# Dia 24 — Grafana: instalação, datasource InfluxDB, primeiro dashboard

**Fase:** 1 · **Semana:** 4 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-23 concluídos. Estado do projecto:
- src/metrics/influx_client.py — escrita de métricas InfluxDB
- src/parsers/ingest_pipeline.py — pipeline escreve em SQLite + InfluxDB
- InfluxDB a correr em Docker, bucket "events" a receber pontos
- tests/: 153 testes, todos a passar

Quero continuar para o Dia 24: instalar Grafana, ligar ao InfluxDB e criar o
primeiro dashboard manualmente (a versão "as code" fica para o Dia 25).
```

---

## Objectivo

Hoje é sobretudo trabalho de infraestrutura/configuração (não Python) — o valor é visual: pela primeira vez vemos os eventos em tempo real num dashboard, em vez de linhas de terminal.

```
InfluxDB (bucket events)
        ↓ datasource
    Grafana (:3000)
        ↓
  Dashboard "NetGuard AI — Overview"
```

---

## Conceitos novos

| Conceito | Onde é usado |
|---|---|
| Grafana datasource | Ligação Grafana → InfluxDB (URL, org, token, bucket por defeito) |
| Flux query no painel | Query embutida num painel Grafana |
| Painel "Time series" | Gráfico de linha ao longo do tempo |
| Painel "Stat" | Valor único em destaque (ex: total de bloqueios hoje) |
| Auto-refresh | Dashboard actualiza sozinho (ex: a cada 10s) |

---

## Steps

### Step 1 — Instalar Grafana (Docker)

```bash
docker run -d --name grafana \
  -p 3000:3000 \
  -v grafana-data:/var/lib/grafana \
  grafana/grafana-oss:latest
```

Aceder: `http://192.168.0.43:3000` — login inicial `admin`/`admin` (pede para trocar a password).

---

### Step 2 — Adicionar datasource InfluxDB

**Connections → Data sources → Add data source → InfluxDB**

| Campo | Valor |
|---|---|
| Query Language | Flux |
| URL | `http://<ip-do-container-influxdb>:8086` (ou `host.docker.internal:8086` se Grafana e InfluxDB estiverem em containers separados sem rede partilhada) |
| Organization | `netguard` |
| Token | o token gerado no Dia 22 |
| Default Bucket | `events` |

> Dica de rede Docker: criar uma rede dedicada facilita — `docker network create netguard-net`, e correr ambos os containers com `--network netguard-net`. Depois o URL do datasource passa a ser `http://influxdb:8086` (nome do container em vez de IP).

**Save & Test** → deve mostrar "datasource is working".

---

### Step 3 — Criar o dashboard "NetGuard AI — Overview"

**Dashboards → New → New Dashboard → Add visualization → escolher datasource InfluxDB**

**Painel 1 — Eventos por minuto (Time series):**
```flux
from(bucket: "events")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "events")
  |> filter(fn: (r) => r._field == "count")
  |> aggregateWindow(every: 1m, fn: sum, createEmpty: false)
```

**Painel 2 — Total de bloqueios (Stat):**
```flux
from(bucket: "events")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "events")
  |> filter(fn: (r) => r.action == "block")
  |> filter(fn: (r) => r._field == "count")
  |> sum()
```

**Painel 3 — Eventos por severidade (Bar gauge):**
```flux
from(bucket: "events")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "events")
  |> filter(fn: (r) => r._field == "count")
  |> group(columns: ["severity"])
  |> sum()
```

Configurar o dashboard com **auto-refresh a 10s** (canto superior direito).

---

### Step 4 — Gerar tráfego para ver o dashboard "vivo"

```bash
python scripts/run_syslog_server.py --no-enrich &
python scripts/send_test_syslog.py
```

Ver os painéis a actualizar em tempo real.

---

### Step 5 — Guardar credenciais e exportar

- Guardar `admin` password nova em gestor de passwords pessoal (não commitar)
- **Dashboard settings → JSON Model** → copiar o JSON para referência (será formalizado como provisioning no Dia 25)
- Adicionar ao `.env.example`:
```
GRAFANA_URL=http://localhost:3000
GRAFANA_ADMIN_USER=admin
```

---

### Step 6 — Sem testes automatizados hoje

Este dia é infraestrutura visual, sem código Python novo — não há testes a adicionar. Confirmar apenas que a suite continua verde:

```bash
python -m pytest tests/ -v
# 153 testes, sem alteração
```

---

### Step 7 — Commit (documentação/config apenas)

```bash
git add .env.example
git commit -m "docs: dia 24 — Grafana instalado, datasource InfluxDB e primeiro dashboard"
```

---

## Checklist

- [ ] Grafana a correr em Docker, acessível em `:3000`
- [ ] Password admin trocada e guardada com segurança
- [ ] Datasource InfluxDB configurado e testado ("datasource is working")
- [ ] Dashboard "NetGuard AI — Overview" criado com 3 painéis
- [ ] Auto-refresh activo (10s)
- [ ] Painéis actualizam com tráfego de teste real
- [ ] `python -m pytest tests/ -v` → 153 passed (sem regressão)
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Infraestrutura:**

| Item | Descrição |
|---|---|
| Grafana | Container Docker, porta 3000 |
| Datasource | InfluxDB (Flux), bucket `events` |
| Dashboard | "NetGuard AI — Overview" — 3 painéis |

**Próximo dia:** Dia 25 — provisioning Grafana como código (dashboards-as-code)
