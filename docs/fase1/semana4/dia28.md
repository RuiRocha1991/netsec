# Dia 28 — Revisão da Semana 4: dashboard completo em tempo real

**Fase:** 1 · **Semana:** 4 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-27 concluídos. Estado do projecto:
- InfluxDB + Grafana provisionados como código (deploy/grafana/)
- Dashboard com 6 painéis + 1 alert rule → Telegram
- src/metrics/influx_client.py — MetricsClient integrado no IngestPipeline
- tests/: 160 testes (158 unitários + 2 de integração InfluxDB)

Quero continuar para o Dia 28: revisão end-to-end da Semana 4 — subir tudo
do zero (docker compose down -v && up), gerar tráfego, confirmar dashboard e
alerta, e fechar a semana.
```

---

## Objectivo

Dia de consolidação: nenhuma feature nova, só validação de que a Semana 4 forma um todo coerente e reproduzível — importante porque este é o tipo de setup que terá de ser replicado em cada instalação de cliente.

---

## Steps

### Step 1 — Reset completo e arranque limpo

```bash
docker compose -f docker-compose.grafana.yml down -v
docker compose -f docker-compose.grafana.yml up -d
sleep 10
```

Confirmar sem tocar na UI:
```bash
# datasource existe
curl -s -u admin:$GRAFANA_ADMIN_PASSWORD http://localhost:3000/api/datasources | python -m json.tool

# dashboard existe
curl -s -u admin:$GRAFANA_ADMIN_PASSWORD http://localhost:3000/api/dashboards/uid/netguard-overview | python -m json.tool | head -5

# alert rule existe
curl -s -u admin:$GRAFANA_ADMIN_PASSWORD http://localhost:3000/api/v1/provisioning/alert-rules | python -m json.tool | head -20
```

---

### Step 2 — Gerar tráfego de volume variável

Estender `scripts/generate_test_log.py` (Dia 7) com um modo "burst" para testar o alert rule do Dia 27:

```python
# scripts/generate_test_log.py — adicionar parâmetro
def generate(path: Path, n: int = 200, burst: bool = False) -> None:
    ...
    if burst:
        # concentrar 100 bloqueios no mesmo minuto para disparar o alerta
        burst_start = start + timedelta(minutes=5)
        for i in range(100):
            lines.append(_filterlog_line(
                burst_start + timedelta(seconds=i % 60 * 0.5), "block", "tcp",
                random.choice(external_ips), random.choice(internal_ips),
                random.randint(1024, 65535), 22,
            ))
```

```bash
python -c "
from scripts.generate_test_log import generate
from pathlib import Path
generate(Path('data/logs/burst_test.log'), n=200, burst=True)
"

python scripts/run_syslog_server.py --no-enrich &
python scripts/send_test_syslog.py  # ou apontar para burst_test.log com argparse
```

---

### Step 3 — Confirmar visualmente

- [ ] Dashboard mostra o pico no painel "Eventos por minuto"
- [ ] "Top 10 IPs atacantes" reflecte os IPs do burst
- [ ] Alert rule dispara (**Alerting → Alert rules → estado "Firing"**)
- [ ] Mensagem chega ao Telegram (bot do Dia 18/27)

---

### Step 4 — Correr toda a suite, incluindo integração

```bash
python -m pytest tests/ -v --tb=short
# 160 testes: 158 sempre + 2 integration (passam com InfluxDB a correr)

ruff check src/
mypy src/metrics/ src/parsers/ --strict --ignore-missing-imports
```

---

### Step 5 — Actualizar `docker-compose.grafana.yml` com healthchecks

Pequeno endurecimento antes de fechar a semana — garantir que o Grafana só arranca depois do InfluxDB estar pronto:

```yaml
services:
  influxdb:
    # ...
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8086/health"]
      interval: 5s
      timeout: 3s
      retries: 5

  grafana:
    # ...
    depends_on:
      influxdb:
        condition: service_healthy
```

---

### Step 6 — Commit de fecho da Semana 4

```bash
git add scripts/generate_test_log.py docker-compose.grafana.yml
git commit -m "feat: dia 28 — modo burst de teste + healthchecks + fecho Semana 4"

git tag -a semana4 -m "Semana 4 concluída — InfluxDB + Grafana provisionados, 160 testes"
```

---

## Checklist

- [ ] `docker compose down -v && up -d` recria datasource, dashboard e alert rule sem passos manuais
- [ ] Modo `burst` em `generate_test_log.py`
- [ ] Pico visível no dashboard e alert rule dispara
- [ ] Alerta chega ao Telegram
- [ ] Healthchecks Grafana↔InfluxDB no compose
- [ ] `python -m pytest tests/ -v` → 160 (2 integration a passar com InfluxDB activo)
- [ ] `ruff check src/` e `mypy src/ --strict` sem erros
- [ ] Tag `semana4` criada
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros alterados:**

| Ficheiro | Descrição |
|---|---|
| `scripts/generate_test_log.py` | Modo `burst` para testar alerting |
| `docker-compose.grafana.yml` | Healthchecks InfluxDB→Grafana |

**Estado final da Semana 4:**

| Componente | Ficheiro |
|---|---|
| Client InfluxDB | `src/metrics/influx_client.py` |
| Provisioning Grafana | `deploy/grafana/provisioning/` |
| Dashboard | `deploy/grafana/dashboards/netguard/netguard-overview.json` |
| Alert rule | `deploy/grafana/provisioning/alerting/rules.yaml` |

**Testes:** 160 testes (158 unitários + 2 integração InfluxDB)

---

## Próxima semana: Semana 5

**Tema:** Análise de tráfego avançada — Pandas + Scapy + baseline IoT

| Dia | Tema |
|---|---|
| 29 | Agregações temporais avançadas com Pandas (resample, rolling windows) |
| 30 | Heatmap de ataques por hora/dia da semana |
| 31 | Top talkers e baseline de tráfego normal por IP/zona |
| 32 | Captura live com Scapy — fundamentos (sniff, filtros BPF) |
| 33 | Perfil de baseline IoT — capturar padrão normal de um dispositivo |
| 34 | Detecção de desvio ao baseline IoT (regras + thresholds estatísticos) |
| 35 | Revisão Semana 5 — relatório de análise de tráfego |
