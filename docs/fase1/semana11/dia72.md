# Dia 72 — docker-compose local (agente + volumes)

**Fase:** 1 · **Semana:** 11 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-71 concluídos. Estado do projecto:
- Dockerfile do agente construído e validado (Dia 71)
- docker-compose.grafana.yml — InfluxDB + Grafana (Semana 4)
- tests/: 302 testes, todos a passar

Quero continuar para o Dia 72: docker-compose completo que junta o agente
(Dockerfile do Dia 71) com InfluxDB + Grafana (Dia 22-28) numa só stack,
com volumes persistentes para dados que não podem desaparecer entre restarts
(SQLite, modelos ML, cache ChromaDB).
```

---

## Objectivo

O `docker-compose.grafana.yml` (Semana 4) só tinha InfluxDB+Grafana. Hoje: `docker-compose.yml` único que sobe a stack completa de uma instalação de cliente — o artefacto que efectivamente se copia para o VPS Hetzner (arquitectura `CLAUDE.md`).

```
docker-compose.yml
  ├── agent          (Dockerfile Dia 71 — API + syslog UDP + agente)
  ├── influxdb        (Dia 22)
  ├── grafana         (Dia 24-25, provisioning)
  └── volumes: agent-data, influxdb-data, grafana-data
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Named volumes vs bind mounts | `agent-data` (named, gerido pelo Docker) para dados que só o container usa; bind mount só para o provisioning Grafana (precisa de ser editável em git) |
| `depends_on` com `condition: service_healthy` | Agente só arranca depois do InfluxDB estar pronto (reaproveitando padrão do Dia 28) |
| Redes Docker internas vs portas expostas | Só o agente e o Grafana precisam de portas expostas ao host; InfluxDB fica só na rede interna |
| `restart: unless-stopped` | Política de reinício — importante para um serviço de produção num VPS |

---

## Steps

### Step 1 — `docker-compose.yml`

```yaml
services:
  agent:
    build: .
    ports:
      - "8000:8000"
      - "5514:5514/udp"
    environment:
      DB_PATH: /app/data/netsec.db
      INFLUXDB_URL: http://influxdb:8086
      INFLUXDB_TOKEN: ${INFLUXDB_TOKEN}
      INFLUXDB_ORG: netguard
      INFLUXDB_BUCKET: events
    env_file: .env
    volumes:
      - agent-data:/app/data
    cap_add:
      - NET_RAW      # necessário para src/capture/live_sniffer.py (Scapy, Dia 32)
      - NET_ADMIN
    depends_on:
      influxdb:
        condition: service_healthy
    restart: unless-stopped

  influxdb:
    image: influxdb:2.7
    environment:
      DOCKER_INFLUXDB_INIT_MODE: setup
      DOCKER_INFLUXDB_INIT_USERNAME: admin
      DOCKER_INFLUXDB_INIT_PASSWORD: ${INFLUXDB_PASSWORD}
      DOCKER_INFLUXDB_INIT_ORG: netguard
      DOCKER_INFLUXDB_INIT_BUCKET: events
      DOCKER_INFLUXDB_INIT_ADMIN_TOKEN: ${INFLUXDB_TOKEN}
    volumes:
      - influxdb-data:/var/lib/influxdb2
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8086/health"]
      interval: 5s
      timeout: 3s
      retries: 5
    restart: unless-stopped

  grafana:
    image: grafana/grafana-oss:latest
    ports:
      - "3000:3000"
    environment:
      INFLUXDB_TOKEN: ${INFLUXDB_TOKEN}
      GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_ADMIN_PASSWORD}
    volumes:
      - grafana-data:/var/lib/grafana
      - ./deploy/grafana/provisioning:/etc/grafana/provisioning
      - ./deploy/grafana/dashboards:/etc/grafana/provisioning/dashboards
    depends_on:
      influxdb:
        condition: service_healthy
    restart: unless-stopped

volumes:
  agent-data:
  influxdb-data:
  grafana-data:
```

---

### Step 2 — Arrancar tudo e validar

```bash
docker compose down -v  # limpar estado de testes anteriores (docker-compose.grafana.yml)
docker compose up -d --build
sleep 15

curl http://localhost:8000/health
curl -u admin:$GRAFANA_ADMIN_PASSWORD http://localhost:3000/api/health

docker compose logs agent --tail 30
```

---

### Step 3 — Confirmar persistência de dados entre restarts

```bash
# inserir dados de teste
docker compose exec agent python scripts/generate_test_log.py
docker compose exec agent python scripts/ingest_log.py

# reiniciar só o container do agente
docker compose restart agent
sleep 5

curl -H "X-API-Key: $API_KEY" http://localhost:8000/stats
# o total de eventos deve manter-se — confirma que o volume agent-data persiste
```

---

### Step 4 — Descontinuar `docker-compose.grafana.yml`

O novo `docker-compose.yml` substitui-o — remover o ficheiro antigo (ou mantê-lo só para desenvolvimento isolado do dashboard sem o agente, documentando a distinção):

```bash
git rm docker-compose.grafana.yml
# ou, se preferires manter para desenvolvimento rápido do Grafana isoladamente:
# git mv docker-compose.grafana.yml docker-compose.grafana-only.yml
```

Decisão recomendada: manter como `docker-compose.grafana-only.yml`, útil para iterar em dashboards sem precisar de rebuild do agente a cada mudança — documentar isto no topo do ficheiro.

---

### Step 5 — Sem testes `pytest` novos — validação por script

```bash
# scripts/verify_docker_build.sh do Dia 71 cobre só o agente isolado;
# hoje o smoke test cobre a stack completa:
```

```bash
# scripts/verify_compose_stack.sh
#!/usr/bin/env bash
set -euo pipefail

docker compose down -v
docker compose up -d --build

echo "A aguardar serviços..."
for i in $(seq 1 20); do
    if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
        echo "Agente pronto."
        break
    fi
    sleep 2
done

curl -sf http://localhost:8000/health || { echo "FALHA: agente não respondeu"; docker compose logs; exit 1; }
curl -sf -u admin:"$GRAFANA_ADMIN_PASSWORD" http://localhost:3000/api/health || { echo "FALHA: Grafana não respondeu"; exit 1; }

echo "Stack completa validada com sucesso."
docker compose down -v
```

```bash
chmod +x scripts/verify_compose_stack.sh
./scripts/verify_compose_stack.sh
```

---

### Step 6 — Commit

```bash
python -m pytest tests/ -v
# 302 testes, sem alteração

git add docker-compose.yml scripts/verify_compose_stack.sh
git commit -m "feat: dia 72 — docker-compose completo (agente + InfluxDB + Grafana)"
```

---

## Checklist

- [ ] `docker-compose.yml` junta agente + InfluxDB + Grafana com `depends_on: service_healthy`
- [ ] `cap_add: NET_RAW, NET_ADMIN` concedido só ao agente (necessário para Scapy)
- [ ] Volumes nomeados para dados persistentes (`agent-data`, `influxdb-data`, `grafana-data`)
- [ ] Persistência confirmada após `docker compose restart agent`
- [ ] `docker-compose.grafana.yml` antigo descontinuado ou renomeado com propósito claro
- [ ] `scripts/verify_compose_stack.sh` valida a stack completa automaticamente
- [ ] Suite `pytest` continua a passar (302 testes)
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `docker-compose.yml` | Stack completa: agente + InfluxDB + Grafana |
| `scripts/verify_compose_stack.sh` | Smoke test da stack completa |
| `docker-compose.grafana.yml` | Descontinuado/renomeado |

**Próximo dia:** Dia 73 — variáveis de ambiente e secrets em Docker
