# Dia 49 — Checkpoint "Fase 1 v1": demo end-to-end completa

**Fase:** 1 · **Semana:** 7 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-48 concluídos. Refactoring (Dia 47) e qualidade (Dia 48) fechados.
Sete semanas de desenvolvimento produziram um sistema completo:
- Parsing pfSense (IPv4/IPv6) + servidor syslog UDP + webhook HTTP
- Persistência SQLite + motor de regras YAML + AbuseIPDB + GeoIP
- API REST FastAPI com auth + alertas Telegram
- InfluxDB + Grafana provisionados (dashboard + alerting)
- Análise de tráfego avançada + Scapy + baseline IoT
- Isolation Forest (ML) integrado no pipeline
- Relatório PDF semanal automático + agendamento

Quero continuar para o Dia 49: checkpoint "Fase 1 v1" — não é código novo,
é validação de que o sistema inteiro funciona como um todo coerente, de
ponta a ponta, tal como seria apresentado a um primeiro cliente piloto.
```

---

## Objectivo

Este é o marco que o `fase1.md` chama "Entrega final" na sua primeira metade (Semanas 1-7 = agente base funcional; Semanas 8-12 = camada de IA por cima). Hoje corre-se o sistema completo do zero, sem atalhos, como se fosse a primeira instalação num café/clínica real.

---

## Steps

### Step 1 — Arranque limpo de todos os serviços

```bash
# Reset total
docker compose -f docker-compose.grafana.yml down -v
rm -f data/netsec.db data/ip_cache.db

docker compose -f docker-compose.grafana.yml up -d
sleep 10
```

---

### Step 2 — Gerar dataset realista de uma "semana" de tráfego

```bash
python scripts/generate_labeled_dataset.py   # dá volume + padrões variados
python scripts/generate_test_log.py           # tráfego adicional genérico
```

---

### Step 3 — Treinar o modelo ML com os dados gerados

```bash
python scripts/train_model.py
```

---

### Step 4 — Arrancar o agente completo

```bash
# Terminal 1 — servidor syslog UDP com pipeline completo (enrich + rules + metrics + ML scorer)
python scripts/run_syslog_server.py --log-level INFO

# Terminal 2 — API REST
uvicorn src.api.main:app --port 8000

# Terminal 3 — agendador de relatórios (não vamos esperar pela segunda-feira —
# chamar generate_and_send() directamente para o smoke test)
python -c "
from src.reports.scheduler import ReportScheduler
s = ReportScheduler()
path = s.generate_and_send()
print(f'Relatório gerado: {path}')
"
```

---

### Step 5 — Injectar tráfego ao vivo e validar cada camada

```bash
python scripts/send_test_syslog.py
```

**Checklist de validação manual, camada a camada:**

- [ ] **Ingestão:** eventos aparecem em `curl -H "X-API-Key: $API_KEY" http://localhost:8000/stats`
- [ ] **Regras:** eventos SSH/RDP/SMB de IPs externos disparam alerta Telegram (regra YAML)
- [ ] **Threat intel:** eventos externos têm `abuse_score`/`geo_country` preenchidos (`GET /events`)
- [ ] **Métricas:** dashboard Grafana (`http://localhost:3000`) mostra o tráfego em tempo real
- [ ] **Alerting Grafana:** gerar burst de tráfego (`generate_test_log.py` modo `burst`) dispara o alert rule
- [ ] **ML:** `python -c "from src.ml.anomaly_scorer import AnomalyScorer; print(AnomalyScorer().run_once())"` devolve > 0 anomalias nalgum ciclo com dados suficientes
- [ ] **Relatório PDF:** ficheiro em `data/reports/relatorio_*.pdf` abre correctamente, com gráficos visíveis
- [ ] **Telegram:** documento do relatório PDF chega ao bot

---

### Step 6 — Testar os "fail modes" — o sistema degrada de forma segura?

Confirmar que desligar cada dependência externa não derruba o agente:

```bash
# Parar InfluxDB — o pipeline deve continuar a persistir em SQLite e a alertar
docker stop influxdb
python scripts/send_test_syslog.py  # não deve crashar, "Falha ao escrever métrica" no log

# Sem TELEGRAM_BOT_TOKEN configurado — alertas continuam no log, só o Telegram falha silenciosamente
unset TELEGRAM_BOT_TOKEN
python scripts/send_test_syslog.py

docker start influxdb  # repor
```

---

### Step 7 — Suite completa + smoke test de arranque limpo

```bash
python -m pytest tests/ -v --tb=short
ruff check src/
mypy src/ --strict --ignore-missing-imports

# confirmar que um checkout limpo do repo + venv novo consegue correr tudo
# (útil para detectar dependências esquecidas do pyproject.toml)
```

---

### Step 8 — Documentar o checkpoint

Actualizar `docs/fase1/fase1.md` — marcar a secção "Entrega final" (Semanas 1-7, agente base) como validada, e registar quaisquer limitações conhecidas encontradas durante este checkpoint (ex: latência do scoring ML, falsos positivos do Grafana alerting com os thresholds actuais) na tabela de decisões técnicas, para revisitar nas Semanas 8-12 ou em produção real.

---

### Step 9 — Commit e tag do checkpoint

```bash
git add docs/fase1/fase1.md
git commit -m "docs: dia 49 — checkpoint Fase 1 v1 validado end-to-end"

git tag -a fase1-v1-checkpoint -m "Agente base completo e validado: ingestão, regras, ML, dashboards, relatórios"
```

---

## Checklist

- [ ] Arranque completo do zero (`docker compose down -v` + reset SQLite) sem passos manuais escondidos
- [ ] Todas as 8 camadas do Step 5 validadas manualmente
- [ ] Degradação segura confirmada (InfluxDB em baixo, Telegram sem credenciais)
- [ ] Suite completa (229+ testes) a passar
- [ ] `mypy src/ --strict` limpo (herdado do Dia 48)
- [ ] Limitações conhecidas documentadas em `fase1.md`
- [ ] Tag `fase1-v1-checkpoint` criada
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Validação end-to-end:** *(preencher com o resultado real de cada item do Step 5 — o que funcionou de primeira, o que precisou de ajuste)*

**Limitações conhecidas registadas:** *(preencher)*

---

## Próxima semana: Semana 8

**Tema:** Anthropic SDK — análise de alertas em português

| Dia | Tema |
|---|---|
| 50 | Anthropic SDK — setup e primeira chamada |
| 51 | Prompt design para análise de alertas em português |
| 52 | Structured output com Pydantic |
| 53 | Integração no pipeline de alertas |
| 54 | Gestão de custo e tokens |
| 55 | Cache de respostas LLM |
| 56 | Revisão Semana 8 |
