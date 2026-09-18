# Dia 79 — Documentação técnica e arquitectura

**Fase:** 1 · **Semana:** 12 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-78 concluídos. Checklist de entrega verificado. 84 dias de docs de
lição (docs/fase1/semanaN/diaM.md) existem, mas são material de aprendizagem
passo-a-passo — não uma documentação de arquitectura consultável para
alguém (incluindo o próprio developer, daqui a 6 meses) que precise de
entender o sistema rapidamente sem ler 84 ficheiros.

Quero continuar para o Dia 79: escrever a documentação técnica de
arquitectura do agente NetGuard AI — um documento de referência, não um
diário de aprendizagem.
```

---

## Objectivo

Os `diaN.md` respondem "como se construiu, passo a passo". Falta o documento que responde "como o sistema funciona hoje, visto de fora" — o que um novo developer, um investidor técnico, ou o próprio Rui daqui a um ano, precisam para se orientar rapidamente.

---

## Steps

### Step 1 — `docs/architecture.md`

Estrutura sugerida (adaptar conforme o que realmente existe, verificado no Dia 78):

```markdown
# NetGuard AI — Arquitectura Técnica (Fase 1)

## Visão geral

[Diagrama ASCII do fluxo completo: pfSense → syslog/webhook → IngestPipeline
→ (storage, regras, métricas, ML, LLM/agente) → (API, Grafana, Telegram)]

## Componentes

### Ingestão
- `src/parsers/pfsense_parser.py` — parsing de filterlog (IPv4/IPv6)
- `src/parsers/syslog_server.py` — servidor UDP
- `src/parsers/ingest_pipeline.py` — pipeline unificado (UDP + webhook)

### Persistência
- `src/db/storage.py` — CRUD SQLite (EventStorage)
- `src/db/queries.py` — queries analíticas (EventQueries)
- Tabelas: events, alert_analyses, agent_decisions, human_decisions

### Detecção
- `src/analyzers/rule_engine.py` — regras declarativas YAML
- `src/analyzers/threat_intel.py`, `geoip.py` — enriquecimento externo
- `src/ml/` — Isolation Forest (anomaly_model, windowed_features, anomaly_scorer)

### IA
- `src/llm/` — Anthropic SDK, prompts, structured output, orçamento, cache
- `src/rag/` — ChromaDB, MITRE ATT&CK, OWASP Top 10, retriever
- `src/agent/` — LangGraph, tools, decisão, human-in-the-loop

### Exposição
- `src/api/` — FastAPI REST (auth API key)
- `src/metrics/` — InfluxDB
- `deploy/grafana/` — dashboards provisionados
- `src/alerts/` — Telegram (alertas + escalação + relatórios)
- `src/reports/` — PDF semanal (weasyprint + Jinja2)

### Infraestrutura
- `Dockerfile`, `docker-compose.yml` — containerização
- `.github/workflows/ci.yml` — CI (test, quality, docker-build)

## Fluxo de dados — um evento HIGH/CRITICAL, ponta a ponta

1. pfSense envia log via syslog UDP (porta 5514) ou webhook HTTPS
2. `IngestPipeline.process_line()` parseia → `LogEntry`
3. Enriquecimento (GeoIP local + AbuseIPDB com cache) se IP externo
4. Persistência em SQLite (`events` table)
5. Escrita de métrica no InfluxDB (best-effort, não bloqueia o resto)
6. `RuleEngine.evaluate()` — se match com `alert: true` → Telegram imediato
7. Se severidade HIGH/CRITICAL → enfileirado no `AgentQueue`
8. Agente (LangGraph): reúne histórico + reputação + contexto RAG → LLM →
   decide acção (auto_block / monitor / escalate_human / false_positive)
9. Decisão persistida em `agent_decisions`; se `escalate_human`, Telegram
   com botões de decisão
10. Follow-up Telegram com explicação em português enviado

## Decisões de arquitectura (ver também tabelas em fase1.md)

[Resumir aqui as decisões mais importantes das 12 semanas — remeter para
fase1.md para a lista completa]

## Limitações conhecidas da Fase 1

[Listar honestamente — ex: contamination fixo do Isolation Forest não
calibrado por cliente (Dia 39), custo de RAG não optimizado além do
k_per_source (Dia 63), auto_block só regista decisão sem aplicar
efectivamente no pfSense (integração real é Fase 2)]

## O que NÃO está na Fase 1 (por desenho, não por falta de tempo)

- Multi-tenant / VPS central agregando múltiplos clientes (Fase 4)
- Integração real com API do pfSense para aplicar bloqueios automáticos (Fase 2)
- Suricata IDS/IPS, pfBlockerNG, WireGuard, HAProxy (Fase 2)
- Pentest formal (Fase 3)
```

---

### Step 2 — Diagrama de arquitectura visual (não só ASCII)

Gerar um diagrama mais legível para apresentações (ex: usando uma ferramenta de diagramas, ou um SVG simples) — a decidir consoante as ferramentas disponíveis; o ASCII do Step 1 é o mínimo obrigatório e sempre legível em qualquer editor de texto/terminal.

---

### Step 3 — Docstrings de módulo em falta

Rever os módulos `src/` criados ao longo de 12 semanas — confirmar que cada ficheiro `.py` tem, no mínimo, uma docstring de módulo de uma linha explicando o seu propósito (não o "quê" óbvio do nome do ficheiro, mas o "porquê" de existir separadamente, quando não for óbvio). Preencher as que faltarem.

---

### Step 4 — Actualizar `docs/README.md` para apontar para `architecture.md`

```markdown
## Documentação

- [`architecture.md`](../architecture.md) — visão técnica de referência do sistema (ler primeiro se és novo no projecto)
- `fase1/`, `fase2/`, etc. — diário de desenvolvimento dia-a-dia (como cada peça foi construída)
```

---

### Step 5 — Commit

```bash
python -m pytest tests/ -v
# sem alteração — dia de documentação pura

git add docs/architecture.md docs/README.md
git commit -m "docs: dia 79 — documentação técnica de arquitectura (visão de referência)"
```

---

## Checklist

- [ ] `docs/architecture.md` criado com visão de referência (não diário de desenvolvimento)
- [ ] Fluxo de dados ponta-a-ponta documentado com os nomes reais de módulos/funções
- [ ] Limitações conhecidas listadas honestamente
- [ ] O que está fora de âmbito da Fase 1 explicitamente separado
- [ ] Docstrings de módulo em falta preenchidas
- [ ] `docs/README.md` aponta para `architecture.md`
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `docs/architecture.md` | Documentação técnica de referência |
| `docs/README.md` | Link para architecture.md |

**Próximo dia:** Dia 80 — guião de demo para clientes
