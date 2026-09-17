# NetGuard AI — Fase 4: Produto + IA + Primeiros Clientes

**Duração:** Meses 13–18 (~24 semanas)
**Pré-requisito:** Fase 3 concluída · ler `CLAUDE.md` na raiz

---

## Objectivo

Juntar tudo num produto polido, vendável e escalável. Adicionar a camada de IA que diferencia de qualquer concorrente. Instalar nos primeiros clientes reais e validar o modelo de negócio.

## Entrega final

- Agente LangGraph autónomo com tool use e resposta automática a incidentes
- RAG sobre MITRE ATT&CK, OWASP e guias pfSense
- Chatbot de rede em português — responde a perguntas do cliente sobre a sua rede
- Dashboard Grafana multi-tenant (cada cliente vê só os seus dados)
- Script de instalação automatizado (onboarding em 10 minutos)
- Relatório PDF semanal personalizado por cliente
- 2–3 clientes reais instalados
- Modelo de negócio definido e validado

---

## Visão geral das semanas

| Semana | Foco | Entregável |
|---|---|---|
| 1–4 | Anthropic SDK + LLM análise de alertas | Alertas explicados em português |
| 5–8 | LangChain + RAG sobre MITRE/OWASP | Análise enriquecida com contexto de ameaças |
| 9–12 | LangGraph + agente autónomo | Agente que investiga e actua automaticamente |
| 13–16 | Produto multi-tenant + onboarding | Script instalação 10 minutos |
| 17–20 | Primeiro cliente piloto | Instalação real + relatório before/after |
| 21–24 | Escalar + modelo de negócio | 2–3 clientes, pricing definido |

---

## Arquitectura de IA

```
pfSense logs ──► parser ──► SQLite/PostgreSQL
                                │
                    ┌───────────┤
                    │           │
              Isolation      LangGraph Agent
              Forest ML      ┌──────────────┐
              (anomalias)    │ tool: query_db│
                    │        │ tool: abuseipdb│
                    └───────►│ tool: geoip   │
                             │ tool: mitre_rag│
                             └───────┬────────┘
                                     │
                              Claude claude-sonnet-4-6
                              "Alerta: IP 1.2.3.4 da Rússia
                               tentou aceder SSH 47 vezes
                               nos últimos 5 minutos..."
                                     │
                              Telegram Bot ──► Cliente
                              Grafana Alert ──► Dashboard
```

---

## Stack de IA

| Componente | Tecnologia | Para quê |
|---|---|---|
| LLM | Anthropic claude-sonnet-4-6 | Análise e explicação de alertas |
| Orquestração | LangGraph | Agente autónomo com tools |
| RAG | LangChain + ChromaDB | Contexto MITRE ATT&CK, OWASP |
| ML anomalias | scikit-learn Isolation Forest | Detecção de padrões anómalos |
| Threat intel | AbuseIPDB API + MaxMind GeoLite2 | Enrichment de IPs |

---

## Modelo de negócio

| Serviço | Preço estimado |
|---|---|
| Hardware + instalação (one-time) | 490€ + mão de obra |
| Café / pequeno comércio (mensal) | 30–50€/mês |
| Clínica / escritório advogados (mensal) | 80–150€/mês |
| PME com dados sensíveis (mensal) | 150–300€/mês |
| Pentest anual (serviço adicional) | 500–1500€ |

**Ponto de equilíbrio:** 10 clientes a 50€/mês = 500€ receita · ~20€ custos infra.

---

## Custos de infraestrutura VPS

| Item | Custo |
|---|---|
| Hetzner CX21 (2 vCPU, 4GB RAM) — aguenta 20–30 clientes | 3.79€/mês |
| Upgrade CX31 (8GB) quando necessário | 8€/mês |
| API Anthropic (LLM) | ~0.50–2€/mês por cliente |
| AbuseIPDB free tier | 0€ |

---

## Diferenciador vs concorrência

| Feature | Operadores Telecom | NetGuard AI |
|---|---|---|
| Configuração | Genérica, fechada | 100% por cliente |
| Alertas | Nenhuns ou genéricos | Explicados em português com contexto |
| Visibilidade | Nenhuma | Dashboard Grafana em tempo real |
| Pentest | Não incluído | Anual, relatório before/after |
| Preço | Bundle com internet | Serviço autónomo + hardware próprio |

---

## Estado

⬜ Fase 4 ainda não iniciada — a iniciar após conclusão da Fase 3

---

## Como iniciar o Dia 1 da Fase 4

```
Estou a iniciar a Fase 4 do NetGuard AI. Ler CLAUDE.md e docs/fase4/fase4.md.
Quero o Dia 1 da Fase 4 detalhado — integrar Anthropic SDK Python no agente
e gerar a primeira análise de alerta de segurança em português com LLM.
```
