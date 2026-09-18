# NetGuard AI — Documentação do projecto

> Ficheiro principal de navegação. O contexto completo está em `CLAUDE.md` na raiz.
> Este ficheiro serve apenas para navegar rapidamente para o dia em curso.

---

## Estado actual

**Fase 1 · Semana 1 · Dia 7 — próximo**

| Item | Valor |
|---|---|
| VM Ubuntu | `192.168.0.43` · alias `netsec-vm` |
| Projecto | `~/projects/netsec` |
| Activar venv | `source .venv/bin/activate` |
| Testes | `python -m pytest tests/ -v` → 64 passed |

---

## Roadmap

| Fase | Meses | Foco | Contexto |
|---|---|---|---|
| **1** | 1–3 | Python + redes + agente base | [`fase1/fase1.md`](fase1/fase1.md) |
| **2** | 4–6 | pfSense + lab RED/GREEN/DMZ | [`fase2/fase2.md`](fase2/fase2.md) |
| **3** | 7–12 | Pentesting + relatórios | [`fase3/fase3.md`](fase3/fase3.md) |
| **4** | 13–18 | Produto + IA + clientes | [`fase4/fase4.md`](fase4/fase4.md) |

---

## Fase 1 — dias

```
docs/fase1/
├── fase1.md                   ← contexto completo da fase
├── semana1/
│   ├── dia1.md  ✅  Configuração do ambiente
│   ├── dia2.md  ✅  Python core (tipos, comprehensions, walrus)
│   ├── dia3.md  ✅  Wireshark + tshark + pyshark
│   ├── dia4.md  ✅  Funções de rede (NetworkZone, DANGEROUS_PORTS)
│   ├── dia5.md  ✅  LogEntry dataclass
│   ├── dia6.md  ✅  Parser pfSense filterlog
│   └── dia7.md  ⬜  Pipeline completo: ficheiro log → SQLite
├── semana2/
│   ├── dia8.md  ⬜  Suporte IPv6 + regex avançado
│   ├── dia9.md  ⬜  Servidor syslog UDP com threading
│   ├── dia10.md ⬜  Queries SQLite avançadas + Pandas
│   ├── dia11.md ⬜  Motor de regras YAML
│   ├── dia12.md ⬜  AbuseIPDB threat intel com cache
│   ├── dia13.md ⬜  GeoIP MaxMind GeoLite2 offline
│   └── dia14.md ⬜  Pipeline completo + revisão Semana 2
├── semana3/
│   ├── dia15.md ⬜  FastAPI base — /health, /events, /stats
│   ├── dia16.md ⬜  Pydantic models e validação de inputs
│   ├── dia17.md ⬜  Paginação, filtros e ordenação
│   ├── dia18.md ⬜  Alertas Telegram Bot em tempo real
│   ├── dia19.md ⬜  Webhook pfSense → FastAPI (IngestPipeline)
│   ├── dia20.md ⬜  Autenticação API key
│   └── dia21.md ⬜  Testes e2e httpx/uvicorn + revisão Semana 3
├── semana4/  (planos escritos)
│   ├── dia22.md ⬜  InfluxDB — conceitos e client Python
│   ├── dia23.md ⬜  Escrever métricas no InfluxDB
│   ├── dia24.md ⬜  Grafana — instalação e primeiro dashboard
│   ├── dia25.md ⬜  Provisioning Grafana como código
│   ├── dia26.md ⬜  Painéis: top IPs, zonas, alertas HIGH
│   ├── dia27.md ⬜  Alertas Grafana + testes InfluxDB writer
│   └── dia28.md ⬜  Revisão Semana 4 — dashboard completo
├── semana5/
│   ├── dia29.md ⬜  Agregações temporais avançadas (Pandas)
│   ├── dia30.md ⬜  Heatmap de ataques por hora/dia
│   ├── dia31.md ⬜  Top talkers e baseline de tráfego
│   ├── dia32.md ⬜  Captura live com Scapy — fundamentos
│   ├── dia33.md ⬜  Perfil de baseline IoT
│   ├── dia34.md ⬜  Detecção de desvio ao baseline IoT
│   └── dia35.md ⬜  Revisão Semana 5
├── semana6/
│   ├── dia36.md ⬜  Feature engineering
│   ├── dia37.md ⬜  Janelas temporais e agregações por IP
│   ├── dia38.md ⬜  Isolation Forest — primeiro modelo
│   ├── dia39.md ⬜  Treino e avaliação do modelo
│   ├── dia40.md ⬜  Persistência do modelo (joblib)
│   ├── dia41.md ⬜  Integração do scoring ML no pipeline
│   └── dia42.md ⬜  Revisão Semana 6
├── semana7/
│   ├── dia43.md ⬜  weasyprint — fundamentos HTML→PDF
│   ├── dia44.md ⬜  Template do relatório semanal (Jinja2)
│   ├── dia45.md ⬜  Gráficos no relatório PDF
│   ├── dia46.md ⬜  Agendamento do relatório (APScheduler)
│   ├── dia47.md ⬜  Refactoring e consolidação de módulos
│   ├── dia48.md ⬜  mypy --strict limpo + cobertura de testes
│   └── dia49.md ⬜  Checkpoint "Fase 1 v1" — demo end-to-end
├── semana8/
│   ├── dia50.md ⬜  Anthropic SDK — setup e primeira chamada
│   ├── dia51.md ⬜  Prompt design para análise em português
│   ├── dia52.md ⬜  Structured output com Pydantic
│   ├── dia53.md ⬜  Integração no pipeline de alertas
│   ├── dia54.md ⬜  Gestão de custo e tokens
│   ├── dia55.md ⬜  Cache de respostas LLM
│   └── dia56.md ⬜  Revisão Semana 8
├── semana9/
│   ├── dia57.md ⬜  LangChain — conceitos e chains básicas
│   ├── dia58.md ⬜  ChromaDB — setup e embeddings
│   ├── dia59.md ⬜  Ingestão do MITRE ATT&CK
│   ├── dia60.md ⬜  Ingestão do OWASP Top 10
│   ├── dia61.md ⬜  RAG chain para análise enriquecida
│   ├── dia62.md ⬜  Avaliação da qualidade do retrieval
│   └── dia63.md ⬜  Revisão Semana 9
├── semana10/
│   ├── dia64.md ⬜  LangGraph — StateGraph, nodes e edges
│   ├── dia65.md ⬜  Tools: consultar BD e AbuseIPDB
│   ├── dia66.md ⬜  Tool: consultar RAG
│   ├── dia67.md ⬜  Grafo de decisão — triagem automática
│   ├── dia68.md ⬜  Human-in-the-loop
│   ├── dia69.md ⬜  Memória do agente e logging de decisões
│   └── dia70.md ⬜  Revisão Semana 10
├── semana11/
│   ├── dia71.md ⬜  Dockerfile do agente
│   ├── dia72.md ⬜  docker-compose local
│   ├── dia73.md ⬜  Variáveis de ambiente e secrets em Docker
│   ├── dia74.md ⬜  Teste de integração end-to-end no container
│   ├── dia75.md ⬜  CI — GitHub Actions: testes automáticos
│   ├── dia76.md ⬜  CI — lint + mypy + build da imagem
│   └── dia77.md ⬜  Revisão Semana 11
└── semana12/
    ├── dia78.md ⬜  Checklist de entrega final
    ├── dia79.md ⬜  Documentação técnica e arquitectura
    ├── dia80.md ⬜  Guião de demo para clientes
    ├── dia81.md ⬜  Hardening — erros e logging de produção
    ├── dia82.md ⬜  Performance e profiling básico
    ├── dia83.md ⬜  Revisão final de segurança do agente
    └── dia84.md ⬜  Fecho da Fase 1 — tag `fase1-v1`
```

**Próximo:** Dia 7 — pipeline completo: ficheiro log → SQLite

---

## Como retomar

1. Verificar que tudo passa: `python -m pytest tests/ -v`
2. Abrir `docs/fase1/semana1/diaN.md` para o dia em curso
3. Copiar o bloco "Prompt de contexto" se precisar de iniciar sessão nova

**Verificação rápida:**
```bash
cd ~/projects/netsec && source .venv/bin/activate
python -m pytest tests/ -v && ruff check src/ && echo "✓ tudo ok"
```
