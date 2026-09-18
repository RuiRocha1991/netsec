# Dia 63 — Revisão da Semana 9: análise enriquecida com contexto

**Fase:** 1 · **Semana:** 9 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-62 concluídos. Estado do projecto:
- src/rag/ completo — vector_store, mitre_loader, owasp_loader, retriever, evaluation
- src/llm/client.py — analyze_alert_with_context() (RAG-enriched)
- src/llm/analysis_queue.py — usa a versão enriquecida
- tests/: 278 testes, todos a passar

Quero continuar para o Dia 63: revisão end-to-end da Semana 9 — confirmar
que um evento HIGH real, de ponta a ponta, produz uma explicação em
português que cita a técnica MITRE/categoria OWASP correcta.
```

---

## Objectivo

Fechar o ciclo completo: evento pfSense → regra → análise LLM enriquecida com RAG → Telegram, com a técnica MITRE citada na explicação final, tal como desenhado no Dia 61.

---

## Steps

### Step 1 — Garantir que ambas as colecções RAG estão populadas

```bash
python scripts/ingest_mitre.py
python scripts/ingest_owasp.py
python scripts/evaluate_retrieval.py
```

Confirmar Recall@3 ≥ 75% (Dia 62) antes de prosseguir — se estiver abaixo, este é o momento de ajustar `build_retrieval_query()` ou as descrições curadas do OWASP, não mais tarde.

---

### Step 2 — Teste end-to-end manual completo

```bash
python scripts/run_syslog_server.py --log-level INFO &

python -c "
from src.parsers.ingest_pipeline import IngestPipeline
p = IngestPipeline()
line = ('Sep 17 10:30:45 pfsense filterlog[1]: '
        '5,,,0,em0,match,block,in,4,0x0,,64,1234,0,none,6,tcp,60,'
        '185.220.101.45,192.168.10.50,54321,22,0,S,111,0,0,mss')
p.process_line(line)
"

sleep 3

curl -H "X-API-Key: $API_KEY" http://localhost:8000/events?limit=1
# copiar o id do evento
curl -H "X-API-Key: $API_KEY" http://localhost:8000/events/<id>/analysis
```

**Confirmar no output de `/analysis`:** o campo `summary` deve conter uma referência a `T1110` (ou técnica equivalente), fruto do contexto RAG injectado no Dia 61.

Confirmar no Telegram: a mensagem de follow-up (Dia 56) também deve reflectir a explicação enriquecida.

---

### Step 3 — Auditoria de custo com RAG activo

O prompt enriquecido (Dia 61) é maior que o prompt base (Dia 51) — mais tokens de entrada por chamada. Confirmar o impacto no orçamento:

```bash
curl -H "X-API-Key: $API_KEY" http://localhost:8000/llm/usage
```

Comparar `input_tokens` médio por chamada antes (Semana 8, ~500 tokens estimados no Dia 54) vs depois do RAG (provavelmente 800-1200 tokens, consoante o tamanho dos documentos recuperados). Se o custo subir significativamente, considerar truncar `context_docs` para `k_per_source=1` em vez de `2` (`SecurityKnowledgeRetriever.retrieve`) — decisão a documentar, não a aplicar cegamente sem medir primeiro.

---

### Step 4 — Suite completa

```bash
python -m pytest tests/ -v --tb=short
ruff check src/
mypy src/rag/ src/llm/ --strict --ignore-missing-imports
```

---

### Step 5 — Documentar decisões da Semana 9 em `docs/fase1/fase1.md`

| Decisão | Motivo |
|---|---|
| MITRE ATT&CK filtrado por tácticas de rede/perímetro, não o dataset completo | A maioria das ~600 técnicas não se aplica a um agente baseado em pfSense |
| OWASP Top 10 curado manualmente em YAML, não extraído de API | Não existe dataset JSON oficial estruturado; conteúdo editorial beneficia de curadoria humana |
| `k_per_source` do retriever ajustado com base em custo medido, não intuição | Ver Step 3 — trade-off explícito entre qualidade de contexto e custo por chamada |

---

### Step 6 — Commit de fecho da Semana 9

```bash
git add docs/fase1/fase1.md
git commit -m "docs: dia 63 — revisão e validação end-to-end da Semana 9"

git tag -a semana9 -m "Semana 9 concluída — RAG (MITRE ATT&CK + OWASP Top 10) integrado, 278 testes"
```

---

## Checklist

- [ ] Ambas as colecções RAG populadas e com Recall@3 ≥ 75%
- [ ] Evento end-to-end produz análise com citação de técnica MITRE/OWASP
- [ ] Follow-up Telegram reflecte a explicação enriquecida
- [ ] Impacto de custo do RAG medido e documentado (não assumido)
- [ ] Decisões da semana documentadas em `fase1.md`
- [ ] Suite completa a passar
- [ ] `mypy src/rag/ src/llm/ --strict` sem erros
- [ ] Tag `semana9` criada
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Validação end-to-end:** *(preencher — o resultado real da análise de teste, se citou a técnica correcta)*

**Estado final da Semana 9:**

| Componente | Ficheiro |
|---|---|
| Vector store | `src/rag/vector_store.py` |
| Ingestão MITRE | `src/rag/mitre_loader.py` |
| Ingestão OWASP | `src/rag/owasp_loader.py` |
| Retriever combinado | `src/rag/retriever.py` |
| Avaliação de retrieval | `src/rag/evaluation.py` |
| Análise LLM enriquecida | `src/llm/client.py::analyze_alert_with_context` |

**Testes:** 278 testes · todos a passar

---

## Próxima semana: Semana 10

**Tema:** LangGraph — agente autónomo com tool use

| Dia | Tema |
|---|---|
| 64 | LangGraph — StateGraph, nodes e edges |
| 65 | Tools do agente: consultar BD e AbuseIPDB |
| 66 | Tool: consultar RAG (MITRE/OWASP) |
| 67 | Grafo de decisão — triagem automática de alertas |
| 68 | Human-in-the-loop — escalação de casos incertos |
| 69 | Memória do agente e logging de decisões |
| 70 | Revisão Semana 10 |
