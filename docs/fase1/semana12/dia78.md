# Dia 78 — Checklist de entrega final

**Fase:** 1 · **Semana:** 12 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-77 concluídos — Semana 11 fechada (tag `semana11`). 77 dias de
desenvolvimento produziram o agente completo: ingestão, regras, threat
intel, dashboards, ML, relatórios, LLM, RAG, agente autónomo, Docker, CI/CD.
tests/: ~310+ testes, todos a passar.

fase1.md (secção "Entrega final", linha ~12-23) define o que a Fase 1
deveria entregar:
- Recebe logs pfSense em tempo real via syslog UDP ✓ (Semana 2)
- Parseia e persiste em SQLite ✓ (Semana 1-2)
- Enriquece com GeoIP e AbuseIPDB ✓ (Semana 2)
- Detecta anomalias com ML (Isolation Forest) ✓ (Semana 6)
- Expõe via FastAPI ✓ (Semana 3)
- Visualiza em Grafana ✓ (Semana 4)
- Alerta no Telegram ✓ (Semana 3, 10)
- Gera relatório PDF semanal automático ✓ (Semana 7)

Quero continuar para o Dia 78: verificar sistematicamente, item a item, que
cada linha da "Entrega final" está genuinamente cumprida — não assumir,
confirmar com um comando ou teste concreto para cada uma.
```

---

## Objectivo

Distinguir "está no código" de "está confirmado a funcionar". Hoje é uma auditoria ponto-a-ponto contra a especificação original do `fase1.md`, escrita no Dia 1 antes de qualquer código existir — o teste definitivo de que a Fase 1 entrega o que prometeu.

---

## Steps

### Step 1 — Checklist "Entrega final" com evidência concreta por item

Correr cada verificação e registar o resultado (não só ✓/✗, mas o comando/output que prova):

```bash
# 1. Recebe logs pfSense em tempo real via syslog UDP
python scripts/run_syslog_server.py --no-enrich &
python scripts/send_test_syslog.py
curl -H "X-API-Key: $API_KEY" http://localhost:8000/stats
# EVIDÊNCIA: total de eventos > 0 confirma recepção UDP → parse → persistência

# 2. Parseia e persiste em SQLite
sqlite3 data/netsec.db "SELECT COUNT(*) FROM events;"
# EVIDÊNCIA: contagem > 0

# 3. Enriquece com GeoIP e AbuseIPDB
sqlite3 data/netsec.db "SELECT src_ip, geo_country, abuse_score FROM events WHERE geo_country IS NOT NULL LIMIT 5;"
# EVIDÊNCIA: pelo menos alguns eventos externos têm geo_country/abuse_score preenchidos

# 4. Detecta anomalias com ML (Isolation Forest)
python scripts/train_model.py
python -c "from src.ml.anomaly_scorer import AnomalyScorer; print(AnomalyScorer().run_once())"
# EVIDÊNCIA: modelo treina e corre scoring sem erro

# 5. Expõe via FastAPI
curl -H "X-API-Key: $API_KEY" http://localhost:8000/docs
# EVIDÊNCIA: Swagger UI acessível, lista todos os endpoints

# 6. Visualiza em Grafana
curl -u admin:$GRAFANA_ADMIN_PASSWORD http://localhost:3000/api/dashboards/uid/netguard-overview
# EVIDÊNCIA: dashboard existe e devolve os 6 painéis (Semana 4)

# 7. Alerta no Telegram
python -c "
from src.alerts.telegram_notifier import TelegramNotifier
n = TelegramNotifier()
print('Enviado:', n.send('Teste de verificação Dia 78'))
"
# EVIDÊNCIA: mensagem chega ao bot

# 8. Gera relatório PDF semanal automático
python scripts/generate_weekly_report.py
ls -la data/reports/*.pdf
# EVIDÊNCIA: ficheiro PDF gerado, > 0 bytes, magic bytes %PDF- válidos
```

---

### Step 2 — Verificar itens implícitos do CLAUDE.md não listados explicitamente na "Entrega final" mas parte da promessa do produto

- [ ] Regra gold de rede reflectida no motor de regras (`data/rules.yaml` — bloqueios IOT→GREEN, etc.)
- [ ] Multi-tenant (VPS central) — **não implementado na Fase 1** (é Fase 4, documentar explicitamente como fora de âmbito, não como falha)
- [ ] Pentest anual — **não implementado na Fase 1** (é Fase 3, idem)
- [ ] Agente Python com ML + LLM — ✓ confirmado nos steps acima

---

### Step 3 — Registar gaps encontrados (se algum item falhar a verificação)

Se algum item da checklist não passar na verificação real (não no "deveria funcionar"), documentar aqui exactamente o que falhou e criar um item de acção — não avançar para o Dia 79 com itens da "Entrega final" ainda por confirmar.

---

### Step 4 — Actualizar `docs/fase1/fase1.md`

Marcar a secção "Entrega final" com o estado real confirmado, e adicionar uma nota explícita separando o que é entrega da Fase 1 do que é Fase 3/4 (para não haver ambiguidade para quem ler o documento mais tarde).

---

### Step 5 — Commit

```bash
git add docs/fase1/fase1.md
git commit -m "docs: dia 78 — checklist de entrega final verificado com evidência"
```

---

## Checklist

- [ ] Todos os 8 itens da "Entrega final" verificados com comando/evidência concreta, não assumidos
- [ ] Itens fora de âmbito da Fase 1 (multi-tenant, pentest) marcados explicitamente como tal, não como gaps
- [ ] Quaisquer gaps encontrados documentados com plano de acção
- [ ] `fase1.md` actualizado com o resultado real da verificação
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Resultado da verificação item-a-item:** *(preencher com o resultado real de cada um dos 8 pontos)*

**Gaps encontrados (se algum):** *(preencher ou "nenhum")*

**Próximo dia:** Dia 79 — documentação técnica e arquitectura
