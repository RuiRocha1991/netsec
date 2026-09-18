# Dia 77 — Revisão da Semana 11: pipeline CI/CD funcional

**Fase:** 1 · **Semana:** 11 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-76 concluídos. Estado do projecto:
- Dockerfile multi-stage + docker-compose.yml (agente+InfluxDB+Grafana)
- Docker Secrets suportados via read_secret()
- .github/workflows/ci.yml — 3 jobs paralelos (test, quality, docker-build)
- tests/: 310 testes, todos a passar

Quero continuar para o Dia 77: revisão end-to-end da Semana 11 e simulação
de um deployment real num VPS — validar o caminho completo "código no git"
até "agente a correr num servidor", tal como aconteceria na primeira
instalação de um cliente real.
```

---

## Objectivo

Simular o cenário real: um VPS Hetzner novo (arquitectura `CLAUDE.md`), git clone, configurar secrets, `docker compose up`, confirmado a funcionar — sem nenhum passo que só existe "na cabeça" do developer e não está documentado nem versionado.

---

## Steps

### Step 1 — Simular um "VPS limpo" localmente

```bash
# clone fresco para uma pasta separada, simula uma máquina nova
git clone ~/projects/netsec /tmp/netguard-deploy-test
cd /tmp/netguard-deploy-test
git checkout netsec-0
```

---

### Step 2 — Configurar secrets como um cliente real faria

```bash
cp .env.example .env
# preencher .env manualmente com valores de teste (não os reais de produção)

mkdir -p secrets
echo "sk-ant-test-key" > secrets/anthropic_api_key.txt
echo "fake_telegram_token" > secrets/telegram_bot_token.txt
echo "fake_abuseipdb_key" > secrets/abuseipdb_api_key.txt
```

---

### Step 3 — Deployment completo

```bash
docker compose -f docker-compose.yml -f docker-compose.secrets.yml up -d --build
sleep 20

curl http://localhost:8000/health
curl -u admin:$GRAFANA_ADMIN_PASSWORD http://localhost:3000/api/health
```

**Se algum passo falhar aqui que não falhou antes**, é sinal de dependência implícita não documentada — corrigir a documentação/scripts, não só "fazer funcionar desta vez".

---

### Step 4 — Confirmar o ciclo completo de dados

```bash
docker compose exec agent python scripts/generate_test_log.py
docker compose exec agent python scripts/ingest_log.py

curl -H "X-API-Key: $API_KEY" http://localhost:8000/stats
```

---

### Step 5 — Limpar o ambiente de simulação

```bash
docker compose -f docker-compose.yml -f docker-compose.secrets.yml down -v
cd ~/projects/netsec
rm -rf /tmp/netguard-deploy-test
```

---

### Step 6 — Documentar o guião de deployment em `docs/fase1/fase1.md`

Adicionar uma secção "Guião de instalação num VPS novo" com os passos exactos validados no Step 1-4 — este documento torna-se a base do "guião de demo para clientes" da Semana 12 (Dia 80).

---

### Step 7 — Verificar o CI completo uma última vez

```bash
python -m pytest tests/ -v --tb=short
# suite completa, incluindo testes docker (Dia 74) — ~310+ testes

ruff check src/
mypy src/ --strict --ignore-missing-imports
```

Confirmar no GitHub que os 3 jobs do workflow (Dia 75-76) continuam verdes na branch actual.

---

### Step 8 — Documentar decisões da Semana 11

| Decisão | Motivo |
|---|---|
| Multi-stage Dockerfile, não single-stage | Imagem final mais pequena, menos superfície de ataque |
| `cap_add: NET_RAW/NET_ADMIN` só no serviço `agent` | Least privilege — só quem precisa de captura de pacotes recebe o privilégio |
| Docker Secrets via convenção `_FILE`, não hardcoded em env vars | Caminho de evolução para multi-tenant (Fase 4) sem reescrever código de leitura de secrets |
| Testes `docker` marcados e separados dos rápidos | Suite dia-a-dia continua a correr em segundos, não minutos |
| 3 jobs CI paralelos (não sequenciais) | Feedback mais rápido — falha de lint não espera pela suite completa de testes |

---

### Step 9 — Commit de fecho da Semana 11

```bash
git add docs/fase1/fase1.md
git commit -m "docs: dia 77 — guião de deployment validado, fecho Semana 11"

git tag -a semana11 -m "Semana 11 concluída — Docker + CI/CD completos, deployment validado end-to-end"
```

---

## Checklist

- [ ] Deployment simulado do zero (clone fresco) funciona sem passos escondidos
- [ ] Secrets via ficheiro (Docker Secrets) testados end-to-end
- [ ] Ciclo completo de dados confirmado (ingest → API → stats)
- [ ] Guião de deployment documentado em `fase1.md`
- [ ] Suite completa (~310+ testes) a passar
- [ ] `mypy src/ --strict` sem erros
- [ ] CI (3 jobs) verde no GitHub
- [ ] Decisões da semana documentadas
- [ ] Tag `semana11` criada
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros alterados:**

| Ficheiro | Descrição |
|---|---|
| `docs/fase1/fase1.md` | Guião de instalação num VPS novo, decisões da Semana 11 |

**Estado final da Semana 11:**

| Componente | Ficheiro |
|---|---|
| Imagem Docker | `Dockerfile` |
| Stack completa | `docker-compose.yml` |
| Secrets de produção | `docker-compose.secrets.yml`, `src/config/secrets.py` |
| CI | `.github/workflows/ci.yml` |
| Testes de integração no container | `tests/test_docker_integration.py` |

**Testes:** ~310+ testes · todos a passar

---

## Próxima semana: Semana 12

**Tema:** Entrega da Fase 1

| Dia | Tema |
|---|---|
| 78 | Checklist de entrega final (revisão de `fase1.md`) |
| 79 | Documentação técnica e arquitectura |
| 80 | Guião de demo para clientes |
| 81 | Hardening — erros e logging de produção |
| 82 | Performance e profiling básico |
| 83 | Revisão final de segurança do próprio agente |
| 84 | Fecho da Fase 1 — tag `fase1-v1` |
