# Dia 71 — Dockerfile do agente

**Fase:** 1 · **Semana:** 11 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-70 concluídos — Semana 10 fechada (tag `semana10`). Estado do projecto:
- Agente completo: ingestão, regras, ML, RAG, LLM, agente LangGraph
- src/api/ — FastAPI completa
- tests/: 302 testes, todos a passar
- CLAUDE.md — stack: "Containers | Docker + docker-compose (Fase 4)" — mas o
  roadmap real da Fase 1 (fase1.md, actualizado ao longo das semanas)
  antecipou isto para a Semana 11, porque o deployment em VPS (arquitectura
  multi-tenant do CLAUDE.md) precisa de um artefacto reproduzível antes
  do fim da Fase 1

Quero continuar para o Dia 71: Dockerfile do agente NetGuard AI — imagem
single-container que corre o pipeline de ingestão + API, para instalação
reprodutível em qualquer VPS/servidor de cliente.
```

---

## Objectivo

Até agora o agente corre a partir do código-fonte numa venv local (a VM de desenvolvimento). Para uma instalação de cliente real (VPS Hetzner, arquitectura do `CLAUDE.md`), precisa de um artefacto: `docker build` + `docker run`, sem depender de replicar manualmente o ambiente Python 3.12 + dependências de sistema (weasyprint precisa de libs do SO, ver Dia 43).

```
Dockerfile (multi-stage)
  Stage 1 "builder": instala dependências Python num venv isolado
  Stage 2 "runtime": imagem final, só com o necessário para correr
        ↓
docker build -t netguard-ai:latest .
        ↓
docker run netguard-ai:latest
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Multi-stage Docker build | Reduzir tamanho da imagem final — ferramentas de build não vão para produção |
| `python:3.12-slim` como base | Imagem oficial mínima, não a `python:3.12` completa (mais pequena, menos superfície de ataque) |
| `.dockerignore` | Evitar copiar `.venv/`, `data/*.db`, `__pycache__` para dentro da imagem |
| `HEALTHCHECK` no Dockerfile | Docker/orquestrador sabe quando o container está realmente pronto |
| Utilizador não-root no container | Boa prática de segurança — nunca correr como root desnecessariamente |

---

## Steps

### Step 1 — `.dockerignore`

```
.venv/
__pycache__/
*.pyc
.git/
.pytest_cache/
htmlcov/
data/*.db
data/models/*.joblib
data/reports/*.pdf
data/chroma*
data/rag_sources/*.json
.env
```

---

### Step 2 — `Dockerfile`

```dockerfile
# ── Stage 1: builder ─────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# dependências de sistema necessárias para compilar/instalar alguns packages
# (weasyprint precisa de libs nativas — Dia 43; scapy precisa de libpcap)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e ".[api,reports,ml,rag,agent,metrics,capture,analysis]"

# ── Stage 2: runtime ──────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# dependências de sistema em runtime (weasyprint precisa destas mesmo depois
# de instalado — Pango/Cairo são bibliotecas partilhadas, não só de build)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
    libpcap0.8 shared-mime-info \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash netguard

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app
COPY src/ src/
COPY templates/ templates/
COPY data/rules.yaml data/rules.yaml
COPY data/rag_sources/owasp_top10.yaml data/rag_sources/owasp_top10.yaml
COPY scripts/ scripts/

RUN mkdir -p /app/data && chown -R netguard:netguard /app
USER netguard

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)" || exit 1

EXPOSE 8000 5514/udp

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

> Nota de design: `scapy` requer `libpcap` — capacidades de captura ao vivo (`LiveSniffer`, Dia 32) dentro de um container precisam de `--cap-add=NET_RAW --cap-add=NET_ADMIN` no `docker run` (documentado no Dia 72, `docker-compose`). O `Dockerfile` por si só não concede privilégios de rede elevados — decisão de segurança correcta, concedida explicitamente só quando necessário.

---

### Step 3 — Build e teste manual

```bash
docker build -t netguard-ai:latest .

docker run -p 8000:8000 --env-file .env netguard-ai:latest &
sleep 3
curl http://localhost:8000/health
# {"status":"ok"}
```

Confirmar o tamanho da imagem (multi-stage deve produzir algo bem mais pequeno que instalar tudo numa imagem só):

```bash
docker images netguard-ai:latest
```

---

### Step 4 — `scripts/verify_docker_build.sh` — smoke test de CI

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "A construir imagem Docker..."
docker build -t netguard-ai:test .

echo "A arrancar container de teste..."
docker run -d --name netguard-test -p 18000:8000 -e API_KEY=test_key netguard-ai:test

echo "A aguardar healthcheck..."
for i in $(seq 1 15); do
    status=$(docker inspect --format='{{.State.Health.Status}}' netguard-test 2>/dev/null || echo "starting")
    if [ "$status" = "healthy" ]; then
        echo "Container saudável."
        docker rm -f netguard-test
        exit 0
    fi
    sleep 2
done

echo "FALHA: container não ficou saudável a tempo."
docker logs netguard-test
docker rm -f netguard-test
exit 1
```

```bash
chmod +x scripts/verify_docker_build.sh
./scripts/verify_docker_build.sh
```

---

### Step 5 — Qualidade e commit

Não há testes `pytest` novos hoje — é infraestrutura, validada pelo smoke test do Step 4, não pela suite unitária (padrão já usado no Dia 24, Grafana).

```bash
python -m pytest tests/ -v
# 302 testes, sem alteração — suite continua a passar dentro E fora do container

git add Dockerfile .dockerignore scripts/verify_docker_build.sh
git commit -m "feat: dia 71 — Dockerfile multi-stage do agente NetGuard AI"
```

---

## Checklist

- [ ] `.dockerignore` exclui `.venv/`, dados locais, `.env`
- [ ] Dockerfile multi-stage — builder com ferramentas de compilação, runtime sem elas
- [ ] Utilizador não-root (`netguard`) no runtime
- [ ] `HEALTHCHECK` configurado, usa o endpoint `/health` já existente
- [ ] Imagem builda e arranca correctamente (`docker build` + `docker run`)
- [ ] `scripts/verify_docker_build.sh` confirma healthcheck automaticamente
- [ ] Suite `pytest` continua a passar (302 testes)
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `Dockerfile` | Build multi-stage do agente |
| `.dockerignore` | Exclusões do contexto de build |
| `scripts/verify_docker_build.sh` | Smoke test de build+healthcheck |

**Tamanho da imagem final:** *(preencher com o resultado real de `docker images`)*

**Próximo dia:** Dia 72 — docker-compose local (agente + volumes)
