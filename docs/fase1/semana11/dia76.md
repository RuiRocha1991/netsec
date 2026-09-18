# Dia 76 — CI: lint + mypy + build da imagem Docker

**Fase:** 1 · **Semana:** 11 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-75 concluídos. Estado do projecto:
- .github/workflows/ci.yml — testes automáticos (Dia 75)
- Dockerfile validado manualmente (Dia 71)
- tests/: 310 testes, todos a passar

Quero continuar para o Dia 76: completar o pipeline CI — hoje só corre
testes; falta mypy --strict (regressão de tipos), e confirmar que a imagem
Docker builda com sucesso a cada push (apanhar Dockerfiles quebrados antes
de chegarem a produção).
```

---

## Objectivo

Um `Dockerfile` pode passar despercebidamente quebrado durante semanas se ninguém o reconstruir manualmente — o CI deve builda-lo a cada push, tal como corre os testes.

```
.github/workflows/ci.yml (Dia 75, testes)
        +
job "quality": ruff + mypy --strict
        +
job "docker-build": docker build (sem push ainda — isso é deployment, fora do âmbito hoje)
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Jobs paralelos no GitHub Actions | `test`, `quality`, `docker-build` correm em simultâneo, não sequencialmente — CI mais rápido |
| `docker/build-push-action` (GitHub Action oficial) | Build optimizado com cache de layers entre execuções |
| GitHub Actions cache para layers Docker (`cache-from`/`cache-to`) | Evitar rebuild completo a cada push quando só o código da aplicação muda |
| `needs:` entre jobs | Definir dependências quando um job depende do resultado de outro (não usado hoje — jobs independentes) |

---

## Steps

### Step 1 — Reestruturar `.github/workflows/ci.yml` em jobs paralelos

```yaml
name: CI

on:
  push:
    branches: ["**"]
  pull_request:
    branches: [master]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: "pip"
      - name: Instalar dependências de sistema
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
            libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
            libpcap-dev shared-mime-info
      - name: Instalar dependências Python
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev,api,reports,ml,rag,agent,metrics,capture,analysis]"
      - name: Testes
        run: pytest tests/ -v -m "not docker" --cov=src --cov-report=term-missing

  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: "pip"
      - name: Instalar dependências
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev,api,reports,ml,rag,agent,metrics,capture,analysis]"
      - name: ruff
        run: ruff check src/
      - name: mypy --strict
        run: mypy src/ --strict --ignore-missing-imports

  docker-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      - name: Build da imagem (sem push)
        uses: docker/build-push-action@v5
        with:
          context: .
          push: false
          tags: netguard-ai:ci
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

---

### Step 2 — Confirmar todos os 3 jobs no GitHub Actions após push

```bash
git add .github/workflows/ci.yml
git commit -m "ci: dia 76 — jobs paralelos test/quality/docker-build"
git push
```

Confirmar no separador Actions: 3 jobs a correr em paralelo, todos verdes.

---

### Step 3 — Actualizar branch protection para exigir os 3 jobs

**Settings → Branches → editar a regra de `master`** — adicionar `quality` e `docker-build` aos status checks obrigatórios (além de `test`, já configurado no Dia 75).

---

### Step 4 — Corrigir eventuais erros mypy que só aparecem no ambiente CI limpo

É comum o `mypy` comportar-se ligeiramente diferente num ambiente CI "limpo" (sem cache local de tipos acumulado) do que na máquina de desenvolvimento — se surgirem erros novos aqui que nunca apareceram localmente, corrigir como qualquer erro de tipo normal (não é uma falha do CI, é uma lacuna que só o ambiente limpo revelou).

```bash
# reproduzir localmente o ambiente exacto do CI, se necessário:
rm -rf .mypy_cache
mypy src/ --strict --ignore-missing-imports
```

---

### Step 5 — Medir o tempo total do workflow e optimizar se necessário

Se o `docker-build` demorar muito (imagem grande, muitas dependências), confirmar que o cache `type=gha` está de facto a reduzir o tempo entre a 1ª e a 2ª execução (comparar os tempos no separador Actions). Se não estiver a ajudar, revisitar a ordem das camadas do `Dockerfile` (Dia 71) — camadas que mudam pouco (instalação de dependências) devem vir antes das que mudam muito (código da aplicação), para maximizar reuso de cache.

---

### Step 6 — Commit final

```bash
python -m pytest tests/ -v -m "not docker"
# 310 testes, sem alteração — infraestrutura CI

git add .github/workflows/ci.yml
git commit -m "ci: dia 76 — confirmar jobs paralelos e optimização de cache Docker"
```

---

## Checklist

- [ ] 3 jobs (`test`, `quality`, `docker-build`) correm em paralelo no CI
- [ ] `mypy --strict` corre no CI, não só localmente
- [ ] `docker build` corre a cada push, apanha Dockerfiles quebrados cedo
- [ ] Cache de layers Docker (`type=gha`) configurado e a funcionar
- [ ] Branch protection actualizada para exigir os 3 jobs
- [ ] Tempo total do workflow razoável (idealmente < 5min com cache quente)
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros alterados:**

| Ficheiro | Descrição |
|---|---|
| `.github/workflows/ci.yml` | 3 jobs paralelos: test, quality, docker-build |

**Tempos observados:** *(preencher com os tempos reais do primeiro e segundo run, para confirmar que o cache ajuda)*

**Próximo dia:** Dia 77 — revisão da Semana 11: pipeline CI/CD funcional
