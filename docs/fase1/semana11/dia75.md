# Dia 75 — CI: GitHub Actions — testes automáticos em cada push

**Fase:** 1 · **Semana:** 11 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-74 concluídos. Estado do projecto:
- Dockerfile + docker-compose completos e testados
- tests/: 306 testes rápidos + 4 testes docker (310 total)
- CLAUDE.md — stack: "CI/CD | GitHub Actions"
- Até agora "python -m pytest tests/ -v" é corrido manualmente a cada dia,
  nunca automaticamente num push/PR

Quero continuar para o Dia 75: primeiro workflow GitHub Actions — correr a
suite de testes rápida automaticamente em cada push, para nunca mais
depender de lembrar de correr os testes manualmente antes de commitar.
```

---

## Objectivo

75 dias de disciplina manual ("correr pytest antes de cada commit") é frágil — um dia de pressa e um teste partido passa despercebido. Hoje isso deixa de depender de memória humana.

```
git push
        ↓
GitHub Actions dispara workflow
        ↓
Setup Python 3.12 + dependências de sistema (weasyprint, scapy)
        ↓
pytest -m "not docker"  (suite rápida — Docker-in-Docker fica para um workflow futuro se necessário)
        ↓
✅/❌ visível no GitHub, bloqueia merge se falhar (com branch protection)
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| GitHub Actions workflow YAML | `.github/workflows/ci.yml` |
| `actions/setup-python` | Provisiona Python na máquina virtual do runner |
| Cache de dependências (`actions/cache` ou `setup-python` cache nativo) | Acelerar runs repetidos — não reinstalar tudo a cada push |
| Matrix de versões (preparação, não usada ainda) | GitHub Actions suporta correr contra múltiplas versões Python — hoje só 3.12, documentado como extensível |
| Branch protection rules (configuração no GitHub, não em código) | Impede merge de PRs com CI vermelho |

---

## Steps

### Step 1 — `.github/workflows/ci.yml`

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
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: "pip"

      - name: Instalar dependências de sistema (weasyprint, scapy)
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
            libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
            libpcap-dev shared-mime-info

      - name: Instalar dependências Python
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev,api,reports,ml,rag,agent,metrics,capture,analysis]"

      - name: Correr testes (suite rápida)
        run: pytest tests/ -v -m "not docker" --cov=src --cov-report=term-missing

      - name: Lint (ruff)
        run: ruff check src/
```

---

### Step 2 — Push e confirmar no GitHub

```bash
git add .github/workflows/ci.yml
git commit -m "ci: dia 75 — workflow GitHub Actions para testes automáticos"
git push
```

Confirmar no separador **Actions** do repositório GitHub que o workflow corre e passa. Se `pip install` do ChromaDB/scikit-learn demorar muito (dependências pesadas), o cache do `setup-python` (`cache: "pip"`) reduz isso drasticamente a partir da segunda execução.

---

### Step 3 — Badge de estado no `docs/README.md`

```markdown
[![CI](https://github.com/<utilizador>/netsec/actions/workflows/ci.yml/badge.svg)](https://github.com/<utilizador>/netsec/actions/workflows/ci.yml)
```

(Substituir `<utilizador>` pelo nome real da conta/organização GitHub do repositório.)

---

### Step 4 — Configurar branch protection (via UI do GitHub, não código)

**Settings → Branches → Add branch protection rule** para `master`:
- Require status checks to pass before merging → seleccionar o job `test`
- Require branches to be up to date before merging

Isto é configuração de repositório, não algo commitável — registar aqui como checklist manual a fazer uma vez.

---

### Step 5 — Testar o CI a falhar deliberadamente (confirmar que bloqueia correctamente)

Numa branch de teste isolada, introduzir um erro deliberado (`assert False` num teste temporário), fazer push, confirmar que o workflow falha e aparece vermelho no GitHub — depois reverter.

```bash
git checkout -b test-ci-failure
echo "def test_ci_bloqueia_falhas(): assert False" >> tests/test_network_utils.py
git add -A && git commit -m "test: confirmar que CI bloqueia falhas (a reverter)"
git push -u origin test-ci-failure
# confirmar vermelho no GitHub Actions
git checkout netsec-0
git branch -D test-ci-failure
git push origin --delete test-ci-failure
```

---

### Step 6 — Commit final

```bash
python -m pytest tests/ -v -m "not docker"
# 310 testes, sem alteração — hoje é só infraestrutura CI

git add docs/README.md
git commit -m "docs: dia 75 — badge de CI no README"
```

---

## Checklist

- [ ] `.github/workflows/ci.yml` corre em cada push e PR
- [ ] Dependências de sistema (weasyprint, scapy) instaladas no runner
- [ ] Cache de pip configurado — runs subsequentes mais rápidos
- [ ] Badge de CI visível no `docs/README.md`
- [ ] Branch protection configurada para `master` (checklist manual confirmado)
- [ ] Testado deliberadamente que um teste falho bloqueia o CI (vermelho no GitHub)
- [ ] Suite continua a passar localmente
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `.github/workflows/ci.yml` | Workflow de testes automáticos |
| `docs/README.md` | Badge de estado CI |

**Confirmação de funcionamento:** *(preencher — link para a execução do workflow no GitHub, resultado do teste de falha deliberada)*

**Próximo dia:** Dia 76 — CI: lint + mypy + build da imagem Docker
