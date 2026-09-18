# Dia 48 — mypy --strict limpo + cobertura de testes

**Fase:** 1 · **Semana:** 7 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-47 concluídos. Refactoring do Dia 47 aplicado (IngestPipeline com
observers, EventQueries separado, factories de teste). Estado do projecto:
- ~15 módulos em src/, cada um com testes próprios ao longo das 7 semanas
- tests/: 229 testes, todos a passar
- mypy configurado como strict em pyproject.toml desde o Dia 1, mas nunca
  corrido sistematicamente sobre TODO o src/ de uma vez — só por ficheiro,
  dia a dia

Quero continuar para o Dia 48: correr mypy --strict sobre o projecto
completo pela primeira vez, corrigir tudo o que aparecer, e medir cobertura
de testes com pytest-cov para identificar código não testado antes do
checkpoint "Fase 1 v1" de amanhã.
```

---

## Objectivo

Módulos que passaram no `mypy --strict` isoladamente podem ainda gerar erros quando analisados em conjunto (tipos incompatíveis entre módulos, imports circulares latentes). Hoje é o primeiro "full sweep".

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `pytest-cov` | Medir % de linhas/branches cobertas pelos testes |
| `--cov-report=html` | Relatório navegável linha a linha |
| `# type: ignore[código-específico]` | Suprimir um erro mypy pontual, com justificação — nunca `# type: ignore` genérico |
| `mypy --strict` flags individuais (`disallow_untyped_defs`, `warn_return_any`, etc.) | O que `strict` realmente activa, para entender os erros |

---

## Steps

### Step 1 — Instalar pytest-cov

```bash
pip install pytest-cov
```

```toml
[project.optional-dependencies]
dev = ["ruff", "mypy", "pytest", "pytest-asyncio", "pytest-cov"]
```

---

### Step 2 — Correr mypy sobre todo o `src/`

```bash
mypy src/ --strict --ignore-missing-imports
```

Categorias de erro mais prováveis de aparecer numa base de código deste tamanho, e como resolver cada uma:

| Erro típico | Causa provável | Correcção |
|---|---|---|
| `Missing return statement` | Função com `if/else` onde um ramo não devolve | Adicionar `return` explícito no ramo em falta |
| `Argument has incompatible type` | Um `str \| None` passado onde só `str` é esperado | Adicionar guard `if x is None: raise/return` antes de usar |
| `Untyped decorator makes function untyped` | Decorator de terceiros sem stubs (ex: alguns decorators do FastAPI/APScheduler) | `# type: ignore[misc]` com comentário a explicar |
| `Cannot find implementation or library stub` | Package sem stubs (`scapy`, `geoip2` já cobertos por `ignore_missing_imports`) | Confirmar que está coberto pela flag global, ou adicionar `# type: ignore[import-untyped]` pontual |
| `Need type annotation for "x"` | Variável inferida como `Any` a partir de um dict/list sem tipo | Anotar explicitamente: `x: list[str] = []` |

Corrigir cada erro reportado — não usar `# type: ignore` como primeira opção, só depois de confirmar que a correcção "correcta" (ajustar tipos) não é directa (ex: biblioteca de terceiros genuinamente sem stubs).

---

### Step 3 — Medir cobertura

```bash
python -m pytest tests/ --cov=src --cov-report=term-missing --cov-report=html
```

```toml
# pyproject.toml
[tool.pytest.ini_options]
addopts = "--cov=src --cov-report=term-missing"
```

Abrir `htmlcov/index.html` num browser e identificar módulos com cobertura baixa. Candidatos prováveis a lacunas (código que só corre em condições raras/manuais, típico em projectos deste tipo):

- Caminhos de erro (`except Exception` genéricos) que nunca são exercitados por um teste dedicado
- `scripts/*.py` — muitos só têm `if __name__ == "__main__":`, sem teste directo (aceitável — são wrappers finos sobre código já testado nos módulos `src/`)
- Ramos de `IoTAnomalyDetector`/`AnomalyScorer` relacionados com falhas de rede/timeout

**Meta razoável para a Fase 1:** 85%+ de cobertura em `src/` (excluindo `scripts/`), não 100% — 100% de cobertura de linha não garante ausência de bugs e tem custo de manutenção desproporcional para um projecto neste estágio.

---

### Step 4 — Preencher as lacunas mais importantes

Escrever testes para os 2-3 módulos com cobertura mais baixa identificados no Step 3 — sem prescrição exacta aqui (depende do que o relatório mostrar), mas priorizar:
1. Caminhos de erro em módulos críticos para segurança (`RuleEngine`, `IngestPipeline`)
2. Lógica de negócio complexa com baixa cobertura (não getters/setters triviais)

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v --cov=src --cov-report=term-missing
# número de testes varia consoante quantos foram adicionados no Step 4

mypy src/ --strict --ignore-missing-imports
# deve terminar sem erros — "Success: no issues found in N source files"

ruff check src/

git add pyproject.toml tests/ src/
git commit -m "chore: dia 48 — mypy --strict limpo em todo o src/ + cobertura >85%"
```

---

## Checklist

- [ ] `pytest-cov` instalado e configurado
- [ ] `mypy src/ --strict --ignore-missing-imports` → "Success: no issues found"
- [ ] Todos os `# type: ignore` usados têm código específico e comentário de justificação
- [ ] Cobertura de `src/` ≥ 85% (excluindo `scripts/`)
- [ ] Lacunas mais importantes preenchidas com testes novos
- [ ] `python -m pytest tests/ -v` — suite completa a passar
- [ ] `ruff check src/` sem erros
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Correcções mypy:** *(listar aqui os erros encontrados e como foram resolvidos)*

**Cobertura antes/depois:** *(preencher com os números reais do relatório)*

**Próximo dia:** Dia 49 — checkpoint "Fase 1 v1": demo end-to-end completa
