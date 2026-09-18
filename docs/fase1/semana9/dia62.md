# Dia 62 — Avaliação da qualidade do retrieval

**Fase:** 1 · **Semana:** 9 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-61 concluídos. Estado do projecto:
- src/rag/retriever.py — SecurityKnowledgeRetriever
- src/rag/vector_store.py — VectorStore (mitre_attack, owasp_top10)
- tests/: 276 testes, todos a passar

Quero continuar para o Dia 62: até agora só confirmámos o RAG "olhando" para
os resultados manualmente (Dias 58-61). Hoje construímos um conjunto de
casos de teste com resultado esperado conhecido, para detectar regressões
de qualidade de retrieval sempre que o dataset ou a query builder mudarem.
```

---

## Objectivo

Retrieval semântico pode degradar silenciosamente — uma alteração no `build_retrieval_query()` ou uma actualização do dataset MITRE pode piorar a relevância sem que nenhum teste unitário tradicional (que só verifica "devolveu uma lista") apanhe isso. Hoje: um pequeno "golden set" de queries com a técnica/categoria esperada, corrido como teste de integração.

```
golden_set.yaml — pares (evento simulado, technique_id esperado)
        ↓
scripts/evaluate_retrieval.py
        ↓
hit_rate = % de casos onde o resultado esperado está no top-K
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Golden set / test set curado | Padrão comum em sistemas de retrieval e ML para detecção de regressão |
| Recall@K | Métrica: o documento certo está entre os K primeiros resultados? |
| Testes de integração com dependência externa real (ChromaDB populado) | Diferente dos testes unitários com mocks dos dias anteriores |

---

## Steps

### Step 1 — `tests/golden_sets/retrieval_golden_set.yaml`

```yaml
# Casos de teste de retrieval — cada caso tem uma query simulando um alerta
# real e o ID da técnica/categoria que ESPERAMOS encontrar no top-3.
cases:
  - description: "SSH brute force de IP externo"
    query: "Tentativa SSH de IP externo — evento de HIGH severidade envolvendo protocolo tcp porto 22"
    expected_id: "T1110"
    source: mitre

  - description: "Port scan — muitos portos distintos"
    query: "Port scan detectado — múltiplas tentativas em portos diferentes do mesmo IP"
    expected_id: "T1046"
    source: mitre

  - description: "Acesso a área de admin sem autenticação"
    query: "Utilizador acedeu a endpoint de administração sem sessão válida"
    expected_id: "A01"
    source: owasp

  - description: "Falta de logging detectado"
    query: "Sistema sem registo suficiente para detectar incidentes de segurança"
    expected_id: "A09"
    source: owasp
```

---

### Step 2 — `src/rag/evaluation.py`

```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from src.rag.vector_store import VectorStore


@dataclass(frozen=True)
class RetrievalCase:
    description: str
    query: str
    expected_id: str
    source: str


@dataclass(frozen=True)
class RetrievalEvalResult:
    case: RetrievalCase
    found_at_rank: int | None  # None = não encontrado no top-K
    top_results: list[str]


def load_golden_set(path: Path) -> list[RetrievalCase]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [RetrievalCase(**c) for c in data["cases"]]


def evaluate_case(case: RetrievalCase, store: VectorStore, k: int = 3) -> RetrievalEvalResult:
    results = store.search(case.query, n_results=k)
    ids = [r.metadata.get("id") or r.text.split(" — ")[0] for r in results]
    found_at = next((i + 1 for i, doc_id in enumerate(ids) if doc_id == case.expected_id), None)
    return RetrievalEvalResult(case=case, found_at_rank=found_at, top_results=ids)


def recall_at_k(results: list[RetrievalEvalResult]) -> float:
    if not results:
        return 0.0
    hits = sum(1 for r in results if r.found_at_rank is not None)
    return hits / len(results)
```

> Nota de implementação: o `id` do documento (`T1110`, `A01`) precisa de estar recuperável a partir do resultado — como `VectorStore.search()` não devolve o `id` do ChromaDB directamente (só `documents`, `distances`, `metadatas`), a forma mais simples é extrair o prefixo do texto (`to_document_text()` começa sempre por `"{id} — ..."`, ver Dias 59-60) — ajustar `RetrievedDocument`/`VectorStore.search()` para incluir também o `id` explicitamente, se preferires um acoplamento menos frágil que "parsear o início do texto".

---

### Step 3 — `scripts/evaluate_retrieval.py`

```python
from __future__ import annotations

from pathlib import Path

from src.rag.evaluation import evaluate_case, load_golden_set, recall_at_k
from src.rag.vector_store import VectorStore

_GOLDEN_SET = Path("tests/golden_sets/retrieval_golden_set.yaml")


def main() -> None:
    cases = load_golden_set(_GOLDEN_SET)
    mitre_store = VectorStore("mitre_attack")
    owasp_store = VectorStore("owasp_top10")

    results = []
    for case in cases:
        store = mitre_store if case.source == "mitre" else owasp_store
        result = evaluate_case(case, store)
        results.append(result)
        status = f"✓ rank {result.found_at_rank}" if result.found_at_rank else "✗ não encontrado"
        print(f"[{status}] {case.description} (esperado: {case.expected_id})")
        if result.found_at_rank is None:
            print(f"    Top resultados: {result.top_results}")

    recall = recall_at_k(results)
    print(f"\nRecall@3: {recall:.1%} ({sum(1 for r in results if r.found_at_rank)}/{len(results)})")


if __name__ == "__main__":
    main()
```

```bash
# garantir que ambas as colecções estão populadas (Dias 59-60)
python scripts/ingest_mitre.py
python scripts/ingest_owasp.py
python scripts/evaluate_retrieval.py
```

**Meta:** Recall@3 ≥ 75% no golden set — abaixo disso, revisitar `build_retrieval_query()` (Dia 61) ou o texto dos documentos ingeridos (descrições demasiado técnicas/curtas prejudicam o matching semântico).

---

### Step 4 — `tests/test_retrieval_evaluation.py`

Teste de integração real (não mockado) — requer as colecções populadas; skip se vazias:

```python
from __future__ import annotations

from pathlib import Path

import pytest

from src.rag.evaluation import evaluate_case, load_golden_set, recall_at_k
from src.rag.vector_store import VectorStore

_GOLDEN_SET = Path("tests/golden_sets/retrieval_golden_set.yaml")

_mitre_store = VectorStore("mitre_attack")
_owasp_store = VectorStore("owasp_top10")
_COLLECTIONS_POPULATED = _mitre_store.count() > 0 and _owasp_store.count() > 0

pytestmark = pytest.mark.skipif(
    not _COLLECTIONS_POPULATED,
    reason="Colecções ChromaDB não populadas — correr scripts/ingest_mitre.py e ingest_owasp.py",
)


class TestRetrievalGoldenSet:
    def test_golden_set_loads(self) -> None:
        cases = load_golden_set(_GOLDEN_SET)
        assert len(cases) >= 4

    def test_recall_meets_minimum_threshold(self) -> None:
        cases = load_golden_set(_GOLDEN_SET)
        results = [
            evaluate_case(c, _mitre_store if c.source == "mitre" else _owasp_store)
            for c in cases
        ]
        recall = recall_at_k(results)
        assert recall >= 0.75, f"Recall@3 abaixo do esperado: {recall:.1%}"
```

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 276 + 2 = 278 testes (2 SKIPPED se colecções não populadas no ambiente de teste)

ruff check src/
mypy src/rag/evaluation.py --strict --ignore-missing-imports

git add tests/golden_sets/ src/rag/evaluation.py scripts/evaluate_retrieval.py \
        tests/test_retrieval_evaluation.py
git commit -m "feat: dia 62 — avaliação de retrieval com golden set (recall@k)"
```

---

## Checklist

- [ ] `tests/golden_sets/retrieval_golden_set.yaml` com casos MITRE e OWASP
- [ ] `evaluate_case()` e `recall_at_k()` implementados
- [ ] `scripts/evaluate_retrieval.py` corre e reporta recall@3
- [ ] Recall@3 ≥ 75% no golden set actual
- [ ] Teste de integração com skip condicional se colecções vazias
- [ ] `python -m pytest tests/ -v` → 278 (2 podem aparecer SKIPPED consoante ambiente)
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `tests/golden_sets/retrieval_golden_set.yaml` | Casos de teste com resultado esperado |
| `src/rag/evaluation.py` | `evaluate_case()`, `recall_at_k()` |
| `scripts/evaluate_retrieval.py` | Script de avaliação |
| `tests/test_retrieval_evaluation.py` | 2 testes de integração |

**Resultado da avaliação:** *(preencher com o recall@3 real obtido)*

**Próximo dia:** Dia 63 — revisão da Semana 9: análise enriquecida com contexto MITRE/OWASP
