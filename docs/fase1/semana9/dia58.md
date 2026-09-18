# Dia 58 — ChromaDB: setup e embeddings

**Fase:** 1 · **Semana:** 9 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-57 concluídos. Estado do projecto:
- src/llm/chains.py — build_simple_chain() com LangChain
- tests/: 262 testes, todos a passar
- Packages: langchain, langchain-anthropic, chromadb, anthropic, scikit-learn,
  joblib, weasyprint, jinja2, apscheduler, pandas, matplotlib, scapy, fastapi,
  influxdb-client, pyyaml, requests, python-dotenv, geoip2

Quero continuar para o Dia 58: ChromaDB (CLAUDE.md — "Vector store | ChromaDB")
— base de dados vectorial para RAG. Hoje só os fundamentos: embeddings,
inserir documentos, pesquisa por similaridade. A ingestão real de MITRE/OWASP
fica para os Dias 59-60.
```

---

## Objectivo

RAG (Retrieval-Augmented Generation) significa: antes de perguntar ao LLM, procurar documentos relevantes numa base de conhecimento e incluí-los no prompt. Hoje aprendemos o mecanismo de busca — **embeddings** (representações numéricas de texto que capturam significado) e **similaridade vectorial** (documentos com significado parecido ficam "perto" no espaço vectorial).

```
Texto ("tentativa de SSH brute force")
        ↓ embedding model
Vector [0.021, -0.384, 0.156, ...]  (ex: 1536 dimensões)
        ↓ ChromaDB armazena + indexa
Query similar → distância vectorial pequena → documento relevante encontrado
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `chromadb.PersistentClient` | Cliente ChromaDB com persistência em disco |
| Embedding function | Função que converte texto → vector (ChromaDB tem uma por defeito, ou custom) |
| `collection.add()` / `collection.query()` | Inserir documentos / pesquisar por similaridade |
| Distância coseno vs euclidiana | Métricas de "proximidade" entre vectores — ChromaDB usa coseno por defeito |
| Metadata em documentos | Filtrar resultados por atributos (ex: `source: "mitre"`) além da similaridade |

---

## Steps

### Step 1 — Instalar ChromaDB (já listado no `pyproject.toml` do Dia 57, confirmar instalação)

```bash
pip install chromadb
```

---

### Step 2 — Experimentar interactivamente

```python
# scripts/chromadb_demo.py
from __future__ import annotations

import chromadb


def main() -> None:
    client = chromadb.PersistentClient(path="data/chroma_demo")
    collection = client.get_or_create_collection("demo")

    collection.add(
        documents=[
            "Um port scan é uma técnica onde um atacante testa múltiplos portos de um sistema.",
            "Ataques de força bruta tentam adivinhar palavras-passe por tentativa e erro.",
            "SQL injection explora falhas em queries de base de dados mal validadas.",
            "O tempo hoje está soalheiro em Lisboa.",  # ruído deliberado, não relacionado
        ],
        ids=["doc1", "doc2", "doc3", "doc4"],
    )

    results = collection.query(
        query_texts=["alguém está a tentar várias palavras-passe no meu servidor"],
        n_results=2,
    )
    print("Documentos mais relevantes:")
    for doc, distance in zip(results["documents"][0], results["distances"][0], strict=True):
        print(f"  [{distance:.3f}] {doc}")


if __name__ == "__main__":
    main()
```

```bash
python scripts/chromadb_demo.py
```

Confirmar que `doc2` (força bruta) surge como mais relevante, e `doc4` (tempo em Lisboa, sem relação) fica com distância claramente maior — prova de que a busca é semântica, não por palavras-chave literais.

---

### Step 3 — `src/rag/__init__.py` e `src/rag/vector_store.py`

```bash
mkdir -p src/rag
touch src/rag/__init__.py
```

```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import chromadb

_DEFAULT_PATH = Path("data/chroma")


@dataclass(frozen=True)
class RetrievedDocument:
    text: str
    distance: float
    metadata: dict


class VectorStore:
    """Wrapper fino sobre ChromaDB — inserção e pesquisa por similaridade."""

    def __init__(self, collection_name: str, persist_path: Path = _DEFAULT_PATH) -> None:
        self.client = chromadb.PersistentClient(path=str(persist_path))
        self.collection = self.client.get_or_create_collection(collection_name)

    def add_documents(
        self, texts: list[str], ids: list[str], metadatas: list[dict] | None = None,
    ) -> None:
        self.collection.add(documents=texts, ids=ids, metadatas=metadatas)

    def search(self, query: str, n_results: int = 5) -> list[RetrievedDocument]:
        results = self.collection.query(query_texts=[query], n_results=n_results)
        if not results["documents"] or not results["documents"][0]:
            return []
        docs = results["documents"][0]
        distances = results["distances"][0]
        metadatas = results["metadatas"][0] if results.get("metadatas") else [{}] * len(docs)
        return [
            RetrievedDocument(text=d, distance=dist, metadata=meta or {})
            for d, dist, meta in zip(docs, distances, metadatas, strict=True)
        ]

    def count(self) -> int:
        return self.collection.count()
```

---

### Step 4 — `tests/test_vector_store.py`

```python
from __future__ import annotations

from pathlib import Path

import pytest

from src.rag.vector_store import VectorStore


@pytest.fixture
def store(tmp_path: Path) -> VectorStore:
    return VectorStore("test_collection", persist_path=tmp_path / "chroma")


class TestVectorStore:
    def test_add_and_count(self, store: VectorStore) -> None:
        store.add_documents(["texto de teste"], ids=["doc1"])
        assert store.count() == 1

    def test_search_returns_relevant_document(self, store: VectorStore) -> None:
        store.add_documents(
            [
                "Ataques de força bruta tentam adivinhar palavras-passe.",
                "O tempo está soalheiro hoje.",
            ],
            ids=["security", "weather"],
        )
        results = store.search("tentativas de login falhadas", n_results=1)
        assert len(results) == 1
        assert results[0].text.startswith("Ataques de força bruta")

    def test_search_empty_collection_returns_empty_list(self, store: VectorStore) -> None:
        assert store.search("qualquer coisa") == []

    def test_metadata_preserved(self, store: VectorStore) -> None:
        store.add_documents(
            ["documento com metadata"], ids=["doc1"], metadatas=[{"source": "teste"}],
        )
        results = store.search("documento", n_results=1)
        assert results[0].metadata["source"] == "teste"
```

> Nota de performance: estes testes usam a embedding function por defeito do ChromaDB (modelo local pequeno, `all-MiniLM-L6-v2`), que é descarregada na primeira execução — a primeira corrida da suite após instalar `chromadb` pode demorar mais (download do modelo, cache local depois disso).

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 262 + 4 = 266 testes

ruff check src/
mypy src/rag/vector_store.py --strict --ignore-missing-imports

echo "data/chroma*" >> .gitignore

git add src/rag/ scripts/chromadb_demo.py tests/test_vector_store.py .gitignore
git commit -m "feat: dia 58 — ChromaDB VectorStore (add/search por similaridade)"
```

---

## Checklist

- [ ] `scripts/chromadb_demo.py` demonstra busca semântica (não por palavra-chave)
- [ ] `VectorStore.add_documents()` e `.search()` implementados
- [ ] Metadata preservada nos resultados de pesquisa
- [ ] `data/chroma*` no `.gitignore` (dados persistidos, não versionados)
- [ ] 4 testes a passar
- [ ] `python -m pytest tests/ -v` → 266 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/rag/__init__.py` | Package rag |
| `src/rag/vector_store.py` | `VectorStore`, `RetrievedDocument` |
| `scripts/chromadb_demo.py` | Demo de busca semântica |
| `tests/test_vector_store.py` | 4 testes |

**Próximo dia:** Dia 59 — ingestão do MITRE ATT&CK no vector store
