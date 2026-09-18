# Dia 59 — Ingestão do MITRE ATT&CK no vector store

**Fase:** 1 · **Semana:** 9 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-58 concluídos. Estado do projecto:
- src/rag/vector_store.py — VectorStore (add_documents, search)
- tests/: 266 testes, todos a passar

Quero continuar para o Dia 59: descarregar o dataset MITRE ATT&CK (técnicas
de ataque conhecidas, formato STIX/JSON oficial) e ingerir as técnicas
relevantes (rede/pfSense) no ChromaDB — a base de conhecimento que vai
enriquecer as análises LLM na Semana 10.
```

---

## Objectivo

MITRE ATT&CK é a referência standard da indústria para classificar técnicas de ataque (ex: `T1110` = Brute Force, `T1046` = Network Service Discovery). Hoje ingerimos um subconjunto relevante (técnicas de rede, não o framework completo de ~600 técnicas — a maioria não se aplica a um pfSense de PME) na colecção `mitre_attack` do ChromaDB.

```
MITRE ATT&CK Enterprise (JSON oficial, attack.mitre.org)
        ↓ filtrar técnicas relevantes para rede/perímetro
MitreTechnique (dataclass) — id, name, description, tactic
        ↓
VectorStore("mitre_attack").add_documents()
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Formato STIX 2.1 (JSON) | Formato oficial em que o MITRE distribui os dados |
| Chunking de documentos | Decidir a granularidade certa: uma técnica = um documento (não o dataset inteiro) |
| Dataset curado vs completo | Filtrar por relevância em vez de ingerir tudo às cegas |
| `requests` + cache local de ficheiro | Evitar re-descarregar ~40MB a cada execução |

---

## Steps

### Step 1 — Descarregar o dataset MITRE ATT&CK Enterprise

```python
# scripts/download_mitre_attack.py
from __future__ import annotations

from pathlib import Path

import requests

_MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
_CACHE_PATH = Path("data/rag_sources/mitre_attack.json")


def download(force: bool = False) -> Path:
    if _CACHE_PATH.exists() and not force:
        print(f"Já existe cache em {_CACHE_PATH} — usa force=True para re-descarregar")
        return _CACHE_PATH

    _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    print(f"A descarregar MITRE ATT&CK de {_MITRE_URL} (~40MB)...")
    resp = requests.get(_MITRE_URL, timeout=60)
    resp.raise_for_status()
    _CACHE_PATH.write_bytes(resp.content)
    print(f"Guardado em {_CACHE_PATH}")
    return _CACHE_PATH


if __name__ == "__main__":
    download()
```

```bash
python scripts/download_mitre_attack.py
echo "data/rag_sources/*.json" >> .gitignore
```

---

### Step 2 — `src/rag/mitre_loader.py` — filtrar e extrair técnicas relevantes

```python
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

# Tácticas relevantes para um agente de perímetro de rede (pfSense) — o
# framework completo cobre muito mais (ex: técnicas pós-exploração em
# endpoints Windows, fora do âmbito de um firewall).
_RELEVANT_TACTICS = {
    "reconnaissance", "initial-access", "command-and-control",
    "exfiltration", "discovery", "lateral-movement",
}


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str  # ex: "T1110"
    name: str
    description: str
    tactics: list[str]

    def to_document_text(self) -> str:
        return f"{self.technique_id} — {self.name}: {self.description}"


def load_relevant_techniques(json_path: Path) -> list[MitreTechnique]:
    data = json.loads(json_path.read_text(encoding="utf-8"))
    techniques: list[MitreTechnique] = []

    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        tactics = [
            phase["phase_name"] for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        if not any(t in _RELEVANT_TACTICS for t in tactics):
            continue

        technique_id = next(
            (ref["external_id"] for ref in obj.get("external_references", [])
             if ref.get("source_name") == "mitre-attack"),
            None,
        )
        if technique_id is None:
            continue

        description = obj.get("description", "").split("\n")[0][:500]  # primeira frase, truncada
        techniques.append(MitreTechnique(
            technique_id=technique_id, name=obj.get("name", ""),
            description=description, tactics=tactics,
        ))

    return techniques
```

---

### Step 3 — `scripts/ingest_mitre.py`

```python
from __future__ import annotations

from pathlib import Path

from scripts.download_mitre_attack import download
from src.rag.mitre_loader import load_relevant_techniques
from src.rag.vector_store import VectorStore


def main() -> None:
    json_path = download()
    techniques = load_relevant_techniques(json_path)
    print(f"{len(techniques)} técnicas relevantes filtradas de rede/perímetro")

    store = VectorStore("mitre_attack")
    store.add_documents(
        texts=[t.to_document_text() for t in techniques],
        ids=[t.technique_id for t in techniques],
        metadatas=[{"tactics": ",".join(t.tactics), "source": "mitre"} for t in techniques],
    )
    print(f"Ingeridas {store.count()} técnicas na colecção 'mitre_attack'")


if __name__ == "__main__":
    main()
```

```bash
python scripts/ingest_mitre.py
```

---

### Step 4 — Confirmar com uma pesquisa manual

```bash
python -c "
from src.rag.vector_store import VectorStore
store = VectorStore('mitre_attack')
results = store.search('alguém a tentar várias palavras-passe SSH', n_results=3)
for r in results:
    print(f'[{r.distance:.3f}] {r.text[:100]}')
"
```

Deve devolver `T1110 — Brute Force` (ou técnica relacionada) entre os resultados mais relevantes.

---

### Step 5 — `tests/test_mitre_loader.py`

Testar com um fixture JSON reduzido (não o dataset completo de 40MB) — construído directamente no teste:

```python
from __future__ import annotations

import json
from pathlib import Path

from src.rag.mitre_loader import load_relevant_techniques

_FIXTURE = {
    "objects": [
        {
            "type": "attack-pattern",
            "name": "Brute Force",
            "description": "Adversaries may use brute force techniques.\nMore detail here.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1110"}],
        },
        {
            "type": "attack-pattern",
            "name": "Network Service Discovery",
            "description": "Adversaries may attempt to get a listing of services.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1046"}],
        },
        {
            "type": "attack-pattern",
            "name": "Irrelevant Post-Exploitation Technique",
            "description": "Not relevant to network perimeter.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
        },
        {
            "type": "attack-pattern",
            "name": "Revoked Technique",
            "revoked": True,
            "description": "Should be excluded.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T0001"}],
        },
        {"type": "malware", "name": "Should be ignored — not attack-pattern"},
    ]
}


def test_filters_only_relevant_tactics(tmp_path: Path) -> None:
    path = tmp_path / "mitre.json"
    path.write_text(json.dumps(_FIXTURE), encoding="utf-8")
    techniques = load_relevant_techniques(path)
    ids = {t.technique_id for t in techniques}
    assert "T1110" in ids
    assert "T1046" in ids
    assert "T9999" not in ids  # táctica irrelevante


def test_excludes_revoked_techniques(tmp_path: Path) -> None:
    path = tmp_path / "mitre.json"
    path.write_text(json.dumps(_FIXTURE), encoding="utf-8")
    techniques = load_relevant_techniques(path)
    ids = {t.technique_id for t in techniques}
    assert "T0001" not in ids


def test_to_document_text_includes_id_and_name(tmp_path: Path) -> None:
    path = tmp_path / "mitre.json"
    path.write_text(json.dumps(_FIXTURE), encoding="utf-8")
    techniques = load_relevant_techniques(path)
    brute_force = next(t for t in techniques if t.technique_id == "T1110")
    text = brute_force.to_document_text()
    assert "T1110" in text
    assert "Brute Force" in text
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 266 + 3 = 269 testes

ruff check src/
mypy src/rag/mitre_loader.py --strict --ignore-missing-imports

git add src/rag/mitre_loader.py scripts/download_mitre_attack.py scripts/ingest_mitre.py \
        tests/test_mitre_loader.py .gitignore
git commit -m "feat: dia 59 — ingestão do MITRE ATT&CK (técnicas de rede) no ChromaDB"
```

---

## Checklist

- [ ] Dataset MITRE ATT&CK descarregado e cacheado localmente
- [ ] `load_relevant_techniques()` filtra por tácticas relevantes + exclui revoked/deprecated
- [ ] `scripts/ingest_mitre.py` popula a colecção `mitre_attack`
- [ ] Pesquisa manual confirma retrieval semântico correcto (ex: "força bruta SSH" → T1110)
- [ ] 3 testes com fixture JSON reduzido a passar
- [ ] `python -m pytest tests/ -v` → 269 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/rag/mitre_loader.py` | `MitreTechnique`, `load_relevant_techniques()` |
| `scripts/download_mitre_attack.py` | Download com cache local |
| `scripts/ingest_mitre.py` | Ingestão no ChromaDB |
| `tests/test_mitre_loader.py` | 3 testes |

**Próximo dia:** Dia 60 — ingestão do OWASP Top 10 no vector store
