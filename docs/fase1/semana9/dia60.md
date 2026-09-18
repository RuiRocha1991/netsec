# Dia 60 — Ingestão do OWASP Top 10 no vector store

**Fase:** 1 · **Semana:** 9 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-59 concluídos. Estado do projecto:
- src/rag/vector_store.py — VectorStore
- src/rag/mitre_loader.py — MitreTechnique, load_relevant_techniques()
- Colecção ChromaDB "mitre_attack" populada
- tests/: 269 testes, todos a passar

Quero continuar para o Dia 60: OWASP Top 10 (CLAUDE.md — "Threat intel |
AbuseIPDB... " expandido conceptualmente aqui para cobrir vulnerabilidades
web, relevante porque o HAProxy da arquitectura serve sites da DMZ) — ao
contrário do MITRE (sem API/dataset JSON oficial estruturado), aqui o
conteúdo é curado manualmente em YAML, versionado em git.
```

---

## Objectivo

O OWASP Top 10 não tem um dataset JSON oficial como o MITRE — é conteúdo textual/editorial. Hoje curamos manualmente as 10 categorias num ficheiro YAML versionado (não descarregado de uma API), reflectindo que o produto NetGuard AI protege tanto a rede (pfSense/Suricata, coberto pelo MITRE) como os sites na DMZ (HAProxy, coberto pelo OWASP).

```
data/rag_sources/owasp_top10.yaml (curado à mão, versionado em git)
        ↓
OwaspLoader.load()
        ↓
VectorStore("owasp_top10").add_documents()
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Conteúdo curado vs extraído automaticamente | Segunda fonte RAG do projecto, padrão diferente do Dia 59 |
| `yaml.safe_load()` reaproveitado do `RuleEngine` (Dia 11) | Consistência de formato no projecto |
| Múltiplas colecções ChromaDB no mesmo `PersistentClient` | Separar por fonte (`mitre_attack` vs `owasp_top10`) em vez de misturar tudo numa colecção |

---

## Steps

### Step 1 — `data/rag_sources/owasp_top10.yaml`

```yaml
# OWASP Top 10 (2021) — curado para o contexto NetGuard AI (sites na DMZ
# atrás de HAProxy). Não é o texto oficial completo — resumo accionável.
categories:
  - id: A01
    name: "Broken Access Control"
    description: >
      Falhas que permitem a um utilizador aceder a recursos ou realizar
      acções fora das suas permissões — ex: aceder à área de admin sem
      autenticação, ou aos dados de outro cliente alterando um ID na URL.
    relevance: "Sites na DMZ atrás do HAProxy — validar sempre autorização no backend, nunca confiar só no proxy."

  - id: A02
    name: "Cryptographic Failures"
    description: >
      Dados sensíveis (palavras-passe, cartões, dados pessoais) expostos por
      falta de encriptação em trânsito ou em repouso, ou uso de algoritmos fracos.
    relevance: "HAProxy com Let's Encrypt cobre TLS em trânsito — confirmar que a BD da aplicação também encripta dados sensíveis em repouso."

  - id: A03
    name: "Injection"
    description: >
      SQL injection, command injection, etc. — dados não confiáveis
      interpretados como código pela aplicação.
    relevance: "Suricata (IDS/IPS) pode detectar padrões de injection no tráfego; a mitigação real é sempre no código da aplicação (queries parametrizadas)."

  - id: A04
    name: "Insecure Design"
    description: >
      Falhas estruturais de design de segurança, não implementação — ex:
      ausência de rate limiting em endpoints de login.
    relevance: "Revisão de arquitectura antes de expor um novo site na DMZ — não é algo que o NetGuard AI detecte automaticamente, mas informa o pentest anual."

  - id: A05
    name: "Security Misconfiguration"
    description: >
      Configurações inseguras por defeito, serviços desnecessários expostos,
      mensagens de erro verbosas que revelam detalhes internos.
    relevance: "Regra gold da arquitectura NetGuard AI — bloquear tudo por defeito, só permitir o explicitamente necessário (pfSense)."

  - id: A06
    name: "Vulnerable and Outdated Components"
    description: >
      Uso de bibliotecas/frameworks com vulnerabilidades conhecidas e não corrigidas.
    relevance: "Fora do âmbito directo do NetGuard AI (é responsabilidade do cliente/developer do site) — mas o pentest anual verifica versões expostas via banner grabbing."

  - id: A07
    name: "Identification and Authentication Failures"
    description: >
      Falhas de autenticação — palavras-passe fracas, sessões não expiram,
      sem MFA.
    relevance: "SSH exposto (porta 22) é o vector mais comum detectado pelo NetGuard AI (ver regra ssh_brute_force) — mesma categoria de falha aplicada à infraestrutura, não só a aplicações web."

  - id: A08
    name: "Software and Data Integrity Failures"
    description: >
      Assumir integridade de software/dados sem verificação — ex: auto-updates
      sem verificação de assinatura, CI/CD sem controlo de integridade.
    relevance: "Relevante para a Semana 11 (CI/CD do próprio NetGuard AI) — praticar o que se prega."

  - id: A09
    name: "Security Logging and Monitoring Failures"
    description: >
      Falta de logging suficiente para detectar e responder a incidentes
      em tempo útil.
    relevance: "Esta é literalmente a categoria que o NetGuard AI resolve para os seus clientes — o produto inteiro é a mitigação desta categoria a nível de rede."

  - id: A10
    name: "Server-Side Request Forgery (SSRF)"
    description: >
      Aplicação faz requests para URLs controladas pelo atacante, potencialmente
      acedendo a recursos internos não expostos.
    relevance: "Regra gold DMZ→GREEN bloqueada por defeito limita o impacto mesmo que um site na DMZ seja comprometido via SSRF."
```

---

### Step 2 — `src/rag/owasp_loader.py`

```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class OwaspCategory:
    category_id: str
    name: str
    description: str
    relevance: str

    def to_document_text(self) -> str:
        return (
            f"{self.category_id} — {self.name}: {self.description.strip()} "
            f"Relevância para NetGuard AI: {self.relevance}"
        )


def load_owasp_categories(yaml_path: Path) -> list[OwaspCategory]:
    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    return [
        OwaspCategory(
            category_id=c["id"], name=c["name"],
            description=c["description"], relevance=c["relevance"],
        )
        for c in data.get("categories", [])
    ]
```

---

### Step 3 — `scripts/ingest_owasp.py`

```python
from __future__ import annotations

from pathlib import Path

from src.rag.owasp_loader import load_owasp_categories
from src.rag.vector_store import VectorStore

_YAML_PATH = Path("data/rag_sources/owasp_top10.yaml")


def main() -> None:
    categories = load_owasp_categories(_YAML_PATH)
    print(f"{len(categories)} categorias OWASP Top 10 carregadas")

    store = VectorStore("owasp_top10")
    store.add_documents(
        texts=[c.to_document_text() for c in categories],
        ids=[c.category_id for c in categories],
        metadatas=[{"source": "owasp"} for c in categories],
    )
    print(f"Ingeridas {store.count()} categorias na colecção 'owasp_top10'")


if __name__ == "__main__":
    main()
```

```bash
python scripts/ingest_owasp.py
```

---

### Step 4 — Confirmar com pesquisa manual

```bash
python -c "
from src.rag.vector_store import VectorStore
store = VectorStore('owasp_top10')
results = store.search('alguém a tentar aceder à área de admin sem login', n_results=2)
for r in results:
    print(f'[{r.distance:.3f}] {r.text[:120]}')
"
```

---

### Step 5 — `tests/test_owasp_loader.py`

```python
from __future__ import annotations

from pathlib import Path

import yaml

from src.rag.owasp_loader import load_owasp_categories

_FIXTURE = {
    "categories": [
        {
            "id": "A01", "name": "Broken Access Control",
            "description": "Falhas de autorização.", "relevance": "Muito relevante.",
        },
        {
            "id": "A03", "name": "Injection",
            "description": "SQL injection etc.", "relevance": "Relevante para Suricata.",
        },
    ]
}


class TestOwaspLoader:
    def test_loads_all_categories(self, tmp_path: Path) -> None:
        path = tmp_path / "owasp.yaml"
        path.write_text(yaml.dump(_FIXTURE), encoding="utf-8")
        categories = load_owasp_categories(path)
        assert len(categories) == 2

    def test_category_fields_parsed(self, tmp_path: Path) -> None:
        path = tmp_path / "owasp.yaml"
        path.write_text(yaml.dump(_FIXTURE), encoding="utf-8")
        categories = load_owasp_categories(path)
        a01 = next(c for c in categories if c.category_id == "A01")
        assert a01.name == "Broken Access Control"

    def test_to_document_text_includes_relevance(self, tmp_path: Path) -> None:
        path = tmp_path / "owasp.yaml"
        path.write_text(yaml.dump(_FIXTURE), encoding="utf-8")
        categories = load_owasp_categories(path)
        text = categories[0].to_document_text()
        assert "Relevância para NetGuard AI" in text
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 269 + 3 = 272 testes

ruff check src/
mypy src/rag/owasp_loader.py --strict --ignore-missing-imports

git add data/rag_sources/owasp_top10.yaml src/rag/owasp_loader.py \
        scripts/ingest_owasp.py tests/test_owasp_loader.py
git commit -m "feat: dia 60 — ingestão do OWASP Top 10 curado (YAML) no ChromaDB"
```

---

## Checklist

- [ ] `data/rag_sources/owasp_top10.yaml` versionado em git (conteúdo curado, não gerado)
- [ ] Cada categoria tem `relevance` ligada explicitamente ao contexto NetGuard AI
- [ ] `load_owasp_categories()` e `scripts/ingest_owasp.py` implementados
- [ ] Colecção `owasp_top10` separada de `mitre_attack` (fontes distintas)
- [ ] Pesquisa manual confirma retrieval correcto
- [ ] 3 testes a passar
- [ ] `python -m pytest tests/ -v` → 272 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `data/rag_sources/owasp_top10.yaml` | Conteúdo curado, versionado |
| `src/rag/owasp_loader.py` | `OwaspCategory`, `load_owasp_categories()` |
| `scripts/ingest_owasp.py` | Ingestão no ChromaDB |
| `tests/test_owasp_loader.py` | 3 testes |

**Próximo dia:** Dia 61 — RAG chain para análise enriquecida com contexto MITRE/OWASP
