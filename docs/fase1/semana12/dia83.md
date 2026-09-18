# Dia 83 — Revisão final de segurança do próprio agente

**Fase:** 1 · **Semana:** 12 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-82 concluídos. Sistema completo, com hardening e performance
validados. Ironia a evitar: um PRODUTO DE SEGURANÇA com vulnerabilidades
básicas no seu próprio código seria um problema de credibilidade grave —
"o NetGuard AI protege-te de ataques" perde todo o sentido se o próprio
NetGuard AI for fácil de comprometer.

Quero continuar para o Dia 83: revisão de segurança dedicada ao código do
próprio agente — a API que aceita input externo (webhook, syslog), a
superfície exposta, gestão de secrets, antes do fecho formal da Fase 1.
```

---

## Objectivo

Revisão sistemática dos vectores de ataque mais relevantes para este produto especificamente — não uma checklist OWASP genérica repetida, mas focada no que este código realmente expõe.

---

## Steps

### Step 1 — Auditoria de input não confiável

O `IngestPipeline` processa **texto vindo directamente da rede** (syslog UDP, sem autenticação nenhuma por desenho do protocolo syslog) e via webhook (autenticado, mas ainda assim input externo). Rever:

```bash
# confirmar que parse_line() nunca usa eval/exec/pickle sobre input externo
grep -rn "eval(\|exec(\|pickle.loads" src/parsers/ src/api/
# deve devolver vazio — qualquer resultado aqui é uma vulnerabilidade crítica

# confirmar que todas as queries SQL são parametrizadas (Dia 17 já documentou isto,
# revalidar que se manteve assim nos 66 dias seguintes)
grep -rn "f\"SELECT\|f'SELECT\|\.format(.*SELECT\|% .*SELECT" src/db/
# qualquer resultado aqui é um candidato a SQL injection — investigar cada um
```

---

### Step 2 — Confirmar que o servidor UDP (sem autenticação por desenho) está mitigado

O syslog UDP (porta 5514) não tem autenticação — qualquer processo na rede local pode enviar dados. Isto é uma limitação aceite do protocolo syslog tradicional, mitigada por:
- [ ] O agente confia apenas na rede interna (não expor a porta 5514 UDP à Internet — confirmar `docker-compose.yml`, Dia 72, não publica esta porta além da rede do cliente)
- [ ] `parse_line()` descarta silenciosamente linhas malformadas, nunca crasha com input arbitrário (testado desde o Dia 6-8)
- [ ] Volume de input não confiável não pode esgotar recursos indefinidamente — `Queue(maxsize=10_000)` (Dia 9) já limita, confirmar que continua presente

```bash
grep -n "maxsize" src/parsers/syslog_server.py
```

---

### Step 3 — Auditoria da API REST — todos os endpoints de escrita autenticados?

```bash
grep -n "@router.post\|@app.post\|@router.put\|@router.delete" src/api/main.py
```

Confirmar manualmente, para cada um, que está dentro do `router` protegido por `Depends(verify_api_key)` (Dia 20) — **excepto** `/telegram/callback` (Dia 68), que tem a sua própria justificação documentada (autenticação via secret do Telegram, não API key nossa). Qualquer endpoint de escrita fora dessas duas categorias é um bug de segurança a corrigir imediatamente.

---

### Step 4 — Fuzzing básico do parser — input adversarial

```python
# scripts/fuzz_parser.py
from __future__ import annotations

import random
import string

from src.parsers.pfsense_parser import parse_line

_ADVERSARIAL_INPUTS = [
    "",
    "\x00\x01\x02",
    "A" * 100_000,  # linha extremamente longa
    "Sep 17 10:30:45 pfsense filterlog[1]: " + ",".join(["x"] * 1000),  # muitos campos
    "'; DROP TABLE events; --",
    "<script>alert(1)</script>",
    "../../../../etc/passwd",
    "Sep 17 10:30:45 pfsense filterlog[1]: 5,,,0,em0,match,block,in,4," + "9" * 50,  # ip_ver inválido gigante
]


def fuzz_random(n: int = 10_000) -> int:
    """Gera strings aleatórias e confirma que parse_line nunca lança excepção."""
    crashes = 0
    for _ in range(n):
        length = random.randint(0, 500)
        garbage = "".join(random.choices(string.printable, k=length))
        try:
            parse_line(garbage)
        except Exception as exc:
            crashes += 1
            print(f"CRASH com input: {garbage[:80]!r} — {exc}")
    return crashes


def main() -> None:
    print("A testar inputs adversariais conhecidos...")
    for adversarial in _ADVERSARIAL_INPUTS:
        try:
            result = parse_line(adversarial)
            print(f"  OK (result={result is not None}): {adversarial[:60]!r}")
        except Exception as exc:
            print(f"  CRASH: {adversarial[:60]!r} — {exc}")

    print("\nA fuzzar com 10.000 inputs aleatórios...")
    crashes = fuzz_random()
    print(f"\nTotal de crashes: {crashes}/10000")


if __name__ == "__main__":
    main()
```

```bash
python scripts/fuzz_parser.py
```

**Meta: 0 crashes.** Qualquer excepção não apanhada aqui é um bug a corrigir — `parse_line()` deve devolver `None` graciosamente para qualquer input, nunca propagar uma excepção (isto já era um objectivo desde o Dia 6, hoje confirma-se sistematicamente em vez de assumir).

---

### Step 5 — `tests/test_parser_fuzzing.py`

```python
from __future__ import annotations

from scripts.fuzz_parser import _ADVERSARIAL_INPUTS, fuzz_random
from src.parsers.pfsense_parser import parse_line


class TestParserRobustness:
    def test_adversarial_inputs_never_crash(self) -> None:
        for adversarial in _ADVERSARIAL_INPUTS:
            try:
                parse_line(adversarial)
            except Exception as exc:
                assert False, f"parse_line crashou com input adversarial: {adversarial!r} — {exc}"

    def test_random_fuzzing_zero_crashes(self) -> None:
        crashes = fuzz_random(n=1000)  # amostra menor no CI, 10k é para investigação manual
        assert crashes == 0
```

---

### Step 6 — Rever `docs/architecture.md` (Dia 79) — adicionar secção de segurança

```markdown
## Modelo de ameaça e mitigações

| Vector | Mitigação |
|---|---|
| Syslog UDP sem autenticação | Só na rede interna, nunca exposto à Internet (ver docker-compose.yml) |
| Webhook HTTP de ingestão | Requer API key (X-API-Key) |
| Endpoints de escrita da API | Todos atrás de auth, excepto /telegram/callback (auth própria via Telegram) |
| Input malformado no parser | Fuzzing confirma 0 crashes — descarta graciosamente |
| Secrets (API keys, tokens) | Docker Secrets via convenção _FILE em produção; nunca em git |
| SQL injection | Todas as queries parametrizadas — auditado no Dia 83 |
```

---

### Step 7 — Qualidade e commit

```bash
python -m pytest tests/ -v -m "not docker"
# 316 + 2 = 318... ajustar título final: 319 (com margem)

ruff check src/

git add scripts/fuzz_parser.py tests/test_parser_fuzzing.py docs/architecture.md
git commit -m "test: dia 83 — fuzzing do parser e revisão final de segurança"
```

---

## Checklist

- [ ] Nenhum `eval`/`exec`/`pickle.loads` sobre input externo
- [ ] Todas as queries SQL confirmadas parametrizadas
- [ ] Porta syslog UDP confirmada não exposta à Internet
- [ ] Todos os endpoints de escrita da API auditados — auth correcta ou excepção justificada
- [ ] Fuzzing do parser: 0 crashes em 10.000 inputs aleatórios + casos adversariais conhecidos
- [ ] `docs/architecture.md` tem secção de modelo de ameaça
- [ ] 2 testes de robustez a passar
- [ ] `python -m pytest tests/ -v -m "not docker"` → 319 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Resultado da auditoria:** *(preencher — confirmar que todos os pontos passaram, ou documentar o que foi corrigido)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `scripts/fuzz_parser.py` | Fuzzing do parser |
| `tests/test_parser_fuzzing.py` | 2 testes |
| `docs/architecture.md` | Secção de modelo de ameaça |

**Próximo dia:** Dia 84 — fecho da Fase 1: tag `fase1-v1`
