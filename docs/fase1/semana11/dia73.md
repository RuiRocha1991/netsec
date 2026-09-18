# Dia 73 — Variáveis de ambiente e secrets em Docker

**Fase:** 1 · **Semana:** 11 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-72 concluídos. Estado do projecto:
- docker-compose.yml — agente + InfluxDB + Grafana
- .env.example acumulou ~15 variáveis ao longo de 72 dias (ver ficheiro)
- tests/: 302 testes, todos a passar

Quero continuar para o Dia 73: revisão de segurança de como secrets (API
keys, tokens, passwords) chegam ao container — .env funciona bem em
desenvolvimento, mas tem riscos numa instalação de cliente real (VPS
partilhado por múltiplos clientes, arquitectura multi-tenant do CLAUDE.md).
```

---

## Objectivo

`.env` com `env_file:` no compose (Dia 72) é aceitável para um único cliente/VPS dedicado, mas o `CLAUDE.md` descreve uma arquitectura **multi-tenant** — vários clientes agregados no mesmo VPS Hetzner. Hoje: validação de que os secrets de um cliente nunca vazam para outro, e um caminho de migração documentado para Docker Secrets quando a arquitectura multi-tenant for implementada (Fase 4).

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Docker Secrets (`docker secret create`) vs env vars | Mecanismo mais seguro — secrets nunca aparecem em `docker inspect` nem `ps aux` |
| `_FILE` suffix convention (`API_KEY_FILE=/run/secrets/api_key`) | Padrão comum para apps que leem secrets de ficheiro em vez de env var |
| `.env` no `.gitignore` — auditoria de que nunca foi commitado | Verificação retroactiva, não só prevenção |
| Least privilege — variáveis só onde são necessárias | O container Grafana não precisa de `ANTHROPIC_API_KEY`, por exemplo |

---

## Steps

### Step 1 — Auditoria: `.env` nunca foi commitado?

```bash
git log --all --full-history -- .env
# deve devolver vazio — se não devolver, o secret está no histórico de git
# e precisa de rotação (a key/token específica tem de ser revogada e recriada,
# remover do histórico com git filter-repo não é suficiente sozinho)

git log -p --all | grep -i "ANTHROPIC_API_KEY=sk-" | head -5
# verificação adicional — procurar keys reais coladas em commits por engano
```

> Se esta auditoria encontrar um secret exposto: revogar imediatamente a key no painel do provider (Anthropic Console, AbuseIPDB, Telegram BotFather) antes de sequer tentar limpar o histórico git — a rotação é o que importa, a limpeza do histórico é secundária.

---

### Step 2 — Suportar leitura de secrets por ficheiro (`_FILE` convention)

```python
# src/llm/client.py e outros módulos que lêem API keys — padrão a aplicar
# consistentemente. Criar um helper partilhado:
```

```python
# src/config/secrets.py
from __future__ import annotations

import os
from pathlib import Path


def read_secret(env_var: str, default: str = "") -> str:
    """Lê um secret de <ENV_VAR>_FILE (Docker Secrets) se existir,
    caindo para <ENV_VAR> directamente (desenvolvimento local).
    """
    file_path = os.getenv(f"{env_var}_FILE")
    if file_path and Path(file_path).exists():
        return Path(file_path).read_text(encoding="utf-8").strip()
    return os.getenv(env_var, default)
```

Actualizar os pontos onde secrets são lidos (`LLMClient`, `ThreatIntel`, `TelegramNotifier`, `TokenBudgetTracker` indirectamente via `.env`) para usar `read_secret()` em vez de `os.getenv()` directo:

```python
# exemplo em src/llm/client.py
from src.config.secrets import read_secret

self.api_key = api_key or read_secret("ANTHROPIC_API_KEY")
```

---

### Step 3 — `docker-compose.secrets.yml` (overlay opcional para produção)

```yaml
# Overlay a usar em produção com: docker compose -f docker-compose.yml -f docker-compose.secrets.yml up
services:
  agent:
    secrets:
      - anthropic_api_key
      - telegram_bot_token
      - abuseipdb_api_key
    environment:
      ANTHROPIC_API_KEY_FILE: /run/secrets/anthropic_api_key
      TELEGRAM_BOT_TOKEN_FILE: /run/secrets/telegram_bot_token
      ABUSEIPDB_API_KEY_FILE: /run/secrets/abuseipdb_api_key

secrets:
  anthropic_api_key:
    file: ./secrets/anthropic_api_key.txt
  telegram_bot_token:
    file: ./secrets/telegram_bot_token.txt
  abuseipdb_api_key:
    file: ./secrets/abuseipdb_api_key.txt
```

```bash
mkdir -p secrets
echo "secrets/" >> .gitignore
```

> Docker Secrets "ficheiro local" (usado aqui) é o modo mais simples — Docker Swarm/Kubernetes têm mecanismos mais robustos (secrets encriptados no cluster), fora do âmbito de um VPS single-host da Fase 1. Documentado como caminho de evolução para a Fase 4 (multi-tenant real).

---

### Step 4 — Reduzir variáveis por serviço ao mínimo necessário (least privilege)

Rever `docker-compose.yml` (Dia 72) — confirmar que `grafana` só recebe `INFLUXDB_TOKEN` (não `ANTHROPIC_API_KEY`, `TELEGRAM_BOT_TOKEN`, etc., que não usa) e que `influxdb` não recebe nenhum secret que não seja o seu próprio.

---

### Step 5 — `tests/test_secrets.py`

```python
from __future__ import annotations

from pathlib import Path

import pytest

from src.config.secrets import read_secret


class TestReadSecret:
    def test_reads_from_env_var_when_no_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_SECRET", "valor_direto")
        monkeypatch.delenv("TEST_SECRET_FILE", raising=False)
        assert read_secret("TEST_SECRET") == "valor_direto"

    def test_reads_from_file_when_file_var_set(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("valor_do_ficheiro\n", encoding="utf-8")
        monkeypatch.setenv("TEST_SECRET_FILE", str(secret_file))
        assert read_secret("TEST_SECRET") == "valor_do_ficheiro"

    def test_file_takes_precedence_over_env_var(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("do_ficheiro", encoding="utf-8")
        monkeypatch.setenv("TEST_SECRET", "do_env_var")
        monkeypatch.setenv("TEST_SECRET_FILE", str(secret_file))
        assert read_secret("TEST_SECRET") == "do_ficheiro"

    def test_returns_default_when_neither_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TEST_SECRET", raising=False)
        monkeypatch.delenv("TEST_SECRET_FILE", raising=False)
        assert read_secret("TEST_SECRET", default="fallback") == "fallback"
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 302 + 4 = 306 testes

ruff check src/
mypy src/config/ --strict --ignore-missing-imports

git add src/config/secrets.py src/llm/client.py src/analyzers/threat_intel.py \
        src/alerts/telegram_notifier.py docker-compose.secrets.yml \
        tests/test_secrets.py .gitignore
git commit -m "feat: dia 73 — suporte a Docker Secrets via convenção _FILE"
```

---

## Checklist

- [ ] Auditoria confirma que `.env` nunca foi commitado no histórico
- [ ] `read_secret()` suporta `_FILE` convention com fallback para env var directa
- [ ] Módulos que leem secrets actualizados para usar `read_secret()`
- [ ] `docker-compose.secrets.yml` como overlay opcional de produção
- [ ] `secrets/` no `.gitignore`
- [ ] Least privilege confirmado — cada serviço só recebe as variáveis que usa
- [ ] 4 testes a passar
- [ ] `python -m pytest tests/ -v` → 306 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/config/secrets.py` | `read_secret()` |
| `src/llm/client.py`, `threat_intel.py`, `telegram_notifier.py` | Migrados para `read_secret()` |
| `docker-compose.secrets.yml` | Overlay de produção |
| `tests/test_secrets.py` | 4 testes |

**Resultado da auditoria de histórico git:** *(preencher — confirmar que nada foi encontrado, ou documentar a rotação feita se algo foi)*

**Próximo dia:** Dia 74 — teste de integração end-to-end no container
