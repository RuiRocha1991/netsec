# Dia 74 — Teste de integração end-to-end no container

**Fase:** 1 · **Semana:** 11 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-73 concluídos. Estado do projecto:
- Dockerfile + docker-compose.yml + docker-compose.secrets.yml completos
- src/config/secrets.py — read_secret() com suporte a Docker Secrets
- tests/: 306 testes, todos a passar

Quero continuar para o Dia 74: até agora todos os testes correm FORA do
container (na VM de desenvolvimento, contra o código-fonte directamente).
Hoje: suite de testes de integração que corre CONTRA o container real, a
confirmar que o artefacto Docker empacotado se comporta como o código-fonte.
```

---

## Objectivo

"Passa na minha máquina" não é suficiente para um artefacto que vai ser instalado em VPS de clientes — o container pode ter dependências de sistema em falta, permissões erradas, variáveis de ambiente mal propagadas. Hoje: testes que sobem a stack `docker-compose.yml` real e validam via HTTP, tal como um cliente real interagiria.

```
pytest (na máquina de desenvolvimento)
        ↓ docker compose up -d --build (via subprocess ou testcontainers)
Container real a correr
        ↓ httpx contra localhost:8000
Validação do comportamento real, não do código-fonte
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `pytest` fixture `scope="session"` | Subir o container uma vez para todos os testes deste ficheiro, não por teste |
| `subprocess.run(["docker", "compose", ...])` | Orquestrar Docker a partir de Python |
| Testes marcados `@pytest.mark.docker` | Categoria própria — lentos, requerem Docker instalado, corridos separadamente do resto da suite |
| Retry/polling para "container pronto" | Reutiliza o padrão do `live_server` fixture (Dia 21) |

---

## Steps

### Step 1 — Registar novo marker

```toml
# pyproject.toml
[tool.pytest.ini_options]
markers = [
    "integration: testes que sobem um servidor real (mais lentos)",
    "docker: testes que sobem o container Docker completo (requerem Docker instalado)",
]
```

---

### Step 2 — `tests/test_docker_integration.py`

```python
from __future__ import annotations

import subprocess
import time

import httpx
import pytest

_BASE_URL = "http://localhost:8000"
_API_KEY = "docker_test_key"


def _docker_compose_available() -> bool:
    try:
        subprocess.run(
            ["docker", "compose", "version"], capture_output=True, timeout=5, check=True,
        )
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not _docker_compose_available(), reason="Docker não disponível"),
]


@pytest.fixture(scope="session")
def docker_stack():
    env = {"API_KEY": _API_KEY, "INFLUXDB_TOKEN": "test_token",
           "INFLUXDB_PASSWORD": "test_pw", "GRAFANA_ADMIN_PASSWORD": "test_pw"}
    import os
    full_env = {**os.environ, **env}

    subprocess.run(["docker", "compose", "down", "-v"], env=full_env, capture_output=True)
    subprocess.run(
        ["docker", "compose", "up", "-d", "--build"], env=full_env, check=True, timeout=180,
    )

    ready = False
    for _ in range(30):
        try:
            resp = httpx.get(f"{_BASE_URL}/health", timeout=2)
            if resp.status_code == 200:
                ready = True
                break
        except httpx.RequestError:
            pass
        time.sleep(2)

    if not ready:
        subprocess.run(["docker", "compose", "logs"], env=full_env)
        subprocess.run(["docker", "compose", "down", "-v"], env=full_env)
        pytest.fail("Container não ficou pronto a tempo")

    yield _BASE_URL

    subprocess.run(["docker", "compose", "down", "-v"], env=full_env)


class TestDockerIntegration:
    def test_health_endpoint(self, docker_stack: str) -> None:
        resp = httpx.get(f"{docker_stack}/health")
        assert resp.status_code == 200

    def test_webhook_ingest_and_query(self, docker_stack: str) -> None:
        headers = {"X-API-Key": _API_KEY}
        line = (
            "Sep 17 10:30:45 pfsense filterlog[1]: "
            "5,,,0,em0,match,block,in,4,0x0,,64,1234,0,none,6,tcp,60,"
            "203.0.113.1,192.168.10.50,54321,22,0,S,111,0,0,mss"
        )
        ingest = httpx.post(
            f"{docker_stack}/ingest/webhook", json={"lines": [line]}, headers=headers, timeout=10,
        )
        assert ingest.status_code == 200
        assert ingest.json()["ingested"] == 1

        events = httpx.get(f"{docker_stack}/events", headers=headers, timeout=10)
        assert events.json()["total"] >= 1

    def test_grafana_reachable(self, docker_stack: str) -> None:
        resp = httpx.get("http://localhost:3000/api/health", timeout=10)
        assert resp.status_code == 200

    def test_data_persists_across_agent_restart(self, docker_stack: str) -> None:
        import os
        full_env = {**os.environ, "API_KEY": _API_KEY}
        headers = {"X-API-Key": _API_KEY}
        stats_before = httpx.get(f"{docker_stack}/stats", headers=headers, timeout=10).json()

        subprocess.run(["docker", "compose", "restart", "agent"], env=full_env, check=True)
        time.sleep(5)

        for _ in range(15):
            try:
                if httpx.get(f"{docker_stack}/health", timeout=2).status_code == 200:
                    break
            except httpx.RequestError:
                pass
            time.sleep(2)

        stats_after = httpx.get(f"{docker_stack}/stats", headers=headers, timeout=10).json()
        assert stats_after["total"] == stats_before["total"]
```

---

### Step 3 — Correr separadamente do resto da suite (é lento — ~2-3 minutos por build)

```bash
python -m pytest tests/ -v -m "not docker"    # suite normal, rápida (dia a dia)
python -m pytest tests/test_docker_integration.py -v -m docker  # só quando relevante
```

---

### Step 4 — Documentar no `docs/README.md` quando correr cada suite

Adicionar à secção "Como retomar":

```markdown
**Verificação rápida (dia-a-dia):**
python -m pytest tests/ -v -m "not docker"

**Verificação completa (antes de merge/deploy):**
python -m pytest tests/ -v   # inclui testes docker — requer Docker instalado, ~3min
```

---

### Step 5 — Commit

```bash
python -m pytest tests/ -v -m "not docker"
# 306 + 4 = 310 testes (os 4 novos são "docker", contam mas correm à parte)

ruff check src/

git add tests/test_docker_integration.py pyproject.toml docs/README.md
git commit -m "feat: dia 74 — testes de integração end-to-end contra o container real"
```

---

## Checklist

- [ ] Marker `docker` registado e usado para separar da suite rápida
- [ ] `docker_stack` fixture sobe/desce a stack real via `docker compose`
- [ ] 4 testes validam: health, ingest+query, Grafana acessível, persistência após restart
- [ ] Skip automático se Docker não estiver instalado (não falha CI sem Docker)
- [ ] `docs/README.md` documenta a distinção entre suite rápida e completa
- [ ] `python -m pytest tests/ -v -m "not docker"` continua rápido
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `tests/test_docker_integration.py` | 4 testes contra o container real |
| `pyproject.toml` | Marker `docker` |
| `docs/README.md` | Distinção suite rápida vs completa |

**Próximo dia:** Dia 75 — CI: GitHub Actions — testes automáticos em cada push
