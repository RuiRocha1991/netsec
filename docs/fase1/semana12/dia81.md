# Dia 81 — Hardening: erros e logging de produção

**Fase:** 1 · **Semana:** 12 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-80 concluídos. Sistema completo, documentado, com guião de demo.
Estado do projecto: tests/: ~310+ testes, todos a passar. Ao longo de 80
dias, cada módulo tratou erros de forma ad-hoc (try/except locais,
logger.warning em vários sítios) — nunca houve uma passagem dedicada a
consistência de logging e tratamento de erros a nível de produto.

Quero continuar para o Dia 81: revisão de hardening — logging estruturado
consistente, tratamento de erros que não deixa o cliente "às cegas" quando
algo falha, sem introduzir features novas.
```

---

## Objectivo

Uma instalação de cliente vai correr sem supervisão directa — quando algo falhar às 3h de uma terça, ninguém está a olhar para o terminal. Hoje: garantir que os logs contam a história completa depois do facto, e que nenhuma falha silenciosa deixa o sistema num estado inconsistente sem aviso.

---

## Steps

### Step 1 — Configuração de logging centralizada

```python
# src/config/logging_config.py
from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path


def configure_logging(
    level: str | None = None,
    log_dir: Path = Path("data/logs"),
) -> None:
    """Configura logging estruturado para toda a aplicação — chamado uma vez no arranque."""
    log_dir.mkdir(parents=True, exist_ok=True)
    resolved_level = level or os.getenv("LOG_LEVEL", "INFO")

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s [%(threadName)s] %(message)s"
    )

    root = logging.getLogger()
    root.setLevel(resolved_level)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    # rotação — nunca deixar os logs crescerem sem limite num VPS de recursos limitados
    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / "netguard.log", maxBytes=10_000_000, backupCount=5, encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    # reduzir verbosidade de bibliotecas terceiras muito faladoras
    for noisy_logger in ("httpx", "urllib3", "chromadb"):
        logging.getLogger(noisy_logger).setLevel("WARNING")
```

Chamar `configure_logging()` no arranque de cada entrypoint (`src/api/main.py`, `scripts/run_syslog_server.py`, etc.) em vez do `logging.basicConfig()` ad-hoc que alguns scripts já tinham desde os primeiros dias.

---

### Step 2 — Auditoria de `except Exception` genéricos — cada um justificado ou corrigido

Percorrer os pontos conhecidos de `except Exception:` no código (worker threads de `SyslogServer`, `AgentQueue`, `LLMAnalysisQueue`, `AnomalyScorer`) e confirmar, para cada um:
1. Está a fazer `logger.exception(...)` (com stack trace), não só `logger.warning(str(e))`?
2. O sistema continua num estado consistente depois de apanhar a excepção?
3. Existe alguma forma de o cliente/operador ficar a saber que algo falhou repetidamente (não só uma vez perdida no log)?

Para o ponto 3, adicionar um contador simples de falhas consecutivas com alerta se ultrapassar um threshold:

```python
# src/config/health.py
from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class ComponentHealth:
    """Regista falhas consecutivas de um componente — alerta se persistente."""
    name: str
    consecutive_failures: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record_success(self) -> None:
        with self._lock:
            self.consecutive_failures = 0

    def record_failure(self) -> bool:
        """Devolve True se atingiu o threshold de alerta (5 falhas seguidas)."""
        with self._lock:
            self.consecutive_failures += 1
            return self.consecutive_failures >= 5
```

Integrar em pelo menos um worker crítico (ex: `SyslogServer._worker`) como exemplo de padrão a replicar nos outros, se o tempo do dia permitir:

```python
# src/parsers/syslog_server.py
from src.config.health import ComponentHealth

class SyslogServer:
    def __init__(self, ...):
        ...
        self._health = ComponentHealth(name="syslog_worker")

    def _worker(self) -> None:
        while True:
            ...
            try:
                self.pipeline.process_line(line)
                self._health.record_success()
            except Exception:
                logger.exception("Erro no worker")
                if self._health.record_failure():
                    logger.critical(
                        "Worker syslog falhou 5 vezes seguidas — possível problema sistémico"
                    )
            finally:
                _queue.task_done()
```

---

### Step 3 — Endpoint `GET /health/detailed` — saúde de cada componente, não só "ok"

```python
# src/api/main.py
@router.get("/health/detailed")
def health_detailed(storage: EventStorage = Depends(get_storage)) -> dict:
    checks = {}
    try:
        storage.count()
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "error"

    checks["disk_space_ok"] = _check_disk_space()
    return {"status": "ok" if all(v == "ok" or v is True for v in checks.values()) else "degraded",
            "checks": checks}


def _check_disk_space(min_free_gb: float = 1.0) -> bool:
    import shutil
    free_gb = shutil.disk_usage("/").free / (1024 ** 3)
    return free_gb >= min_free_gb
```

---

### Step 4 — `tests/test_health.py` e `tests/test_logging_config.py`

```python
# tests/test_health.py
from __future__ import annotations

from src.config.health import ComponentHealth


class TestComponentHealth:
    def test_success_resets_counter(self) -> None:
        health = ComponentHealth(name="test")
        health.record_failure()
        health.record_failure()
        health.record_success()
        assert health.consecutive_failures == 0

    def test_alerts_at_threshold(self) -> None:
        health = ComponentHealth(name="test")
        for _ in range(4):
            assert health.record_failure() is False
        assert health.record_failure() is True

    def test_disk_space_check_reasonable_default(self) -> None:
        from src.api.main import _check_disk_space
        # numa máquina de desenvolvimento normal, deve haver > 1GB livre
        assert _check_disk_space(min_free_gb=0.001) is True
```

```python
# tests/test_logging_config.py
from __future__ import annotations

import logging
from pathlib import Path

from src.config.logging_config import configure_logging


class TestConfigureLogging:
    def test_creates_log_directory(self, tmp_path: Path) -> None:
        log_dir = tmp_path / "logs"
        configure_logging(level="INFO", log_dir=log_dir)
        assert log_dir.exists()

    def test_creates_rotating_file_handler(self, tmp_path: Path) -> None:
        configure_logging(level="INFO", log_dir=tmp_path / "logs2")
        root = logging.getLogger()
        handler_types = [type(h).__name__ for h in root.handlers]
        assert "RotatingFileHandler" in handler_types
        # limpar handlers para não afectar outros testes
        root.handlers.clear()
```

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 310 + 3 + 2 = 315... ajustar título final: 314

ruff check src/
mypy src/config/ --strict --ignore-missing-imports

git add src/config/logging_config.py src/config/health.py \
        src/parsers/syslog_server.py src/api/main.py \
        tests/test_health.py tests/test_logging_config.py
git commit -m "feat: dia 81 — logging estruturado, rotação, health checks detalhados"
```

---

## Checklist

- [ ] `configure_logging()` centralizada, com rotação de ficheiros, chamada em todos os entrypoints
- [ ] `except Exception` genéricos auditados — todos com `logger.exception()` (stack trace)
- [ ] `ComponentHealth` detecta falhas persistentes, não só falhas isoladas
- [ ] `GET /health/detailed` verifica BD e espaço em disco
- [ ] 5 testes a passar
- [ ] `python -m pytest tests/ -v` → 314 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/config/logging_config.py` | Logging centralizado com rotação |
| `src/config/health.py` | `ComponentHealth` |
| `src/api/main.py` | `GET /health/detailed` |
| `tests/test_health.py`, `test_logging_config.py` | 5 testes |

**Próximo dia:** Dia 82 — performance e profiling básico
