# Dia 46 — Agendamento do relatório com APScheduler

**Fase:** 1 · **Semana:** 7 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-45 concluídos. Estado do projecto:
- src/reports/report_builder.py — ReportBuilder com gráficos embutidos
- src/reports/pdf_renderer.py — PDFRenderer
- src/alerts/telegram_notifier.py — TelegramNotifier
- tests/: 225 testes, todos a passar

Quero continuar para o Dia 46: gerar o relatório semanal automaticamente
(ex: toda segunda-feira às 08:00) e enviá-lo por Telegram — sem depender de
um cron externo do SO, para o agendamento viver dentro do próprio processo
Python (mais portável entre instalações de cliente e mais fácil de testar).
```

---

## Objectivo

`APScheduler` corre dentro do processo Python do agente — não precisa de configurar `cron` no SO em cada instalação de cliente, o que simplifica o deployment (relevante para a Semana 11, Docker).

```
AgentScheduler (arranca com o serviço principal)
        ↓ cron trigger: "seg 08:00"
ReportBuilder.build() → PDFRenderer.render_template()
        ↓
TelegramNotifier envia o PDF como documento
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `apscheduler.schedulers.background.BackgroundScheduler` | Agendador que corre numa thread própria |
| `CronTrigger(day_of_week="mon", hour=8, minute=0)` | Sintaxe de agendamento tipo cron |
| Envio de ficheiro via Telegram Bot API (`sendDocument`) | Diferente de `sendMessage` (texto) — usa `multipart/form-data` |
| `scheduler.add_job(..., id=..., replace_existing=True)` | Evitar duplicar jobs em restarts/reloads |

---

## Steps

### Step 1 — Instalar APScheduler

```bash
pip install apscheduler
```

```toml
[project.optional-dependencies]
reports = ["weasyprint", "jinja2", "apscheduler"]
```

---

### Step 2 — Extender `TelegramNotifier` com `send_document()`

```python
# src/alerts/telegram_notifier.py
_DOCUMENT_API_BASE = "https://api.telegram.org/bot{token}/sendDocument"


class TelegramNotifier:
    # ... código existente ...

    def send_document(self, file_path: Path, caption: str = "") -> bool:
        if not self.bot_token or not self.chat_id:
            logger.warning("TELEGRAM_BOT_TOKEN/CHAT_ID não configurados")
            return False
        try:
            url = _DOCUMENT_API_BASE.format(token=self.bot_token)
            with open(file_path, "rb") as fh:
                resp = self.session.post(
                    url,
                    data={"chat_id": self.chat_id, "caption": caption},
                    files={"document": (file_path.name, fh, "application/pdf")},
                    timeout=30,
                )
            resp.raise_for_status()
            return True
        except requests.RequestException as exc:
            logger.warning("Erro ao enviar documento Telegram: %s", exc)
            return False
```

(Adicionar `from pathlib import Path` ao topo do ficheiro, se ainda não estiver importado.)

---

### Step 3 — `src/reports/scheduler.py`

```python
from __future__ import annotations

import logging
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from src.alerts.telegram_notifier import TelegramNotifier
from src.reports.pdf_renderer import PDFRenderer
from src.reports.report_builder import ReportBuilder

logger = logging.getLogger(__name__)


class ReportScheduler:
    """Agenda a geração e envio automático do relatório semanal."""

    def __init__(
        self,
        report_builder: ReportBuilder | None = None,
        renderer: PDFRenderer | None = None,
        notifier: TelegramNotifier | None = None,
        output_dir: Path = Path("data/reports"),
    ) -> None:
        self.report_builder = report_builder or ReportBuilder()
        self.renderer = renderer or PDFRenderer()
        self.notifier = notifier or TelegramNotifier()
        self.output_dir = output_dir
        self._scheduler = BackgroundScheduler()

    def generate_and_send(self) -> Path:
        """Executa o ciclo completo: construir contexto → renderizar → enviar."""
        context = self.report_builder.build()
        output_path = self.output_dir / f"relatorio_{context.period_end}.pdf"
        self.renderer.render_template("weekly_report.html.jinja", context, output_path)

        sent = self.notifier.send_document(
            output_path, caption=f"Relatório semanal — {context.period_start} a {context.period_end}"
        )
        if not sent:
            logger.warning("Relatório gerado mas não foi possível enviar via Telegram")
        return output_path

    def start(self, day_of_week: str = "mon", hour: int = 8, minute: int = 0) -> None:
        self._scheduler.add_job(
            self.generate_and_send,
            trigger=CronTrigger(day_of_week=day_of_week, hour=hour, minute=minute),
            id="weekly_report", replace_existing=True,
        )
        self._scheduler.start()
        logger.info("Relatório semanal agendado: %s às %02d:%02d", day_of_week, hour, minute)

    def stop(self) -> None:
        self._scheduler.shutdown(wait=False)
```

---

### Step 4 — `scripts/run_report_scheduler.py`

```python
from __future__ import annotations

import signal
import time

from src.reports.scheduler import ReportScheduler


def main() -> None:
    scheduler = ReportScheduler()
    scheduler.start(day_of_week="mon", hour=8, minute=0)

    def _shutdown(sig: int, frame: object) -> None:
        print("\nA parar o agendador...")
        scheduler.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _shutdown)
    print("Agendador activo — relatório semanal toda segunda-feira às 08:00 (Ctrl+C para parar)")
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
```

---

### Step 5 — `tests/test_report_scheduler.py`

```python
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.reports.scheduler import ReportScheduler


@pytest.fixture
def scheduler(tmp_path: Path) -> ReportScheduler:
    builder = MagicMock()
    from src.reports.context import ReportMetrics, WeeklyReportContext
    from datetime import date
    builder.build.return_value = WeeklyReportContext(
        client_name="Teste", period_start=date(2026, 9, 10), period_end=date(2026, 9, 17),
        metrics=ReportMetrics(total_events=10, blocked=5, high_priority=1, change_pct=0.0),
    )
    renderer = MagicMock()
    renderer.render_template.side_effect = lambda name, ctx, path: path
    notifier = MagicMock()
    notifier.send_document.return_value = True

    return ReportScheduler(
        report_builder=builder, renderer=renderer, notifier=notifier, output_dir=tmp_path,
    )


class TestReportScheduler:
    def test_generate_and_send_calls_pipeline_in_order(self, scheduler: ReportScheduler) -> None:
        scheduler.generate_and_send()
        scheduler.report_builder.build.assert_called_once()
        scheduler.renderer.render_template.assert_called_once()
        scheduler.notifier.send_document.assert_called_once()

    def test_generate_and_send_returns_output_path(self, scheduler: ReportScheduler) -> None:
        path = scheduler.generate_and_send()
        assert path.name == "relatorio_2026-09-17.pdf"

    def test_send_failure_does_not_raise(self, scheduler: ReportScheduler) -> None:
        scheduler.notifier.send_document.return_value = False
        path = scheduler.generate_and_send()  # não deve levantar excepção
        assert path is not None

    def test_start_registers_cron_job(self, scheduler: ReportScheduler) -> None:
        scheduler.start(day_of_week="fri", hour=9, minute=30)
        job = scheduler._scheduler.get_job("weekly_report")
        assert job is not None
        scheduler.stop()
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 225 + 4 = 229 testes

ruff check src/
mypy src/reports/scheduler.py --strict --ignore-missing-imports

git add src/reports/scheduler.py src/alerts/telegram_notifier.py \
        scripts/run_report_scheduler.py tests/test_report_scheduler.py pyproject.toml
git commit -m "feat: dia 46 — agendamento do relatório semanal com APScheduler"
```

---

## Checklist

- [ ] `TelegramNotifier.send_document()` envia PDF via `sendDocument`
- [ ] `ReportScheduler.generate_and_send()` encadeia build → render → send
- [ ] `ReportScheduler.start()` agenda com `CronTrigger`
- [ ] Falha no envio não interrompe o ciclo (PDF fica gerado mesmo assim)
- [ ] `scripts/run_report_scheduler.py` corre em background com Ctrl+C para parar
- [ ] 4 testes a passar
- [ ] `python -m pytest tests/ -v` → 229 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/reports/scheduler.py` | `ReportScheduler` |
| `src/alerts/telegram_notifier.py` | `send_document()` |
| `scripts/run_report_scheduler.py` | CLI do agendador |
| `tests/test_report_scheduler.py` | 4 testes |

**Próximo dia:** Dia 47 — refactoring e consolidação de módulos
