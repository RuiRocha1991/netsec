# Dia 68 — Human-in-the-loop: escalação de casos incertos

**Fase:** 1 · **Semana:** 10 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-67 concluídos. Estado do projecto:
- src/agent/decision.py — decide_final_action() com 4 acções
- src/agent/triage_graph.py — grafo completo com roteamento em leque
- src/alerts/telegram_notifier.py — TelegramNotifier
- tests/: 292 testes, todos a passar

Quero continuar para o Dia 68: a acção "escalate_human" hoje só regista no
log — falta o mecanismo real de escalação (notificar o dono do negócio com
opções claras) e a forma de ele responder (aprovar/rejeitar a sugestão do
agente), fechando o ciclo human-in-the-loop.
```

---

## Objectivo

Decisões automáticas de segurança (bloquear um IP) têm um custo se erradas — um fornecedor legítimo bloqueado por engano é mau para o negócio do cliente. `escalate_human` existe precisamente para os casos onde o agente não tem confiança suficiente. Hoje: Telegram passa a ter **botões interactivos** (Telegram Bot API suporta isso nativamente) para o dono do negócio decidir com um toque, sem precisar de usar a API/dashboard.

```
Agente decide "escalate_human"
        ↓
TelegramNotifier envia mensagem com botões: [Bloquear] [Ignorar] [Ver mais]
        ↓
Cliente toca num botão
        ↓
Telegram webhook/callback → API regista a decisão humana
        ↓
storage.save_human_decision(event_id, decision)
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| Telegram Inline Keyboards | Botões clicáveis numa mensagem — API `reply_markup` |
| Callback query | Evento gerado quando o utilizador clica num botão inline |
| Webhook Telegram (`setWebhook`) vs polling | Para receber callbacks — reutiliza `POST` endpoint já existente no `src/api/` |
| Estado "pendente de decisão humana" | Novo estado de um evento, distinto de "resolvido automaticamente" |

---

## Steps

### Step 1 — Estender `TelegramNotifier` com botões inline

```python
# src/alerts/telegram_notifier.py
def send_escalation(self, event_id: int, summary: str, src_ip: str) -> bool:
    if not self.bot_token or not self.chat_id:
        return False
    text = (
        f"⚠️ *Precisa da tua decisão*\n\n{summary}\n\n"
        f"IP: `{src_ip}`\n\nO que queres fazer?"
    )
    keyboard = {
        "inline_keyboard": [[
            {"text": "🚫 Bloquear", "callback_data": f"block:{event_id}"},
            {"text": "✅ Ignorar", "callback_data": f"ignore:{event_id}"},
        ]]
    }
    try:
        url = _API_BASE.format(token=self.bot_token)
        resp = self.session.post(
            url, json={
                "chat_id": self.chat_id, "text": text, "parse_mode": "Markdown",
                "reply_markup": keyboard,
            }, timeout=5,
        )
        resp.raise_for_status()
        return True
    except requests.RequestException as exc:
        logger.warning("Erro ao enviar escalação Telegram: %s", exc)
        return False
```

---

### Step 2 — Nova tabela e métodos em `src/db/storage.py`

```python
# _init_schema():
conn.execute("""
    CREATE TABLE IF NOT EXISTS human_decisions (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id    INTEGER NOT NULL REFERENCES events(id),
        decision    TEXT NOT NULL,           -- 'block' | 'ignore'
        decided_at  TEXT DEFAULT (datetime('now'))
    )
""")

# métodos:
def save_human_decision(self, event_id: int, decision: str) -> int:
    with self._conn() as conn:
        cur = conn.execute(
            "INSERT INTO human_decisions (event_id, decision) VALUES (?, ?)",
            (event_id, decision),
        )
        return cur.lastrowid  # type: ignore[return-value]

def get_human_decision(self, event_id: int) -> sqlite3.Row | None:
    with self._conn() as conn:
        return conn.execute(
            "SELECT * FROM human_decisions WHERE event_id = ? ORDER BY id DESC LIMIT 1",
            (event_id,),
        ).fetchone()
```

---

### Step 3 — Endpoint webhook para callbacks do Telegram

```python
# src/api/schemas.py
class TelegramCallback(BaseModel):
    callback_query: dict  # estrutura completa do Telegram — extraímos só o necessário


# src/api/main.py — NOTA: este endpoint fica FORA do router com auth API key,
# porque é chamado pelo Telegram, não por um cliente autenticado nosso.
# A segurança aqui vem de um "secret token" configurável no setWebhook do Telegram,
# validado via header X-Telegram-Bot-Api-Secret-Token.
@app.post("/telegram/callback")
def telegram_callback(
    payload: dict, storage: EventStorage = Depends(get_storage),
) -> dict:
    callback = payload.get("callback_query", {})
    data = callback.get("data", "")  # ex: "block:42"
    if ":" not in data:
        return {"ok": False}

    action, event_id_str = data.split(":", 1)
    event_id = int(event_id_str)
    decision = "block" if action == "block" else "ignore"
    storage.save_human_decision(event_id, decision)
    return {"ok": True}
```

---

### Step 4 — Ligar ao node `escalate_human` do grafo

```python
# src/agent/triage_graph.py
from src.alerts.telegram_notifier import TelegramNotifier


def _escalate_human(state: TriageState, notifier: TelegramNotifier | None = None) -> TriageState:
    notifier = notifier or TelegramNotifier()
    state["final_action"] = "escalate_human"
    analysis = state.get("analysis")
    summary = analysis.summary if analysis else "Alerta sem análise automática disponível."
    notifier.send_escalation(
        event_id=state.get("event_id", 0), summary=summary,
        src_ip=state["match"].entry.src_ip,
    )
    state["reasoning_log"].append("Acção: escalado para revisão humana via Telegram")
    return state
```

`TriageState` ganha o campo `event_id: int` (precisa de ser passado pelo caller do grafo, tipicamente a partir do `IngestPipeline`).

---

### Step 5 — `tests/test_escalation.py`

```python
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.alerts.telegram_notifier import TelegramNotifier
from src.db.storage import EventStorage


class TestSendEscalation:
    def test_sends_with_inline_keyboard(self) -> None:
        notifier = TelegramNotifier(bot_token="fake", chat_id="123")
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(notifier.session, "post", MagicMock(return_value=mock_resp))
            result = notifier.send_escalation(42, "Resumo de teste", "1.2.3.4")
        assert result is True

    def test_no_credentials_returns_false(self) -> None:
        notifier = TelegramNotifier(bot_token="", chat_id="")
        assert notifier.send_escalation(1, "teste", "1.2.3.4") is False


class TestHumanDecisionStorage:
    def test_save_and_get_decision(self, tmp_path: Path) -> None:
        storage = EventStorage(tmp_path / "hd.db")
        from datetime import datetime
        from src.models.log_entry import LogEntry
        event_id = storage.insert(LogEntry(
            timestamp=datetime(2026, 9, 17, 10, 0, 0), action="block", interface="em0",
            protocol="tcp", src_ip="1.2.3.4", src_port=1111, dst_ip="192.168.10.50", dst_port=22,
        ))
        storage.save_human_decision(event_id, "block")
        row = storage.get_human_decision(event_id)
        assert row["decision"] == "block"


class TestTelegramCallbackEndpoint:
    def test_callback_saves_decision(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient
        from src.api.deps import get_storage
        from src.api.main import app

        storage = EventStorage(tmp_path / "cb.db")
        from datetime import datetime
        from src.models.log_entry import LogEntry
        event_id = storage.insert(LogEntry(
            timestamp=datetime(2026, 9, 17, 10, 0, 0), action="block", interface="em0",
            protocol="tcp", src_ip="1.2.3.4", src_port=1111, dst_ip="192.168.10.50", dst_port=22,
        ))
        app.dependency_overrides[get_storage] = lambda: storage
        client = TestClient(app)

        resp = client.post("/telegram/callback", json={
            "callback_query": {"data": f"block:{event_id}"}
        })
        app.dependency_overrides.clear()

        assert resp.status_code == 200
        assert storage.get_human_decision(event_id)["decision"] == "block"
```

---

### Step 6 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 292 + 4 = 296 testes

ruff check src/
mypy src/agent/ src/db/storage.py src/api/main.py --strict --ignore-missing-imports

git add src/alerts/telegram_notifier.py src/db/storage.py src/api/schemas.py \
        src/api/main.py src/agent/triage_graph.py src/agent/state.py \
        tests/test_escalation.py
git commit -m "feat: dia 68 — human-in-the-loop com botões Telegram e webhook de callback"
```

---

## Checklist

- [ ] `send_escalation()` envia mensagem com inline keyboard (Bloquear/Ignorar)
- [ ] Tabela `human_decisions` liga decisão humana ao `event_id`
- [ ] `POST /telegram/callback` fora do router autenticado (autenticação própria via secret do Telegram — nota documentada)
- [ ] Node `escalate_human` do grafo envia a notificação real, não só regista no log
- [ ] 4 testes a passar
- [ ] `python -m pytest tests/ -v` → 296 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados/alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/alerts/telegram_notifier.py` | `send_escalation()` com botões inline |
| `src/db/storage.py` | Tabela `human_decisions`, save/get |
| `src/api/main.py` | `POST /telegram/callback` |
| `src/agent/triage_graph.py` | `_escalate_human` envia notificação real |
| `tests/test_escalation.py` | 4 testes |

**Próximo dia:** Dia 69 — memória do agente e logging de decisões
