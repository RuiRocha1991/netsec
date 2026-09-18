# Dia 18 — Alertas Telegram Bot em tempo real

**Fase:** 1 · **Semana:** 3 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-17 concluídos. Estado do projecto:
- src/api/ — FastAPI: /health, /events (paginado+filtros), /stats
- src/parsers/syslog_server.py — pipeline UDP: enrich + rules + storage
- src/analyzers/rule_engine.py — RuleEngine YAML
- tests/: 125 testes, todos a passar
- Packages: fastapi, uvicorn, pydantic, pyshark, pandas, pyyaml, requests,
  python-dotenv, geoip2

Quero continuar para o Dia 18: bot Telegram que envia alerta em tempo real
quando o RuleEngine faz match numa regra com alert=true.
```

---

## Objectivo

Até agora os alertas só aparecem no terminal do `SyslogServer`. Ninguém está a olhar para o terminal 24/7 — hoje o alerta chega ao telemóvel via Telegram.

```
RuleEngine.evaluate() → match com alert=true
        ↓
TelegramNotifier.send() → Bot API
        ↓
Telemóvel do dono do café/clínica recebe mensagem
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `python-telegram-bot` (só o `Bot` síncrono via `requests`, sem framework completo) | Enviar mensagens |
| Telegram Bot API REST directa | Mais simples que o SDK completo para só enviar mensagens |
| Deduplicação/throttling | Evitar spam — não enviar o mesmo alerta 50x por segundo |
| `collections.deque` com maxlen | Estrutura eficiente para histórico recente limitado |
| `hashlib.md5` | Gerar chave de deduplicação a partir dos campos do alerta |

---

## Steps

### Step 1 — Criar o bot no Telegram

1. Conversar com **@BotFather** no Telegram → `/newbot` → seguir instruções
2. Guardar o `TELEGRAM_BOT_TOKEN` recebido
3. Enviar uma mensagem qualquer ao bot criado
4. Obter o `chat_id`:
```bash
curl "https://api.telegram.org/bot<TOKEN>/getUpdates"
# procurar "chat":{"id": 123456789, ...}
```
5. Preencher `.env`:
```
TELEGRAM_BOT_TOKEN=1234567890:AAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TELEGRAM_CHAT_ID=123456789
```

---

### Step 2 — `src/alerts/telegram_notifier.py`

```python
from __future__ import annotations

import hashlib
import logging
import os
import time
from collections import deque

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_API_BASE = "https://api.telegram.org/bot{token}/sendMessage"
_DEDUP_WINDOW_SECS = 300  # não repetir o mesmo alerta durante 5 minutos


class TelegramNotifier:
    """Envia alertas para o Telegram com deduplicação e throttling."""

    def __init__(
        self,
        bot_token: str | None = None,
        chat_id: str | None = None,
        dedup_window: int = _DEDUP_WINDOW_SECS,
    ) -> None:
        self.bot_token = bot_token or os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = chat_id or os.getenv("TELEGRAM_CHAT_ID", "")
        self.dedup_window = dedup_window
        self._recent: deque[tuple[str, float]] = deque(maxlen=200)
        self.session = requests.Session()

    def _dedup_key(self, text: str) -> str:
        return hashlib.md5(text.encode()).hexdigest()

    def _is_duplicate(self, key: str) -> bool:
        now = time.time()
        # limpar entradas fora da janela
        while self._recent and now - self._recent[0][1] > self.dedup_window:
            self._recent.popleft()
        return any(k == key for k, _ in self._recent)

    def send(self, text: str, parse_mode: str = "Markdown") -> bool:
        """Envia mensagem, devolve False se for duplicado recente ou falhar."""
        key = self._dedup_key(text)
        if self._is_duplicate(key):
            logger.debug("Alerta duplicado ignorado (dedup window)")
            return False

        if not self.bot_token or not self.chat_id:
            logger.warning("TELEGRAM_BOT_TOKEN/CHAT_ID não configurados")
            return False

        try:
            url = _API_BASE.format(token=self.bot_token)
            resp = self.session.post(
                url,
                json={"chat_id": self.chat_id, "text": text, "parse_mode": parse_mode},
                timeout=5,
            )
            resp.raise_for_status()
            self._recent.append((key, time.time()))
            return True
        except requests.RequestException as exc:
            logger.warning("Erro ao enviar Telegram: %s", exc)
            return False

    def send_alert(self, severity: str, rule_name: str, src_ip: str,
                    dst_ip: str, dst_port: int, geo: str | None = None,
                    abuse_score: int | None = None) -> bool:
        """Formata e envia um alerta de segurança."""
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
        geo_str = f" [{geo}]" if geo else ""
        score_str = f" · abuse={abuse_score}" if abuse_score else ""
        text = (
            f"{emoji} *{severity}* — `{rule_name}`\n"
            f"`{src_ip}`{geo_str}{score_str} → `{dst_ip}:{dst_port}`"
        )
        return self.send(text)
```

---

### Step 3 — Integrar no `SyslogServer`

```python
# src/parsers/syslog_server.py — adicionar ao __init__:
from src.alerts.telegram_notifier import TelegramNotifier
# ...
self.notifier = TelegramNotifier()

# Actualizar _process_rules:
def _process_rules(self, entry: LogEntry) -> None:
    matches = self.engine.evaluate(entry)
    for match in matches:
        if match.rule.alert:
            print(f"[{match.rule.severity}] ...")  # mantém log local
            self.notifier.send_alert(
                severity=match.rule.severity,
                rule_name=match.rule.name,
                src_ip=entry.src_ip,
                dst_ip=entry.dst_ip,
                dst_port=entry.dst_port,
                geo=entry.geo_country,
                abuse_score=entry.abuse_score,
            )
```

---

### Step 4 — `tests/test_telegram_notifier.py`

```python
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.alerts.telegram_notifier import TelegramNotifier


@pytest.fixture
def notifier() -> TelegramNotifier:
    return TelegramNotifier(bot_token="fake_token", chat_id="123")


class TestTelegramNotifier:
    def test_no_credentials_returns_false(self) -> None:
        n = TelegramNotifier(bot_token="", chat_id="")
        assert n.send("teste") is False

    def test_successful_send(self, notifier: TelegramNotifier) -> None:
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        with patch.object(notifier.session, "post", return_value=mock_resp) as mock_post:
            result = notifier.send("alerta de teste")
        assert result is True
        mock_post.assert_called_once()

    def test_duplicate_within_window_not_sent(self, notifier: TelegramNotifier) -> None:
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        with patch.object(notifier.session, "post", return_value=mock_resp) as mock_post:
            notifier.send("mesma mensagem")
            result = notifier.send("mesma mensagem")
        assert result is False
        assert mock_post.call_count == 1

    def test_api_error_returns_false(self, notifier: TelegramNotifier) -> None:
        import requests
        with patch.object(notifier.session, "post", side_effect=requests.ConnectionError()):
            assert notifier.send("falha") is False

    def test_send_alert_formats_message(self, notifier: TelegramNotifier) -> None:
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        with patch.object(notifier.session, "post", return_value=mock_resp) as mock_post:
            notifier.send_alert("HIGH", "ssh_brute_force", "1.2.3.4", "192.168.10.50", 22)
        sent_text = mock_post.call_args.kwargs["json"]["text"]
        assert "ssh_brute_force" in sent_text
        assert "1.2.3.4" in sent_text
```

---

### Step 5 — Testar com credenciais reais (opcional)

```bash
python -c "
from src.alerts.telegram_notifier import TelegramNotifier
n = TelegramNotifier()
ok = n.send_alert('HIGH', 'teste_manual', '203.0.113.1', '192.168.10.50', 22, geo='RU', abuse_score=87)
print('Enviado:', ok)
"
```

---

### Step 6 — Qualidade e commit

```bash
pip install python-dotenv  # já instalado no dia 12 — confirmar
python -m pytest tests/ -v
# 125 + 5 = 130 testes

ruff check src/
git add src/alerts/telegram_notifier.py src/parsers/syslog_server.py \
        tests/test_telegram_notifier.py .env.example
git commit -m "feat: dia 18 — alertas Telegram com deduplicação"
```

---

## Checklist

- [ ] Bot Telegram criado via @BotFather
- [ ] `TELEGRAM_BOT_TOKEN` e `TELEGRAM_CHAT_ID` em `.env`
- [ ] `TelegramNotifier.send()` com deduplicação por `deque` + `md5`
- [ ] `send_alert()` formata mensagem com emoji por severidade
- [ ] Integrado em `SyslogServer._process_rules`
- [ ] 5 testes com mocks a passar (sem consumir Telegram real)
- [ ] `python -m pytest tests/ -v` → 130 passed
- [ ] (Opcional) Alerta real recebido no telemóvel
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/alerts/telegram_notifier.py` | `TelegramNotifier` — send + send_alert + dedup |
| `tests/test_telegram_notifier.py` | 5 testes com mocks |

**Próximo dia:** Dia 19 — webhook pfSense → FastAPI (alternativa ao syslog UDP)
