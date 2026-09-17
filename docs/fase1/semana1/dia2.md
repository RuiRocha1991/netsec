# Dia 2 — Python core

**Fase:** 1 · **Semana:** 1 · **Estado:** ✅ Concluído

---

## Prompt de contexto

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura de rede alvo: pfSense com zonas GREEN(10.x)/IOT(40.x)/DMZ(30.x).

Dias 1 e 2 da Fase 1 concluídos. O que existe no projecto:
- src/models/network_utils.py — is_private(), get_network_zone()
- src/models/python_core.py — tipos, f-strings, comprehensions, unpacking, walrus, regex
- Exercism submetidos: hello-world, two-fer, bob
- Git: 3 commits

Quero continuar para o Dia 3.
```

---

## Objectivo

Dominar os padrões Python usados todos os dias com contexto de redes e segurança.

---

## Steps executados

### Step 1 — Tipos, type hints, f-strings

```bash
ssh netsec-vm && cd ~/projects/netsec && source .venv/bin/activate
touch src/models/python_core.py
```

`src/models/python_core.py`:
```python
from __future__ import annotations
from typing import Optional

ip: str = "192.168.0.43"
port: int = 22
is_blocked: bool = False
packets: float = 1_024.5

msg: str = f"SSH: {ip}:{port} → bloqueado={is_blocked}"
print(msg)

threat_score: int = 87
country: str = "Russia"
print(f"IP: {ip:<20} Score: {threat_score:3d}/100  País: {country}")

geo_country: Optional[str] = None
print(f"País: {geo_country or 'desconhecido'}")
```

### Step 2 — Comprehensions

```python
# List comprehension
private_ips: list[str] = [
    ip for ip in ips if ip.startswith(("192.", "10.", "172."))
]

# Dict comprehension
DANGEROUS: set[int] = {23, 3389, 445, 5900, 1433}
port_risk: dict[int, str] = {
    p: ("🔴 alto" if p in DANGEROUS else "🟢 normal") for p in PORTS
}

# Set comprehension — IPs únicos de logs com duplicados
unique_blocked: set[str] = {
    line.split()[0]       # 1º campo = IP
    for line in log_lines
    if "block" in line    # só linhas bloqueadas
}
```

> O set comprehension percorre `log_lines`, filtra as que têm "block",
> parte cada linha por espaços (`.split()`), pega no índice 0 (o IP),
> e o `{}` elimina duplicados automaticamente.

### Step 3 — Unpacking e walrus operator

```python
import re

# Unpacking directo
src_ip, dst_port, protocol, action = "1.2.3.4 443 tcp block".split()

# * para ignorar campos do meio
rule_num, *_ignored, src = ["5", "0", "0", "em0", "block", "tcp", "1.2.3.4"]

# Walrus operator := — assign + test numa linha
PATTERN = re.compile(
    r"(?P<action>block|pass).*?(?P<src>\d+\.\d+\.\d+\.\d+):(?P<sport>\d+)"
    r".*?(?P<dst>\d+\.\d+\.\d+\.\d+):(?P<dport>\d+)"
)
for entry in log_entries:
    if m := PATTERN.search(entry):    # faz o match E verifica se existe
        print(f"{m.group('action')} {m.group('src')} → porto {m.group('dport')}")
```

### Step 4 — Exercism

```bash
curl -L https://github.com/exercism/cli/releases/latest/download/exercism_linux_x86_64.tar.gz \
  | tar -xz -C ~/.local/bin/
exercism configure --token=TOKEN
exercism download --exercise=hello-world --track=python
exercism download --exercise=two-fer --track=python
exercism download --exercise=bob --track=python
# testar e submeter cada um
```

```bash
ruff check src/ && mypy src/models/python_core.py
git add src/models/python_core.py
git commit -m "feat: python core — comprehensions, unpacking, walrus"
```

---

## ✅ Resumo — alterações feitas

**Ficheiros criados:** `src/models/python_core.py`

**Conceitos:**

| Conceito | Exemplo |
|---|---|
| Type hints | `ip: str`, `Optional[str]`, `list[str]`, `dict[int, str]` |
| f-strings | `{ip:<20}`, `{score:3d}` |
| List comprehension | filtrar IPs privados |
| Dict comprehension | mapear porto → risco |
| Set comprehension | IPs únicos de logs (elimina duplicados) |
| Unpacking | `src, port, proto, action = line.split()` |
| Walrus `:=` | `if m := PATTERN.search(entry):` |
| Regex grupos nomeados | `(?P<action>block\|pass)` |

**Exercism:** hello-world · two-fer · bob

**Git:** commit 3: `feat: python core — comprehensions, unpacking, walrus`
