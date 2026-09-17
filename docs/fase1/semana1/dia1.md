# Dia 1 — Configuração do ambiente

**Fase:** 1 · **Semana:** 1 · **Estado:** ✅ Concluído

---

## Prompt de contexto

> Copiar este bloco para iniciar uma sessão nova no Claude sobre este dia.

```
Projecto: NetGuard AI — sistema de segurança de redes com IA para PMEs.
Dev: background Java 7 anos, a aprender Python para construir o produto.
VM Ubuntu Server 24.04 em 192.168.0.43, alias SSH "netsec-vm".
Projecto em ~/projects/netsec, Python 3.12.4 via pyenv, venv em .venv.
Arquitectura de rede alvo: pfSense com zonas GREEN(10.x)/IOT(40.x)/DMZ(30.x).
Stack: Python · FastAPI · SQLite · Pandas · scikit-learn · Anthropic API · LangChain · Grafana.

Dia 1 da Fase 1 está concluído. O que foi feito:
- VirtualBox: Adaptador 1 Bridged (192.168.0.43), Adaptador 2 Rede Interna netsec-lab (192.168.10.50)
- Netplan configurado com IPs fixos
- SSH sem password do Mac e Windows com alias netsec-vm
- pyenv + Python 3.12.4 instalado
- Projecto ~/projects/netsec criado com src/{parsers,analyzers,models,alerts,db}, tests/, scripts/
- pyproject.toml, .gitignore, .env.example criados
- src/models/network_utils.py com is_private() e get_network_zone()
- VS Code Remote-SSH configurado
- 2 commits feitos

Quero continuar para o Dia 2.
```

---

## Objectivo

Ter a VM Ubuntu Server acessível por SSH do Mac e Windows, Python 3.12 instalado, projecto criado e primeiro ficheiro Python a correr.

---

## Steps executados

### Step 1 — VirtualBox: duas interfaces de rede

Com a VM desligada → Definições → Rede:

**Adaptador 1 — bridge (rede doméstica):**
```
Ligado a:       Placa de rede em bridge
Modo promíscuo: Permitir tudo
```

**Adaptador 2 — rede interna pfSense:**
```
Ligado a:       Rede Interna
Nome:           netsec-lab
Modo promíscuo: Permitir tudo
```

### Step 2 — Pacotes do sistema

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget openssh-server tshark nmap net-tools \
  build-essential libssl-dev libffi-dev python3-dev zlib1g-dev libbz2-dev \
  libreadline-dev libsqlite3-dev libncursesw5-dev xz-utils tk-dev \
  libxml2-dev libxmlsec1-dev liblzma-dev

# tshark → "Should non-superusers capture packets?" → Yes
sudo usermod -aG wireshark $USER
```

### Step 3 — Netplan IP fixo

`/etc/netplan/00-installer-config.yaml`:
```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: false
      addresses: [192.168.0.43/24]
      routes: [{to: default, via: 192.168.0.1}]
      nameservers: {addresses: [8.8.8.8, 1.1.1.1]}
    enp0s8:
      dhcp4: false
      addresses: [192.168.10.50/24]
```
```bash
sudo netplan apply
```

### Step 4 — SSH sem password

```bash
# No Mac
ssh-keygen -t ed25519 -C "netguard-dev"
ssh-copy-id -i ~/.ssh/id_ed25519.pub UTILIZADOR@192.168.0.43
```

`~/.ssh/config` (Mac e Windows):
```
Host netsec-vm
    HostName 192.168.0.43
    Port 22
    User UTILIZADOR
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 60
```

### Step 5 — pyenv + Python 3.12.4

```bash
curl https://pyenv.run | bash
# adicionar ao ~/.bashrc:
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"

source ~/.bashrc
pyenv install 3.12.4 && pyenv global 3.12.4
```

### Step 6 — Estrutura do projecto

```bash
mkdir -p ~/projects/netsec/src/{parsers,analyzers,models,alerts,db}
mkdir -p ~/projects/netsec/{tests,data/logs,scripts}
cd ~/projects/netsec
touch src/__init__.py src/parsers/__init__.py src/analyzers/__init__.py
touch src/models/__init__.py src/alerts/__init__.py src/db/__init__.py
python -m venv .venv && source .venv/bin/activate
pip install --upgrade pip && pip install ruff mypy pytest pytest-asyncio
```

`pyproject.toml`, `.gitignore`, `.env.example` — ver netguard_fase1.md completo.

### Step 7 — Primeiro ficheiro Python

`src/models/network_utils.py` com `is_private()` e `get_network_zone()`.

```bash
git init && git add . && git commit -m "chore: initial project structure"
```

### Step 8 — VS Code Remote-SSH

Extensão Remote-SSH → Connect → netsec-vm → abrir ~/projects/netsec → seleccionar .venv.

---

## ✅ Resumo — alterações feitas

| O quê | Antes | Depois |
|---|---|---|
| VirtualBox Adaptador 1 | NAT | Bridged — VM visível na rede doméstica |
| VirtualBox Adaptador 2 | Desactivado | Rede Interna "netsec-lab" |
| IP enp0s3 | DHCP | 192.168.0.43/24 (fixo) |
| IP enp0s8 | sem IP | 192.168.10.50/24 (fixo) |
| SSH | com password | sem password (chave ed25519) |

**Ficheiros criados:**
`~/.bashrc` (pyenv) · `~/.ssh/authorized_keys` · `~/.ssh/config` (Mac+Win) ·
`pyproject.toml` · `.gitignore` · `.env.example` · `src/models/network_utils.py` · `.vscode/settings.json`

**Packages apt:** git curl wget openssh-server tshark nmap net-tools build-essential + libs Python

**Packages pip:** ruff mypy pytest pytest-asyncio

**Git:** commit 1: `chore: initial project structure` · commit 2: `chore: add VS Code settings`
