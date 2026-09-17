# NetGuard AI — Contexto para o Claude

> Este ficheiro é carregado automaticamente no início de cada sessão.
> Contém tudo o que o Claude precisa de saber para continuar sem perder contexto.

---

## Quem está a construir isto

- **Formação:** Licenciatura em Engenharia Informática
- **Experiência:** 7 anos backend Java — apps para Jira (Xporter, Xray), primeiro Data Center depois Cloud
- **Objectivo:** mudar de área — construir e vender um produto de segurança de redes com IA para PMEs
- **Python:** a aprender — frame explicações em termos de Java quando fizer sentido

---

## O produto — NetGuard AI

Sistema completo de segurança de redes para PMEs (cafés, clínicas, escritórios), instalado à medida:

- Appliance pfSense com arquitectura RED / GREEN / DMZ / IoT
- Suricata IDS/IPS + pfBlockerNG (threat intelligence)
- WireGuard VPN para acesso remoto seguro
- HAProxy como reverse proxy na DMZ (80/443 apenas)
- Traffic shaping por zona e por IP
- **Agente Python** com ML (anomaly detection) + LLM (análise de alertas em português)
- Dashboard Grafana em tempo real
- Alertas Telegram + relatório PDF semanal automático
- Pentest anual com relatório before/after

**Diferenciador:** operadores telecom vendem caixas fechadas com regras genéricas. O NetGuard AI é 100% configurável por cliente, com IA que explica alertas em português e pentest para demonstrar valor.

---

## Arquitectura de rede

```
Internet / ISP
      |
   [pfSense — Topton N100 4x 2.5GbE]
      |
      +— GREEN  192.168.10.0/24 — LAN privada (PCs, portáteis, NAS)
      +— IoT    192.168.40.0/24 — câmeras, sensores — sem acesso externo
      +— DMZ    192.168.30.0/24 — sites públicos — só 80/443 para fora
```

**Regra gold:** bloquear tudo por defeito. Só permitir o explicitamente necessário.

| De → Para | GREEN | IoT | DMZ | Internet |
|---|---|---|---|---|
| **GREEN** | ✓ livre | controlado | controlado | ✓ livre |
| **IoT** | ✗ bloqueado | ✓ livre | ✗ bloqueado | ✗ bloqueado |
| **DMZ** | ✗ bloqueado | ✗ bloqueado | ✓ livre | ✓ 80/443 |
| **Internet** | ✗ bloqueado | ✗ bloqueado | ✓ 80/443 | — |

---

## Deployment — VPS central

Agente Python num VPS central que agrega logs de todos os clientes:

```
Cliente A (pfSense) ──syslog TLS──►
Cliente B (pfSense) ──syslog TLS──► VPS Hetzner CX21 (3.79€/mês)
Cliente C (pfSense) ──syslog TLS──►     ├── Agente Python + ML
                                         ├── PostgreSQL multi-tenant
                                         ├── Grafana multi-org
                                         └── FastAPI + LangGraph
```

---

## Stack tecnológica

| Camada | Tecnologia |
|---|---|
| Firewall | pfSense CE |
| IDS/IPS | Suricata |
| Threat intel | pfBlockerNG-devel |
| VPN | WireGuard |
| Reverse proxy | HAProxy + Let's Encrypt |
| Linguagem | Python 3.12 |
| API | FastAPI + Pydantic |
| Base de dados | SQLite (dev) → PostgreSQL (prod) |
| Análise | Pandas, NumPy, scikit-learn |
| ML | Isolation Forest, Local Outlier Factor |
| Captura | Scapy, pyshark, tshark |
| Threat intel | AbuseIPDB (free tier), MaxMind GeoLite2 |
| LLM | Anthropic API (claude-sonnet-4-6) |
| Orquestração IA | LangChain + LangGraph |
| Vector store | ChromaDB |
| Monitorização | Grafana + InfluxDB |
| Alertas | Telegram Bot API |
| Relatórios | weasyprint (PDF) |
| Containers | Docker + docker-compose (Fase 4) |
| CI/CD | GitHub Actions |

---

## Ambiente de desenvolvimento

| Item | Valor |
|---|---|
| VM Ubuntu Server 24.04 | IP `192.168.0.43` · alias SSH `netsec-vm` |
| IP rede interna (para pfSense) | `192.168.10.50` |
| Projecto | `~/projects/netsec` |
| Python | `3.12.4` via pyenv |
| Activar venv | `source ~/projects/netsec/.venv/bin/activate` |
| VS Code | Remote-SSH → `netsec-vm` → `~/projects/netsec` |

**VMs VirtualBox:**
- VM 1 — Ubuntu Server 24.04 (activa, Fase 1)
- VM 2 — pfSense CE (criar na Fase 2)
- VM 3 — Kali Linux (criar na Fase 3)

---

## Estrutura do projecto

```
~/projects/netsec/
├── CLAUDE.md                  ← este ficheiro
├── pyproject.toml             ← ruff, mypy, pytest config
├── conftest.py
├── .env.example
├── src/
│   ├── models/
│   │   ├── network_utils.py   ← NetworkZone, is_private(), get_network_zone(),
│   │   │                         is_dangerous_port(), classify_event()
│   │   ├── log_entry.py       ← dataclass LogEntry (modelo central de eventos)
│   │   └── python_core.py     ← exemplos de Python core (aprendizagem)
│   ├── parsers/
│   │   └── pfsense_parser.py  ← parse_line(), parse_file() — formato filterlog
│   ├── analyzers/             ← vazio (Semana 2+)
│   ├── alerts/                ← vazio (Semana 3+)
│   └── db/                    ← vazio (Semana 2+)
├── tests/
│   ├── test_network_utils.py  ← 29 testes
│   ├── test_log_entry.py      ← 17 testes
│   └── test_pfsense_parser.py ← 18 testes
├── scripts/
│   └── analyze_pcap.py        ← análise .pcap com pyshark
├── data/
│   └── captures/              ← ficheiros .pcap (não vão para git)
└── docs/
    ├── README.md              ← índice e estado actual
    ├── fase1/                 ← fase1.md + semana1/ com dia1..dia6
    ├── fase2/                 ← fase2.md
    ├── fase3/                 ← fase3.md
    └── fase4/                 ← fase4.md
```

---

## Estado actual

**Fase 1 · Semana 1 — em curso**

| Dia | Tema | Estado |
|---|---|---|
| Dia 1 | Configuração do ambiente | ✅ |
| Dia 2 | Python core (tipos, comprehensions, walrus) | ✅ |
| Dia 3 | Wireshark + tshark + pyshark | ✅ |
| Dia 4 | Funções de rede + DANGEROUS_PORTS + classify_event() | ✅ |
| Dia 5 | LogEntry dataclass + propriedades + serialização | ✅ |
| Dia 6 | Parser pfSense filterlog (parse_line, parse_file) | ✅ |
| Dia 7 | Pipeline completo: ficheiro de log → SQLite | ⬜ próximo |

**Packages instalados:** `ruff mypy pytest pytest-asyncio pyshark`

**Testes:** 64 testes, todos a passar (`python -m pytest tests/ -v`)

---

## Convenções do projecto

### Git
- Um commit por dia no mínimo
- Mensagens: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`
- Branch por dia/tema: `netset-N`

### Python
- `from __future__ import annotations` em todos os ficheiros
- Type hints completos — mypy strict
- `ruff check src/` antes de cada commit
- Sem comentários óbvios — só WHY quando não é evidente
- Dataclasses para modelos de dados
- Nomes em inglês no código, comentários/docs em português

### Testes
- pytest, uma classe por módulo/função testada
- Testes de integração verificam campos calculados (zonas, classificação)
- Sem mocks à base de dados — usar SQLite real em ficheiro temporário

---

## Decisões técnicas tomadas

| Decisão | Motivo |
|---|---|
| Porta 22 (SSH) em `DANGEROUS_PORTS` | Alvo frequente de brute force — levantava HIGH priority correctamente |
| `LogEntry` como dataclass com `__post_init__` | Campos calculados (zona, is_dangerous, classification) automáticos na criação |
| `classify_event()` devolve string prefixada (HIGH/MEDIUM/LOW/INFO) | `is_high_priority` usa `startswith("HIGH")` — simples e extensível |
| IPv6 retorna `None` no parser | Ignorado para Dia 6 — tratado no Dia 8 |
| `parse_file()` usa `errors="replace"` | Logs podem ter caracteres inválidos — não crashar |

---

## Roadmap geral

| Fase | Meses | Foco | Ficheiro |
|---|---|---|---|
| **1** | 1–3 | Python + redes + agente base | `docs/fase1/fase1.md` |
| **2** | 4–6 | pfSense + lab RED/GREEN/DMZ | `docs/fase2/fase2.md` |
| **3** | 7–12 | Pentesting + relatórios profissionais | `docs/fase3/fase3.md` |
| **4** | 13–18 | Produto + IA + primeiros clientes | `docs/fase4/fase4.md` |

---

## Como retomar numa nova sessão

1. Os ficheiros de contexto são carregados automaticamente via `CLAUDE.md`
2. Verificar estado actual na tabela "Estado actual" acima
3. Abrir `docs/faseX/semanaY/diaN.md` para o dia em curso
4. Correr `python -m pytest tests/ -v` para confirmar que tudo passa
5. Continuar para o próximo dia

**Comando de verificação rápida:**
```bash
cd ~/projects/netsec && source .venv/bin/activate
python -m pytest tests/ -v && ruff check src/ && echo "✓ tudo ok"
```
