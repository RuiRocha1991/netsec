# NetGuard AI — Fase 1: Python + Redes

**Duração:** Meses 1–3 (~12 semanas)
**Pré-requisito:** ler `CLAUDE.md` na raiz do projecto

---

## Objectivo

Construir o agente base do NetGuard AI em Python — um sistema que recebe logs do pfSense em tempo real, parseia, detecta anomalias e alerta. No final da fase tens um produto já demonstrável a clientes.

## Entrega final

`pfSense Log Collector` — container Docker que:
- Recebe logs pfSense em tempo real via syslog UDP
- Parseia e persiste em SQLite
- Enriquece com GeoIP e AbuseIPDB
- Detecta anomalias com ML (Isolation Forest)
- Expõe via FastAPI
- Visualiza em Grafana
- Alerta no Telegram
- Gera relatório PDF semanal automático

---

## Visão geral das semanas

| Semana | Foco | Entregável |
|---|---|---|
| 1 | Python core + modelo de dados | `network_utils.py`, `LogEntry` dataclass, parser pfSense |
| 2 | Persistência + enriquecimento | SQLite, syslog UDP, motor de regras YAML, AbuseIPDB, GeoIP |
| 3 | API REST + alertas | FastAPI, Pydantic schemas, webhook, auth, Telegram |
| 4 | Séries temporais + dashboard | InfluxDB, Grafana provisionado, painéis em tempo real |
| 5 | Análise de tráfego avançada | Pandas (heatmaps, top talkers), Scapy, baseline IoT |
| 6 | Machine Learning | Feature engineering, Isolation Forest, scoring em tempo real |
| 7 | Relatórios + qualidade | weasyprint PDF semanal, refactor, mypy strict, checkpoint Fase 1 v1 |
| 8 | LLM — análise em português | Anthropic SDK, prompt design, structured output, cache |
| 9 | RAG | LangChain, ChromaDB, ingestão MITRE ATT&CK + OWASP |
| 10 | Agente autónomo | LangGraph, tool use, human-in-the-loop |
| 11 | Containerização + CI/CD | Docker, docker-compose local, GitHub Actions |
| 12 | Entrega da Fase 1 | Documentação, guião de demo, hardening, tag `fase1-v1` |

---

## Regras da fase

- Activar sempre o venv: `source ~/projects/netsec/.venv/bin/activate`
- `ruff check src/` e `mypy src/` antes de cada commit
- Um commit por dia no mínimo
- 64 testes actuais — não deixar regredir

---

## Estado das semanas

### SEMANA 1 — Python core + modelo de dados

| Dia | Tema | Estado | Ficheiros criados |
|---|---|---|---|
| 1 | Configuração do ambiente | ✅ | pyproject.toml, .gitignore, .env.example, network_utils.py (v1) |
| 2 | Python core (tipos, comprehensions, walrus) | ✅ | src/models/python_core.py |
| 3 | Wireshark + tshark + pyshark | ✅ | scripts/analyze_pcap.py |
| 4 | Funções de rede (NetworkZone, DANGEROUS_PORTS, classify_event) | ✅ | src/models/network_utils.py (completo) + tests/test_network_utils.py |
| 5 | LogEntry dataclass | ✅ | src/models/log_entry.py + tests/test_log_entry.py |
| 6 | Parser pfSense filterlog | ✅ | src/parsers/pfsense_parser.py + tests/test_pfsense_parser.py |
| 7 | Pipeline completo: ficheiro log → SQLite | ⬜ próximo | — |

### SEMANA 2 — Persistência + enriquecimento (concluída — planos escritos)

| Dia | Tema |
|---|---|
| 8 | Suporte IPv6 + regex avançado |
| 9 | Servidor syslog UDP (threading + queue) |
| 10 | Queries SQLite avançadas + Pandas |
| 11 | Motor de regras YAML |
| 12 | AbuseIPDB — threat intelligence |
| 13 | GeoIP com MaxMind GeoLite2 |
| 14 | Pipeline completo + revisão da Semana 2 |

### SEMANA 3 — API REST + alertas (planos escritos)

| Dia | Tema |
|---|---|
| 15 | FastAPI base — GET /health, /events, /stats |
| 16 | Pydantic models e validação de inputs |
| 17 | Paginação, filtros e ordenação nos endpoints |
| 18 | Alertas Telegram Bot em tempo real |
| 19 | Webhook pfSense → FastAPI (`IngestPipeline` partilhado) |
| 20 | Autenticação API key nos endpoints |
| 21 | Testes e2e com httpx/uvicorn + revisão Semana 3 |

### SEMANAS 4–12 — planos previstos

| Semana | Dias | Conteúdo previsto |
|---|---|---|
| **Sem 4** | 22–28 | InfluxDB + Grafana provisionado — dashboards em tempo real |
| **Sem 5** | 29–35 | Pandas avançado (heatmaps, top talkers) + Scapy + baseline IoT |
| **Sem 6** | 36–42 | Feature engineering + Isolation Forest (ML anomaly detection) |
| **Sem 7** | 43–49 | weasyprint PDF semanal + refactor + mypy strict + checkpoint Fase 1 v1 |
| **Sem 8** | 50–56 | Anthropic SDK — análise de alertas em português, structured output |
| **Sem 9** | 57–63 | LangChain + ChromaDB — RAG sobre MITRE ATT&CK e OWASP Top 10 |
| **Sem 10** | 64–70 | LangGraph — agente autónomo, tool use, human-in-the-loop |
| **Sem 11** | 71–77 | Docker + docker-compose local + CI/CD com GitHub Actions |
| **Sem 12** | 78–84 | Documentação, guião de demo, hardening, tag `fase1-v1` |

---

## Código existente — resumo dos módulos

### `src/models/network_utils.py`

```python
class NetworkZone(StrEnum):
    GREEN = "GREEN"      # 192.168.10.0/24
    DMZ   = "DMZ"        # 192.168.30.0/24
    IOT   = "IOT"        # 192.168.40.0/24
    MGMT  = "MGMT"       # 192.168.1.0/24
    EXTERNAL = "EXTERNAL"

DANGEROUS_PORTS = frozenset({22, 23, 3389, 445, 5900, 1433, 3306, 6379, 27017})

def is_private(ip: str) -> bool: ...
def get_network_zone(ip: str) -> NetworkZone: ...
def is_dangerous_port(port: int) -> bool: ...
def classify_event(src_ip, dst_ip, dst_port, action) -> str:
    # Devolve "HIGH: ...", "MEDIUM: ...", "LOW: ...", "INFO: ..."
```

### `src/models/log_entry.py`

```python
@dataclass
class LogEntry:
    # Campos do log (obrigatórios)
    timestamp: datetime
    action: str          # "block" | "pass"
    interface: str       # "em0", "em1"
    protocol: str        # "tcp", "udp", "icmp"
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int

    # Campos calculados automaticamente (__post_init__)
    src_zone: NetworkZone
    dst_zone: NetworkZone
    is_src_private: bool
    is_dangerous: bool
    classification: str  # resultado de classify_event()

    # Campos opcionais (enriquecimento externo)
    geo_country: str | None = None
    abuse_score: int | None = None  # 0–100 AbuseIPDB

    # Propriedades
    @property
    def is_high_priority(self) -> bool:
        return self.classification.startswith("HIGH")

    @property
    def risk_score(self) -> int:
        # 0–100, soma: block(+20), external(+30), dangerous_port(+30), abuse_score(+20 max)
```

### `src/parsers/pfsense_parser.py`

```python
def parse_line(line: str, year: int | None = None) -> Optional[LogEntry]:
    # Parseia linha syslog filterlog pfSense → LogEntry
    # Suporta TCP, UDP, ICMP (IPv4 apenas — IPv6 fica para Dia 8)
    # Devolve None se não for filterlog ou estiver malformada

def parse_file(path: str, year: int | None = None) -> list[LogEntry]:
    # Lê ficheiro linha a linha, devolve lista de LogEntry válidos
```

**Formato filterlog pfSense:**
```
Sep 17 10:30:45 pfsense filterlog[12345]: 5,,,0,em0,match,block,in,4,0x0,,64,1234,0,none,6,tcp,60,203.0.113.1,192.168.10.50,54321,22,0,S,111,0,0,mss
```
Índices relevantes: interface=4, action=6, direction=7, ip_ver=8, proto=16, src_ip=18, dst_ip=19, src_port=20, dst_port=21 (TCP/UDP apenas)

---

## Decisões técnicas da Fase 1

| Decisão | Motivo |
|---|---|
| Porta 22 em `DANGEROUS_PORTS` | SSH é alvo frequente de brute force — levantava HIGH priority correctamente |
| `LogEntry` como `@dataclass` | `__post_init__` calcula campos derivados automaticamente |
| `classify_event()` retorna string prefixada | `is_high_priority` usa `startswith("HIGH")` — simples, sem enums extra |
| IPv6 retorna `None` no parser | Deixado para Dia 8 — não crashar em linhas IPv6 |
| `errors="replace"` no `parse_file()` | Logs podem ter bytes inválidos — robustez sem crashar |

---

## Próximo: Dia 8

**Tema:** Suporte IPv6 + regex avançado

**O que construir:**
- Suporte básico IPv6 no `pfsense_parser.py` (índices CSV diferentes do IPv4)
- Regex avançado — grupos não-capturantes, alternância, flags
- Testes para linhas IPv6

**Conceitos Python novos:** `re` avançado, módulo `ipaddress` para IPv6
