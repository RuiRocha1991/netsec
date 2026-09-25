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

## Modo de trabalho — Claude como tutor

Neste projecto o Claude actua como **tutor**, não apenas como executor de tarefas. O objectivo é o Rui perceber como funcionam todas as tecnologias (redes, pfSense, Suricata, ML, LLMs, etc.) para conseguir criar um produto realmente inovador no mercado.

- **Explicar o porquê antes do como:** conceito, problema que resolve e alternativas — só depois o código/configuração
- **Analogias com Java/backend** sempre que ajudem (Spring, JPA, interfaces, threads, etc.)
- **Ensinar a raciocinar:** perguntar/guiar o Rui a chegar à solução em vez de despejar código pronto, sobretudo em conceitos novos
- **Ligar ao produto:** dizer onde cada tecnologia se encaixa no NetGuard AI e como pode ser um diferenciador face à concorrência
- **Mostrar trade-offs e limites** das tecnologias (o que não faz bem, riscos de segurança, custos), não só o caminho feliz
- **Apontar oportunidades de inovação:** onde a IA/automação pode fazer algo que os operadores telecom e soluções fechadas não fazem
- **Verificar compreensão:** resumir no fim o que foi aprendido e sugerir um pequeno exercício ou pergunta de reflexão quando fizer sentido
- **Explicações em português (PT-PT)**, código em inglês, conforme as convenções abaixo

### Ficheiros `docs/faseX/semanaY/diaN.md` (próximos passos)

Ao criar um novo ficheiro de dia (ou de fase/semana), seguir a estrutura dos existentes (ver `docs/fase1/semana2/dia11.md` como referência) e aplicar a lógica de tutor:

1. **Cabeçalho:** `# Dia N — Tema` + `**Fase:** X · **Semana:** Y · **Estado:** ⬜ Por fazer` (passa a ✅ Concluído no fim do dia)
2. **Prompt de contexto:** bloco de código com o estado do projecto, para retomar noutra sessão
3. **Objectivo:** o problema que se resolve e **porquê** importa para o NetGuard AI (com exemplo curto)
4. **Conceito / Como funciona:** explicar a tecnologia ou ideia por trás (rede, segurança, ML, API…) com analogias Java, trade-offs e limites — *antes* dos steps
5. **Conceitos Python novos:** tabela `Conceito | Onde é usado`
6. **Steps** numerados: comandos, **código completo pronto a usar** (formato híbrido escolhido pelo Rui), testes e commit (mensagem `feat:`); só em conceitos muito novos (protocolo, algoritmo de ML) guiar primeiro com perguntas/pistas e dar a solução a seguir
7. **Onde inova:** onde este passo pode ser diferenciador face aos operadores telecom / soluções fechadas
8. **Checklist** de verificação (incluindo "consegues explicar X por palavras tuas?")
9. **Resumo:** ficheiros criados/alterados + o que foi aprendido + exercício ou pergunta de reflexão
10. **Próximo dia:** uma linha com o tema seguinte

### Regras de actualização da documentação

- **Sempre que uma tarefa for dada como concluída**, actualizar os ficheiros `.md` da **fase** (`docs/faseX/faseX.md`) e do **dia** (`diaN.md`): estado ✅, checklist, resumo do que foi feito e contagem de testes
- **Quando o Rui pedir para avançar para o próximo dia**, actualizar também o ficheiro do **próximo dia** (`diaN+1.md`): estado "em curso", prompt de contexto com o estado real do projecto e a estrutura de tutor acima
- Manter em sincronia este `CLAUDE.md` (tabela "Estado actual" e contagem de testes) e o `docs/README.md`
- Commit: `docs: dia N concluído — estado, testes e próximo passo (dia N+1)`

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
│   │   └── pfsense_parser.py  ← parse_line(), parse_file() — filterlog IPv4 + IPv6
│   ├── analyzers/             ← vazio (Semana 2+)
│   ├── alerts/                ← vazio (Semana 3+)
│   └── db/
│       └── storage.py         ← EventStorage (SQLite): insert_many(), stats(), top_blocked_ips()
├── tests/
│   ├── test_network_utils.py  ← 29 testes
│   ├── test_log_entry.py      ← 17 testes
│   ├── test_pfsense_parser.py ← 23 testes
│   └── test_storage.py        ← 7 testes
├── scripts/
│   ├── analyze_pcap.py        ← análise .pcap com pyshark
│   ├── generate_test_log.py   ← gera log pfSense sintético
│   ├── regex_lab.py           ← exercícios de regex avançado
│   └── ingest_log.py          ← pipeline log → SQLite + sumário
├── data/
│   └── captures/              ← ficheiros .pcap (não vão para git)
└── docs/
    ├── README.md              ← índice e estado actual
    ├── fase1/                 ← fase1.md + semana1/ com dia1..dia7
    ├── fase2/                 ← fase2.md
    ├── fase3/                 ← fase3.md
    └── fase4/                 ← fase4.md
```

---

## Estado actual

**Fase 1 · Semana 2 — em curso**

| Dia | Tema | Estado |
|---|---|---|
| Dia 1 | Configuração do ambiente | ✅ |
| Dia 2 | Python core (tipos, comprehensions, walrus) | ✅ |
| Dia 3 | Wireshark + tshark + pyshark | ✅ |
| Dia 4 | Funções de rede + DANGEROUS_PORTS + classify_event() | ✅ |
| Dia 5 | LogEntry dataclass + propriedades + serialização | ✅ |
| Dia 6 | Parser pfSense filterlog (parse_line, parse_file) | ✅ |
| Dia 7 | Pipeline completo: ficheiro de log → SQLite | ✅ |
| Dia 8 | Suporte IPv6 + regex avançado | ✅ |
| Dia 9 | Servidor syslog UDP com threading | ✅ |
| Dia 10 | Queries SQLite avançadas + Pandas | ✅ |
| Dia 11 | Motor de regras YAML configurável | ✅ |
| Dia 12 | AbuseIPDB — threat intelligence | ⬜ próximo |

**Packages instalados:** `pip install -e ".[dev,analysis,capture]"` — dev: `ruff mypy pytest pytest-asyncio` · analysis: `pandas pyyaml` · capture: `pyshark`

**Testes:** 92 testes, todos a passar (`python -m pytest tests/ -v`)

---

## Convenções do projecto

### Git
- Um commit por dia no mínimo
- Mensagens: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`
- Branch por dia/tema: `netsec-N`

### Python
- `from __future__ import annotations` em todos os ficheiros
- Type hints completos — mypy strict
- Usar sempre `X | None` em vez de `Optional[X]` — Python 3.10+ com `from __future__ import annotations`
- `ruff check src/` antes de cada commit (e `ruff check src/ --fix` para auto-corrigir)
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
| Parser IPv6 com índices próprios (`_V6_*`) | Layout real do filterlog IPv6: `class,flow,hoplimit,proto,proto_id,len,src,dst,sport,dport` — não é o do IPv4 |
| `parse_file()` usa `errors="replace"` | Logs podem ter caracteres inválidos — não crashar |
| `EventStorage` abre uma ligação SQLite por operação (`@contextmanager` com commit/rollback) | Simples e seguro; sem estado partilhado entre chamadas |
| `ingest_log.py` não deduplica | Correr duas vezes o mesmo log duplica eventos — a tratar quando houver ingestão contínua (syslog, Dia 9) |
| `*.db` e `data/logs/*.log` no `.gitignore` | Dados gerados localmente não vão para git |

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
