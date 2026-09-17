# NetGuard AI — Documentação do projecto

> Ficheiro principal. Ler antes de iniciar qualquer sessão de trabalho.
> Para retomar numa sessão nova: abrir o ficheiro do dia actual e copiar o bloco de prompt.

---

## Contexto rápido

| Item | Valor |
|---|---|
| Projecto | Sistema de segurança de redes com IA para PMEs |
| Dev | Backend Java 7 anos → a mudar para Python + NetSec |
| VM Ubuntu | `192.168.0.43` · alias `netsec-vm` · pasta `~/projects/netsec` |
| Python | `3.12.4` via pyenv · venv em `~/projects/netsec/.venv` |
| Estado actual | Fase 1 · Semana 1 · Dia 5 concluído |

---

## Arquitectura de rede alvo

```
Internet
    │
[pfSense — Topton N100 4x 2.5GbE]
    ├── GREEN  192.168.10.0/24  LAN privada (PCs, portáteis)
    ├── IOT    192.168.40.0/24  câmeras, sensores — sem acesso externo
    └── DMZ    192.168.30.0/24  sites públicos — só 80/443
```

**VMs VirtualBox:**

| VM | SO | RAM | Quando |
|---|---|---|---|
| VM 1 | Ubuntu Server 24.04 | 2GB | Fase 1 — activa |
| VM 2 | pfSense CE | 2GB | Fase 2 |
| VM 3 | Kali Linux | 4GB | Fase 3 |

---

## Stack

Python 3.12 · FastAPI · SQLite → PostgreSQL · Pandas · scikit-learn · Scapy · pyshark · Anthropic API · LangChain · LangGraph · ChromaDB · Grafana · InfluxDB · Telegram Bot · weasyprint · Docker (Fase 4)

---

## Roadmap

| Fase | Meses | Foco | Ficheiro |
|---|---|---|---|
| **1** | 1–3 | Python + redes + agente base | `fase1/` |
| **2** | 4–6 | pfSense + lab RED/GREEN/DMZ | `fase2/` |
| **3** | 7–12 | Pentesting + relatórios | `fase3/` |
| **4** | 13–18 | Produto + IA + clientes | `fase4/` |

---

## Estrutura de docs

```
docs/
├── README.md                  ← este ficheiro
├── fase1/
│   └── semana1/
│       ├── dia1.md            ✅ concluído
│       ├── dia2.md            ✅ concluído
│       ├── dia3.md            ✅ concluído
│       ├── dia4.md            ✅ concluído
│       ├── dia5.md            ✅ concluído
│       └── dia6.md            ⬜ próximo
├── fase2/
├── fase3/
└── fase4/
```

Cada `diaX.md` tem:
- **Prompt de contexto** — copiar para chat novo, carrega tudo em poucos tokens
- Steps completos com comandos
- Output esperado
- Checklist
- Resumo do que foi feito e alterado

---

## Hardware

**Por cliente:** Topton N100 4x 2.5GbE (~180€) + TP-Link TL-SG3210XHP-M2 PoE+ (~300€) = ~480€
**Lab pessoal:** Topton N100 (~160€) + TP-Link TL-SG108E (~40€) = ~200€

---

## Certificações

Network+ (Fase 2) → eJPT (Fase 3) → CEH (após eJPT) → OSCP (opcional)
