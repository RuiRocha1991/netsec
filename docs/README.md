# NetGuard AI — Documentação do projecto

> Ficheiro principal de navegação. O contexto completo está em `CLAUDE.md` na raiz.
> Este ficheiro serve apenas para navegar rapidamente para o dia em curso.

---

## Estado actual

**Fase 1 · Semana 1 · Dia 7 — próximo**

| Item | Valor |
|---|---|
| VM Ubuntu | `192.168.0.43` · alias `netsec-vm` |
| Projecto | `~/projects/netsec` |
| Activar venv | `source .venv/bin/activate` |
| Testes | `python -m pytest tests/ -v` → 64 passed |

---

## Roadmap

| Fase | Meses | Foco | Contexto |
|---|---|---|---|
| **1** | 1–3 | Python + redes + agente base | [`fase1/fase1.md`](fase1/fase1.md) |
| **2** | 4–6 | pfSense + lab RED/GREEN/DMZ | [`fase2/fase2.md`](fase2/fase2.md) |
| **3** | 7–12 | Pentesting + relatórios | [`fase3/fase3.md`](fase3/fase3.md) |
| **4** | 13–18 | Produto + IA + clientes | [`fase4/fase4.md`](fase4/fase4.md) |

---

## Fase 1 — dias

```
docs/fase1/
├── fase1.md                   ← contexto completo da fase
└── semana1/
    ├── dia1.md  ✅  Configuração do ambiente
    ├── dia2.md  ✅  Python core (tipos, comprehensions, walrus)
    ├── dia3.md  ✅  Wireshark + tshark + pyshark
    ├── dia4.md  ✅  Funções de rede (NetworkZone, DANGEROUS_PORTS)
    ├── dia5.md  ✅  LogEntry dataclass
    └── dia6.md  ✅  Parser pfSense filterlog
```

**Próximo:** Dia 7 — pipeline completo: ficheiro log → SQLite

---

## Como retomar

1. Verificar que tudo passa: `python -m pytest tests/ -v`
2. Abrir `docs/fase1/semana1/diaN.md` para o dia em curso
3. Copiar o bloco "Prompt de contexto" se precisar de iniciar sessão nova

**Verificação rápida:**
```bash
cd ~/projects/netsec && source .venv/bin/activate
python -m pytest tests/ -v && ruff check src/ && echo "✓ tudo ok"
```
