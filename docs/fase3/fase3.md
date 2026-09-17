# NetGuard AI — Fase 3: Pentesting

**Duração:** Meses 7–12 (~24 semanas)
**Pré-requisito:** Fase 2 concluída · ler `CLAUDE.md` na raiz

---

## Objectivo

Aprender a pensar como um atacante para defender melhor — e para demonstrar a clientes o quão vulnerável a sua infraestrutura está. Produzir relatórios de pentest profissionais com CVSS scoring.

## Entrega final

- Competências para fazer pentest completo a uma rede de PME
- Relatório profissional com findings CVSS e remediação priorizada
- Relatório before/after do próprio produto NetGuard AI
- Certificação eJPT ou CEH obtida

---

## Aviso legal

> ⚠️ Nunca fazer pentest em sistemas sem autorização escrita explícita do proprietário.
> Usar sempre labs controlados (VMs próprias).
> Lei portuguesa — art.º 7.º da Lei do Cibercrime — é clara sobre acesso não autorizado.

---

## Certificações

| Certificação | Custo | Quando |
|---|---|---|
| **eJPT** (eLearnSecurity) | ~200€ | Final Fase 3 — prático, hands-on, recomendado primeiro |
| **CEH v13** (EC-Council) | ~550€ | Após eJPT — reconhecido por grandes empresas |

---

## Visão geral das semanas

| Semana | Foco | Entregável |
|---|---|---|
| 1–4 | Kali Linux + metodologia + OWASP Top 10 | TryHackMe paths concluídos |
| 5–8 | PortSwigger Web Security Academy | 60+ labs concluídos |
| 9–12 | Network pentesting + VMs vulneráveis | HackTheBox easy machines |
| 13–16 | WiFi + IoT security | Relatório de segurança IoT |
| 17–20 | Relatórios profissionais + CVSS | Template de relatório de pentest |
| 21–24 | Pentest ao NetGuard AI + certificação | Relatório before/after + eJPT |

---

## Hardware adicional

- **VM Kali Linux** no VirtualBox (4GB RAM, 50GB disco, Rede Interna "netsec-lab")
- **Adaptador WiFi Alfa AWUS036ACH** (~30€) — para pentest WiFi (modo monitor + injection)

**Ligação no lab:**
```
VM Kali (192.168.10.99) ──[netsec-lab]──► pfSense GREEN (192.168.10.1)
                                              └── ataca VMs em ambiente isolado
```

---

## Ferramentas principais (Kali)

| Ferramenta | Para quê |
|---|---|
| nmap | Reconhecimento, port scanning, OS detection |
| Metasploit | Framework de exploits |
| Burp Suite | Intercepção e análise de tráfego HTTP/HTTPS |
| Wireshark | Análise de pacotes |
| Hashcat / John | Cracking de passwords |
| Hydra | Brute force SSH, FTP, HTTP |
| SQLmap | Detecção e exploração de SQL injection |
| Aircrack-ng | Pentest WiFi |
| nikto | Scanner de vulnerabilidades web |

---

## Metodologia de pentest

1. **Reconhecimento** — recolha passiva e activa de informação
2. **Scanning** — identificar hosts, portos, serviços, versões
3. **Enumeração** — extrair detalhes de utilizadores, partilhas, serviços
4. **Exploração** — executar exploits, ganhar acesso
5. **Pós-exploração** — escalada de privilégios, persistência, pivot
6. **Relatório** — findings com CVSS, remediação priorizada

---

## Estado

⬜ Fase 3 ainda não iniciada — a iniciar após conclusão da Fase 2

---

## Como iniciar o Dia 1 da Fase 3

```
Estou a iniciar a Fase 3 do NetGuard AI. Ler CLAUDE.md e docs/fase3/fase3.md.
Quero o Dia 1 da Fase 3 detalhado — setup Kali Linux em VM VirtualBox,
primeiras ferramentas, e metodologia de pentest profissional.
```
