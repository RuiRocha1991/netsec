# NetGuard AI — Fase 2: pfSense + Laboratório Real

**Duração:** Meses 4–6 (~12 semanas)
**Pré-requisito:** Fase 1 concluída · ler `CLAUDE.md` na raiz

---

## Objectivo

Montar fisicamente a arquitectura RED/GREEN/DMZ que vais vender a clientes. No final tens a rede completa funcional em VMs com Suricata IPS, pfBlockerNG, WireGuard VPN, HAProxy e traffic shaping — e o agente Python da Fase 1 a monitorizar tudo em tempo real.

## Entrega final

- Rede RED/GREEN/DMZ funcional na VM pfSense
- Suricata em modo IPS com rulesets ET Open activos
- pfBlockerNG com IP feeds e DNSBL activos
- WireGuard VPN — acesso remoto testado do Mac e telemóvel
- HAProxy com Let's Encrypt na DMZ
- Traffic shaping HFSC configurado
- Checklist de instalação para clientes (50 pontos)
- Agente Python da Fase 1 ligado ao pfSense real via syslog TLS

---

## Certificação em paralelo

**CompTIA Network+** — estudar durante estes 3 meses em paralelo com a prática.
Cobre exactamente o que se pratica nesta fase. Custo: ~350€.

---

## Visão geral das semanas

| Semana | Foco | Entregável |
|---|---|---|
| 1–2 | Hardware + instalação pfSense + zonas | VM pfSense com GREEN/IoT/DMZ configuradas |
| 3–4 | Suricata IDS/IPS + pfBlockerNG | IPS activo, listas de threat intel |
| 5–6 | WireGuard VPN + HAProxy + ACME | VPN funcional, sites públicos seguros |
| 7–8 | Traffic shaping + hardening pfSense | Limites por zona, checklist 50 pontos |
| 9–10 | Integração com agente Python (Fase 1) | Logs pfSense reais → pipeline Python |
| 11–12 | Testes + documentação + entrega | Rede testada, pronta para clientes |

---

## Hardware necessário

### Para esta fase (VMs)
- VM pfSense CE no VirtualBox (criar quando começar)
- VM Ubuntu da Fase 1 (já existe)

### Para clientes reais (hardware físico — adquirir antes da Fase 4)
- **pfSense:** Topton N100 4x 2.5GbE Intel i226 (~160€ AliExpress, sem RAM/SSD)
  - 8GB RAM DDR4 SO-DIMM (~20€)
  - 128GB SSD NVMe M.2 (~20€)
- **Switch (clientes):** TP-Link TL-SG3210XHP-M2 8 portas 2.5GbE PoE+ (~300€)
- **Switch (lab):** TP-Link TL-SG108E 8 portas 1GbE (~40€)

---

## Configuração da VM pfSense

Criar no VirtualBox quando iniciar a Fase 2:

| Campo | Valor |
|---|---|
| RAM | 2GB |
| vCPU | 2 |
| Disco | 20GB |
| Adaptador 1 (WAN) | NAT |
| Adaptador 2 (GREEN) | Rede Interna "netsec-lab" |
| Adaptador 3 (IoT) | Rede Interna "iot-net" |
| Adaptador 4 (DMZ) | Rede Interna "dmz-net" |

**Ligação com VM Ubuntu (Fase 1):**
```
VM Ubuntu (192.168.10.50) ──[netsec-lab]──► pfSense GREEN (192.168.10.1)
```

---

## VLANs e trunk

Quando usar mini-PC com 2 NICs + switch gerido, o trunk transporta todas as VLANs:

```
pfSense NIC 2 ──[cabo trunk]──► Switch gerido
                                  P1: trunk (tagged todas as VLANs)
                                  P2–P4: VLAN 10 (GREEN)
                                  P5: VLAN 40 (IoT)
                                  P6: VLAN 30 (DMZ)
```

---

## Arquitectura de syslog para o agente Python

```
pfSense filterlog ──syslog TLS:514──► VM Ubuntu (192.168.10.50)
                                          └── src/parsers/pfsense_parser.py
                                          └── src/db/storage.py
                                          └── FastAPI /events
                                          └── Grafana dashboard
```

---

## Estado

⬜ Fase 2 ainda não iniciada — a iniciar após conclusão da Fase 1 (Semana 12)

---

## Como iniciar o Dia 1 da Fase 2

Quando chegares ao início da Fase 2, diz ao Claude:

```
Estou a iniciar a Fase 2 do NetGuard AI. Ler CLAUDE.md e docs/fase2/fase2.md.
Quero o Dia 1 da Fase 2 detalhado — instalação pfSense CE na VM VirtualBox
com 4 interfaces (WAN NAT, GREEN netsec-lab, IoT iot-net, DMZ dmz-net),
acesso à WebUI a partir do Mac/Windows.
```
