# Dia 80 — Guião de demo para clientes

**Fase:** 1 · **Semana:** 12 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-79 concluídos. docs/architecture.md documenta o sistema para
developers. CLAUDE.md — objectivo do projecto: "mudar de área — construir e
vender um produto de segurança de redes com IA para PMEs". O checkpoint do
Dia 49 e a verificação do Dia 78 confirmam que o agente base funciona.

Quero continuar para o Dia 80: um guião de demo concreto, pensado para ser
apresentado a um dono de café/clínica/escritório (público não-técnico) em
15-20 minutos — a diferença entre "ter um produto" e "conseguir vendê-lo".
```

---

## Objectivo

`docs/architecture.md` (Dia 79) é para developers; hoje é o oposto — um guião pensado para *convencer*, não para *explicar tecnicamente*. Uma demo mal preparada mata uma venda mesmo com produto bom por trás.

---

## Steps

### Step 1 — `docs/demo_script.md`

```markdown
# NetGuard AI — Guião de Demo (15-20 min)

## Preparação antes da reunião

- [ ] Ambiente demo isolado, com dados sintéticos realistas (NUNCA dados
      reais de outro cliente) — usar `scripts/generate_labeled_dataset.py`
- [ ] Dashboard Grafana aberto num separador, API/Swagger noutro
- [ ] Telegram configurado com um bot de demo (não o de produção)
- [ ] Ter um PDF de relatório semanal já gerado, pronto a mostrar
- [ ] Testar TUDO 30 minutos antes — nunca confiar que "ainda está a funcionar de ontem"

## 1. Abertura (2 min) — o problema, não o produto

Não começar por "isto é o NetGuard AI e tem estas features". Começar pela dor:
> "Sabes quantas vezes por dia alguém tenta invadir a tua rede? A maioria
> dos donos de negócio nunca sabe — só descobrem quando já é tarde. Deixa-me
> mostrar-te o que está a acontecer à tua rede agora mesmo, sem exagerar nem
> assustar."

## 2. Dashboard em tempo real (5 min)

- Abrir o Grafana, mostrar o painel "Eventos por minuto"
- Injectar tráfego ao vivo (`scripts/send_test_syslog.py`) — o dashboard
  reage em tempo real, efeito visual forte
- Apontar para "Top 10 IPs atacantes" — "isto são tentativas reais bloqueadas
  automaticamente, sem precisares de fazer nada"

## 3. Alerta Telegram ao vivo (3 min)

- Mostrar o telemóvel — enviar um evento HIGH de teste
- A mensagem chega em segundos, em português, sem jargão
- Destacar: "o sistema não só bloqueia — explica-te o que aconteceu, como se
  tivesses um técnico de segurança a avisar-te"

## 4. A camada de IA — o diferenciador (5 min)

- Mostrar a análise LLM completa (não só o alerta técnico)
- Se possível, mostrar o caso de um "falso positivo" bem tratado — o sistema
  reconhece que não é grave e não incomoda desnecessariamente
- Mencionar (sem entrar em detalhe técnico): "o sistema usa a mesma
  tecnologia de IA mais avançada do mercado para entender o contexto de
  cada ataque, não só aplicar regras fixas como as caixas normais que os
  operadores vendem"

## 5. Relatório semanal (2 min)

- Mostrar o PDF já gerado — "todas as segundas de manhã, recebes isto
  automaticamente, sem teres de olhar para nada durante a semana"

## 6. O diferenciador vs concorrência (2 min)

> "As operadoras vendem uma caixa fechada com regras genéricas iguais para
> toda a gente. O NetGuard AI é configurado especificamente para o teu
> negócio, e todos os anos fazemos um teste de invasão real ao teu sistema
> para provar que está protegido — não é só uma promessa."

## 7. Fecho — próximos passos (1 min)

- Não pedir fecho de venda na demo — pedir o próximo passo concreto:
  "Queres que façamos um levantamento da tua rede actual, sem compromisso,
  para veres exactamente o que a instalação envolveria?"

## Perguntas frequentes — respostas preparadas

| Pergunta provável | Resposta |
|---|---|
| "Isto vai abrandar a minha internet?" | Não — o NetGuard AI analisa cópias do tráfego (logs), não intercepta directamente cada pacote como um proxy faria. |
| "E se a Internet cair, fico sem proteção?" | O firewall pfSense continua a bloquear localmente mesmo sem ligação ao agente central — o agente adiciona visibilidade e IA, não é o único mecanismo de defesa. |
| "Quanto custa?" | [preencher consoante o modelo de preços definido — fora do âmbito técnico deste guião] |
| "Os meus dados ficam seguros?" | [preparar resposta sobre onde ficam os dados, GDPR, etc. — ver docs/fase2 e fase4 para a arquitectura de dados definitiva] |
```

---

### Step 2 — Ensaiar a demo end-to-end pelo menos uma vez

```bash
# arrancar todo o ambiente de demo
docker compose up -d
sleep 15
python scripts/generate_labeled_dataset.py
python scripts/train_model.py

# seguir o guião do início ao fim, cronometrando
```

Se algum passo demorar mais que o esperado ou falhar, ajustar o guião ou o ambiente antes da demo real — nunca descobrir um problema pela primeira vez à frente de um cliente.

---

### Step 3 — Preparar dados de demo realistas mas não assustadores

Revisitar `scripts/generate_labeled_dataset.py` (Dia 39) — confirmar que os IPs/padrões gerados são plausíveis sem serem excessivamente alarmantes (o objectivo é demonstrar valor, não gerar pânico que pareça exagero de vendedor).

---

### Step 4 — Sem testes `pytest` novos — este é um artefacto de negócio, não de código

```bash
python -m pytest tests/ -v
# sem alteração
```

### Step 5 — Commit

```bash
git add docs/demo_script.md
git commit -m "docs: dia 80 — guião de demo para clientes (não-técnico)"
```

---

## Checklist

- [ ] `docs/demo_script.md` com guião cronometrado (15-20 min)
- [ ] Perguntas frequentes com respostas preparadas
- [ ] Demo ensaiada end-to-end pelo menos uma vez, sem surpresas
- [ ] Dados de demo revistos para serem realistas sem serem alarmistas
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `docs/demo_script.md` | Guião de demo para clientes |

**Próximo dia:** Dia 81 — hardening: erros e logging de produção
