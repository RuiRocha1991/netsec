# Dia 26 — Painéis: top IPs, mapa de zonas, alertas HIGH

**Fase:** 1 · **Semana:** 4 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-25 concluídos. Estado do projecto:
- Grafana provisionado como código (deploy/grafana/)
- Dashboard "NetGuard AI — Overview" com 3 painéis (eventos/min, total
  bloqueios, severidade)
- src/metrics/influx_client.py — MetricsClient.write_event() (sem tag src_ip)
- tests/: 155 testes, todos a passar

Quero continuar para o Dia 26: adicionar 3 painéis novos ao dashboard — top
IPs atacantes, matriz de tráfego entre zonas, e tabela de alertas HIGH/CRITICAL
recentes.
```

---

## Objectivo

Faltam ao dashboard as perguntas que um dono de café/clínica realmente quer responder de relance: "quem me está a atacar mais?", "que zonas estão a comunicar entre si?", "quais foram os alertas graves de hoje?".

**Decisão de design — cardinalidade:** `src_ip` como tag InfluxDB tem cardinalidade alta (potencialmente milhares de IPs distintos) — aceitável à escala de uma PME (dezenas de milhares de eventos/dia, não milhões), mas é uma troca consciente. Documentado aqui para não ser esquecido se o produto escalar para volumes maiores (nesse caso, mover para um measurement agregado periodicamente, ou usar `top()`/`highestMax()` do Flux sem indexar por IP).

---

## Conceitos novos

| Conceito | Onde é usado |
|---|---|
| Flux `group()` + `sum()` + `sort()` + `limit()` | Top-N num painel Grafana |
| Painel "Table" | Lista de alertas com colunas |
| Cardinalidade de tags InfluxDB | Trade-off entre granularidade e performance |
| Flux `pivot()` | Reorganizar dados long-format em colunas para tabela |

---

## Steps

### Step 1 — Adicionar tag `src_ip` ao `MetricsClient`

```python
# src/metrics/influx_client.py — actualizar write_event:
def write_event(
    self,
    action: str,
    src_zone: str,
    dst_zone: str,
    classification: str,
    protocol: str,
    src_ip: str | None = None,
) -> None:
    point = (
        Point("events")
        .tag("action", action)
        .tag("src_zone", src_zone)
        .tag("dst_zone", dst_zone)
        .tag("severity", classification.split(":")[0])
        .tag("protocol", protocol)
        .field("count", 1)
    )
    if src_ip:
        point = point.tag("src_ip", src_ip)
    self._write_api.write(bucket=self.bucket, record=point, write_precision=WritePrecision.S)
```

Actualizar `IngestPipeline._write_metrics` para passar `src_ip=entry.src_ip`.

---

### Step 2 — Painel "Top 10 IPs atacantes" (Bar chart horizontal)

```flux
from(bucket: "events")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "events")
  |> filter(fn: (r) => r.action == "block")
  |> filter(fn: (r) => r._field == "count")
  |> group(columns: ["src_ip"])
  |> sum()
  |> group()
  |> sort(columns: ["_value"], desc: true)
  |> limit(n: 10)
```

---

### Step 3 — Painel "Tráfego entre zonas" (Table)

```flux
from(bucket: "events")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "events")
  |> filter(fn: (r) => r._field == "count")
  |> group(columns: ["src_zone", "dst_zone"])
  |> sum()
  |> group()
  |> pivot(rowKey: ["src_zone"], columnKey: ["dst_zone"], valueColumn: "_value")
```

Resultado: uma linha por `src_zone`, uma coluna por `dst_zone`, célula = contagem — uma matriz de tráfego legível de relance (GREEN→IOT deve estar sempre a zero, por exemplo, confirmando visualmente a regra gold de bloqueio por defeito).

---

### Step 4 — Painel "Alertas HIGH/CRITICAL recentes" (Table)

```flux
from(bucket: "events")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "events")
  |> filter(fn: (r) => r.severity == "HIGH" or r.severity == "CRITICAL")
  |> filter(fn: (r) => r._field == "count")
  |> keep(columns: ["_time", "src_ip", "src_zone", "dst_zone", "severity", "protocol"])
  |> sort(columns: ["_time"], desc: true)
  |> limit(n: 50)
```

Configurar o painel Table com **Cell display mode: Color background** na coluna `severity` (vermelho para CRITICAL, laranja para HIGH) — Grafana suporta isto via *Field overrides → Value mappings*.

---

### Step 5 — Actualizar o JSON de provisioning

Adicionar os 3 novos objectos `panels` ao `deploy/grafana/dashboards/netguard/netguard-overview.json` (exportar de novo da UI depois de criar os painéis manualmente, ou editar o JSON directamente com as queries acima). Ajustar `gridPos` para não sobrepor os painéis existentes do Dia 24/25.

Actualizar o teste de validação:

```python
# tests/test_grafana_provisioning.py — adicionar:
def test_dashboard_has_all_six_panels(self) -> None:
    path = Path("deploy/grafana/dashboards/netguard/netguard-overview.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    titles = {p["title"] for p in data["panels"]}
    expected = {
        "Eventos por minuto", "Total de bloqueios", "Eventos por severidade",
        "Top 10 IPs atacantes", "Tráfego entre zonas", "Alertas HIGH/CRITICAL recentes",
    }
    assert expected <= titles
```

---

### Step 6 — Testar `write_event` com `src_ip`

```python
# tests/test_metrics_client.py — adicionar:
class TestMetricsClientSrcIp:
    def test_write_event_with_src_ip_tags_point(self, metrics: MetricsClient) -> None:
        metrics.write_event("block", "EXTERNAL", "GREEN", "HIGH: ssh", "tcp", src_ip="1.2.3.4")
        metrics._write_api.write.assert_called_once()

    def test_write_event_without_src_ip_still_works(self, metrics: MetricsClient) -> None:
        metrics.write_event("block", "EXTERNAL", "GREEN", "HIGH: ssh", "tcp")
        metrics._write_api.write.assert_called_once()
```

---

### Step 7 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 155 + 1 + 2 = 158 testes

ruff check src/
git add src/metrics/influx_client.py src/parsers/ingest_pipeline.py \
        deploy/grafana/dashboards/netguard/netguard-overview.json \
        tests/test_grafana_provisioning.py tests/test_metrics_client.py
git commit -m "feat: dia 26 — painéis top IPs, tráfego entre zonas e alertas HIGH"
```

---

## Checklist

- [ ] `write_event()` aceita `src_ip` opcional como tag
- [ ] Painel "Top 10 IPs atacantes" — bar chart ordenado
- [ ] Painel "Tráfego entre zonas" — tabela pivotada src_zone × dst_zone
- [ ] Painel "Alertas HIGH/CRITICAL recentes" — tabela com cores por severidade
- [ ] Trade-off de cardinalidade documentado neste ficheiro
- [ ] JSON de provisioning actualizado com os 6 painéis
- [ ] 3 testes novos a passar
- [ ] `python -m pytest tests/ -v` → 158 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros alterados:**

| Ficheiro | Descrição |
|---|---|
| `src/metrics/influx_client.py` | Tag `src_ip` opcional |
| `src/parsers/ingest_pipeline.py` | Passa `src_ip` a `write_event` |
| `deploy/grafana/dashboards/netguard/netguard-overview.json` | +3 painéis |
| `tests/test_metrics_client.py` | +2 testes |
| `tests/test_grafana_provisioning.py` | +1 teste |

**Próximo dia:** Dia 27 — alertas Grafana (thresholds) + testes de integração do writer InfluxDB
