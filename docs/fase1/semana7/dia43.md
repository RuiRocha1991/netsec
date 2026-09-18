# Dia 43 — weasyprint: fundamentos HTML→PDF

**Fase:** 1 · **Semana:** 7 · **Estado:** ⬜ Por fazer

---

## Prompt de contexto

```
Projecto: NetGuard AI. Dev: background Java 7 anos, a aprender Python.
VM netsec-vm (192.168.0.43), projecto ~/projects/netsec, venv .venv.

Dias 1-42 concluídos — Semana 6 fechada (tag `semana6`). Estado do projecto:
- src/ml/ — AnomalyModel, AnomalyScorer, WindowedFeatureBuilder
- src/analyzers/traffic_analysis.py — heatmap, resample, rolling
- src/analyzers/baseline.py — top talkers, ZoneBaseline
- tests/: ~215 testes, todos a passar
- Packages: scikit-learn, joblib, pandas, matplotlib, scapy, fastapi,
  influxdb-client, pyyaml, requests, python-dotenv, geoip2

Quero continuar para o Dia 43: fundamentos do weasyprint — converter HTML+CSS
em PDF, o motor por trás do relatório semanal automático (CLAUDE.md — "relatório
PDF semanal automático").
```

---

## Objectivo

O CLAUDE.md lista "relatório PDF semanal automático" como entregável do produto. Hoje aprendemos o mecanismo base: `weasyprint` renderiza HTML+CSS para PDF — permite usar as competências web (que qualquer developer já tem) em vez de uma API de desenho de PDF de baixo nível.

```
template.html + dados
        ↓ (Dia 44: Jinja2 preenche o template)
HTML final com CSS
        ↓
weasyprint.HTML(string=html).write_pdf()
        ↓
relatorio_semanal.pdf
```

---

## Conceitos Python novos

| Conceito | Onde é usado |
|---|---|
| `weasyprint.HTML(string=...)` / `.write_pdf()` | Converter HTML em PDF |
| CSS `@page` rule | Definir tamanho de página, margens, cabeçalho/rodapé |
| CSS `page-break-before`/`page-break-after` | Controlar quebras de página |
| Fontes do sistema vs `@font-face` | weasyprint usa Pango — fontes precisam de estar instaladas no SO |

---

## Steps

### Step 1 — Instalar weasyprint e dependências de sistema

```bash
# dependências de sistema (Ubuntu) — weasyprint usa Pango/Cairo para renderizar
sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
    libffi-dev shared-mime-info

pip install weasyprint
```

```toml
[project.optional-dependencies]
reports = ["weasyprint", "jinja2"]
```

---

### Step 2 — Primeiro PDF: prova de conceito

```python
# scripts/weasyprint_demo.py
from __future__ import annotations

from pathlib import Path

from weasyprint import HTML

_HTML = """
<html>
<head>
<style>
    @page {
        size: A4;
        margin: 2cm;
        @bottom-center { content: "NetGuard AI — página " counter(page); }
    }
    body { font-family: sans-serif; }
    h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 8px; }
    .metric { display: inline-block; margin: 10px 20px 10px 0; }
    .metric .value { font-size: 32px; font-weight: bold; color: #e94560; }
    .metric .label { font-size: 12px; color: #666; text-transform: uppercase; }
</style>
</head>
<body>
    <h1>Relatório de Segurança — Semana de teste</h1>
    <div class="metric"><div class="value">1247</div><div class="label">Eventos totais</div></div>
    <div class="metric"><div class="value">312</div><div class="label">Bloqueios</div></div>
    <div class="metric"><div class="value">18</div><div class="label">Alta prioridade</div></div>
</body>
</html>
"""


def main() -> None:
    output = Path("data/reports/demo.pdf")
    output.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=_HTML).write_pdf(str(output))
    print(f"PDF gerado em {output}")


if __name__ == "__main__":
    main()
```

```bash
python scripts/weasyprint_demo.py
```

Abrir `data/reports/demo.pdf` e confirmar: cabeçalho estilizado, métricas em destaque, numeração de página no rodapé.

---

### Step 3 — `src/reports/__init__.py` e `src/reports/pdf_renderer.py`

```bash
mkdir -p src/reports
touch src/reports/__init__.py
```

```python
from __future__ import annotations

from pathlib import Path

from weasyprint import HTML


class PDFRenderer:
    """Wrapper fino sobre weasyprint — converte HTML em ficheiro PDF."""

    def render(self, html: str, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        HTML(string=html).write_pdf(str(output_path))
        return output_path

    def render_bytes(self, html: str) -> bytes:
        """Devolve os bytes do PDF sem escrever em disco — útil para enviar por email/API."""
        return HTML(string=html).write_pdf()
```

---

### Step 4 — `tests/test_pdf_renderer.py`

```python
from __future__ import annotations

from pathlib import Path

from src.reports.pdf_renderer import PDFRenderer

_SIMPLE_HTML = "<html><body><h1>Teste</h1></body></html>"


class TestPDFRenderer:
    def test_render_creates_pdf_file(self, tmp_path: Path) -> None:
        renderer = PDFRenderer()
        output = renderer.render(_SIMPLE_HTML, tmp_path / "out.pdf")
        assert output.exists()
        assert output.stat().st_size > 0

    def test_pdf_has_valid_magic_bytes(self, tmp_path: Path) -> None:
        renderer = PDFRenderer()
        output = renderer.render(_SIMPLE_HTML, tmp_path / "out.pdf")
        assert output.read_bytes()[:5] == b"%PDF-"

    def test_render_bytes_returns_valid_pdf(self) -> None:
        renderer = PDFRenderer()
        data = renderer.render_bytes(_SIMPLE_HTML)
        assert data[:5] == b"%PDF-"
```

> Estes testes verificam que o resultado é um PDF sintacticamente válido (assinatura `%PDF-`) — não validam o conteúdo visual (isso exigiria renderização de imagem/OCR, fora de âmbito para testes unitários rápidos).

---

### Step 5 — Qualidade e commit

```bash
python -m pytest tests/ -v
# 215 + 3 = 218 testes

ruff check src/
mypy src/reports/ --strict --ignore-missing-imports

echo "data/reports/*.pdf" >> .gitignore

git add src/reports/ scripts/weasyprint_demo.py tests/test_pdf_renderer.py \
        pyproject.toml .gitignore
git commit -m "feat: dia 43 — fundamentos weasyprint (PDFRenderer)"
```

---

## Checklist

- [ ] Dependências de sistema do weasyprint instaladas
- [ ] `scripts/weasyprint_demo.py` gera PDF com CSS `@page` e numeração de página
- [ ] `PDFRenderer.render()` e `render_bytes()` implementados
- [ ] `data/reports/*.pdf` no `.gitignore`
- [ ] 3 testes a passar (validação de magic bytes `%PDF-`)
- [ ] `python -m pytest tests/ -v` → 218 passed
- [ ] Git commit realizado

---

## Resumo — alterações feitas

*(preencher após conclusão)*

**Ficheiros criados:**

| Ficheiro | Descrição |
|---|---|
| `src/reports/__init__.py` | Package reports |
| `src/reports/pdf_renderer.py` | `PDFRenderer` |
| `scripts/weasyprint_demo.py` | Prova de conceito HTML→PDF |
| `tests/test_pdf_renderer.py` | 3 testes |

**Próximo dia:** Dia 44 — template do relatório semanal com Jinja2
