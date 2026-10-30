"""
chart_svg.py
--------------------------------------------------------------------
Grafici a barre in SVG puro (nessuna dipendenza aggiuntiva oltre
jinja2, coerente con requirements.txt del modulo reporting), per dare
un colpo d'occhio visivo ai numeri che report_generator.py e
aggregate_report.py gia' calcolano ma che finora restavano solo in
tabelle/metric-box testuali.

L'SVG viene incorporato direttamente nell'HTML (nessun file immagine
separato da generare/servire) e reso con il filtro Jinja `|safe` nel
template - il testo che ci finisce dentro (nomi di motore, conteggi
numerici) e' generato qui a partire da dati interni del progetto, non
da input dell'utente finale, quindi non introduce rischio di
iniezione nel contesto in cui e' usato.
--------------------------------------------------------------------
"""

from __future__ import annotations

_BAR_COLORS = {
    "yara": "#6a1b9a",
    "semgrep": "#00838f",
    "cwe_checker": "#2e7d32",
    "veri positivi": "#2e7d32",
    "falsi negativi": "#b71c1c",
    "falsi positivi": "#e65100",
}
_DEFAULT_COLOR = "#546e7a"


def bar_chart_svg(
    data: dict[str, int],
    width: int = 480,
    bar_height: int = 26,
    gap: int = 10,
    label_width: int = 130,
) -> str | None:
    """
    Grafico a barre orizzontali, una barra per chiave di `data`
    (etichetta -> valore intero). Le etichette con un colore dedicato
    in _BAR_COLORS lo usano (es. i nomi dei tre motori, o le chiavi
    "true_positives"/"false_negatives"/"false_positives"); le altre
    prendono un grigio-blu neutro.

    Ritorna None se `data` e' vuoto o tutti i valori sono zero: niente
    da disegnare, meglio non mostrare un grafico vuoto e fuorviante
    (il template puo' quindi fare "{% if chart_svg %}" per decidere
    se includere la sezione).
    """
    items = list(data.items())
    if not items or all(v == 0 for _, v in items):
        return None

    max_val = max(v for _, v in items) or 1
    chart_area_width = width - label_width - 55  # spazio per l'etichetta valore a destra della barra
    height = len(items) * (bar_height + gap) + gap

    bars = []
    y = gap
    for label, value in items:
        bar_w = max(2, round((value / max_val) * chart_area_width)) if value else 0
        color = _BAR_COLORS.get(label, _DEFAULT_COLOR)
        text_y = y + bar_height / 2 + 4
        bars.append(
            f'<text x="{label_width - 8}" y="{text_y}" text-anchor="end" '
            f'font-size="12" font-family="sans-serif" fill="#333">{label}</text>'
            f'<rect x="{label_width}" y="{y}" width="{bar_w}" height="{bar_height}" '
            f'rx="3" fill="{color}" />'
            f'<text x="{label_width + bar_w + 6}" y="{text_y}" '
            f'font-size="12" font-family="sans-serif" fill="#333">{value}</text>'
        )
        y += bar_height + gap

    return (
        f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'xmlns="http://www.w3.org/2000/svg" role="img">'
        + "".join(bars)
        + "</svg>"
    )
