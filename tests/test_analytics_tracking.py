"""El snippet de Umami no va en las vistas con auto-refresh.

/soc recarga cada 8s por `<meta http-equiv="refresh">`: si trackea, cada recarga
suma una visita y las métricas del sitio quedan infladas (medido: 167 de 396
eventos eran recargas del panel).
"""
from dashboard.markup import document

SCRIPT = "analytics.munalabs.eu/script.js"


def test_pagina_normal_trackea():
    assert SCRIPT in document("<p>x</p>")


def test_vista_con_auto_refresh_no_trackea():
    assert SCRIPT not in document("<p>x</p>", refresh=8)


def test_track_explicito_gana_sobre_el_refresh():
    assert SCRIPT in document("<p>x</p>", refresh=8, track=True)
    assert SCRIPT not in document("<p>x</p>", track=False)
