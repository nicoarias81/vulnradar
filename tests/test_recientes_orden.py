"""La tabla de recientes ordena por fecha de publicación, no por cálculo."""


def test_recientes_ordena_por_publicacion_y_no_por_calculo():
    """Un CVE sin fecha no puede colarse arriba de uno publicado.

    Con `coalesce(published, calculated_at)` el día de un stub sin fecha pasaba
    a ser hoy, empataba con los publicados ese día y el desempate alfabético
    subía CVEs de 2023 al tope de la home.
    """
    from dashboard.data import _order_sql

    sql = _order_sql("published")

    assert "c.published DESC NULLS LAST" in sql
    assert "calculated_at" not in sql
