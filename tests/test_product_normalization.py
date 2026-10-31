"""Extracción de vendor/product desde el registro CVE 5.0 y limpieza del nombre.

Sin red ni base: el registro entra como dict y se verifica el resultado.
"""
from core.normalizer import clean_product, extract_vendor_product


def test_clean_product_corta_prior_to():
    assert clean_product(
        "Google Chrome prior to 55.0.2883.75 for Mac, Windows and Linux, and 55.0.2883.84"
    ) == "Google Chrome"


def test_clean_product_corta_comparadores_y_versiones():
    assert clean_product("nginx < 1.25.3") == "nginx"
    assert clean_product("OpenSSL 3.0.x") == "OpenSSL"
    assert clean_product("Foo before 2.0") == "Foo"


def test_clean_product_respeta_nombres_con_numero():
    assert clean_product("Log4j2") == "Log4j2"
    assert clean_product("Windows 11") == "Windows 11"
    assert clean_product("Cisco IOS XE 17.9") == "Cisco IOS XE"


def test_extract_vendor_product_usa_cna_y_limpia():
    raw = {"containers": {"cna": {"affected": [
        {"vendor": "Google", "product": "Chrome prior to 120.0"},
    ]}}}

    assert extract_vendor_product(raw) == ("Google", "Chrome")


def test_extract_vendor_product_cae_al_bloque_adp():
    raw = {"containers": {
        "cna": {"affected": [{"vendor": "n/a", "product": "*"}]},
        "adp": [{"affected": [{"vendor": "Apache", "product": "Tomcat 9.0.0"}]}],
    }}

    assert extract_vendor_product(raw) == ("Apache", "Tomcat")


def test_extract_vendor_product_sin_affected():
    assert extract_vendor_product({}) == (None, None)
    assert extract_vendor_product(None) == (None, None)
    assert extract_vendor_product({"containers": {"cna": {}}}) == (None, None)
