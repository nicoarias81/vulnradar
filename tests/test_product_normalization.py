"""Vendor/product extraction from the CVE 5.0 record and product name cleanup.

No network or DB: the record comes in as a dict and the result is checked.
"""
from core.normalizer import clean_product, extract_vendor_product


def test_clean_product_cuts_prior_to():
    assert clean_product(
        "Google Chrome prior to 55.0.2883.75 for Mac, Windows and Linux, and 55.0.2883.84"
    ) == "Google Chrome"


def test_clean_product_cuts_comparators_and_versions():
    assert clean_product("nginx < 1.25.3") == "nginx"
    assert clean_product("OpenSSL 3.0.x") == "OpenSSL"
    assert clean_product("Foo before 2.0") == "Foo"


def test_clean_product_keeps_names_with_numbers():
    assert clean_product("Log4j2") == "Log4j2"
    assert clean_product("Windows 11") == "Windows 11"
    assert clean_product("Cisco IOS XE 17.9") == "Cisco IOS XE"


def test_extract_vendor_product_uses_cna_and_cleans():
    raw = {"containers": {"cna": {"affected": [
        {"vendor": "Google", "product": "Chrome prior to 120.0"},
    ]}}}

    assert extract_vendor_product(raw) == ("Google", "Chrome")


def test_extract_vendor_product_falls_back_to_adp_block():
    raw = {"containers": {
        "cna": {"affected": [{"vendor": "n/a", "product": "*"}]},
        "adp": [{"affected": [{"vendor": "Apache", "product": "Tomcat 9.0.0"}]}],
    }}

    assert extract_vendor_product(raw) == ("Apache", "Tomcat")


def test_extract_vendor_product_without_affected():
    assert extract_vendor_product({}) == (None, None)
    assert extract_vendor_product(None) == (None, None)
    assert extract_vendor_product({"containers": {"cna": {}}}) == (None, None)
