
from url_analyzer import analyze_url, check_url


def test_valid_example_domain():
    result = analyze_url("https://example.com")
    assert result["status"] == "low"
    assert result["registered_domain"] == "example.com"


def test_domain_without_scheme_gets_https():
    result = analyze_url("example.com")
    assert result["status"] == "low"
    assert result["url"] == "https://example.com"


def test_http_url_warns():
    result = analyze_url("http://example.com/login")
    assert result["status"] == "warning"
    assert any("HTTP" in item for item in result["findings"])


def test_ip_address_warns():
    result = analyze_url("http://192.168.1.25/login")
    assert result["status"] == "warning"
    assert any("IP address" in item for item in result["findings"])


def test_misleading_brand_subdomain_warns():
    result = analyze_url("https://paypal.com.fake-site.example")
    assert result["status"] == "warning"
    assert any(
        "brand impersonation" in item.lower()
        for item in result["findings"]
    )


def test_invalid_port_is_rejected():
    result = analyze_url("https://example.com:99999")
    assert result["status"] == "error"


def test_empty_input_is_rejected():
    result = analyze_url("")
    assert result["status"] == "error"


def test_non_string_input_is_rejected():
    result = analyze_url(None)
    assert result["status"] == "error"


def test_unsupported_scheme_is_rejected():
    result = analyze_url("ftp://example.com")
    assert result["status"] == "error"


def test_invalid_domain_label_is_rejected():
    result = analyze_url("https://-invalid.example")
    assert result["status"] == "error"


def test_whitespace_is_rejected():
    result = analyze_url("https://example .com")
    assert result["status"] == "error"


def test_overlong_url_is_rejected():
    result = analyze_url("https://example.com/" + "a" * 2050)
    assert result["status"] == "error"


def test_embedded_credentials_warn():
    result = analyze_url("https://user:password@example.com")
    assert result["status"] == "warning"
    assert any(
        "credentials" in item.lower()
        for item in result["findings"]
    )


def test_punycode_hostname_warns():
    result = analyze_url("https://xn--pple-43d.com")
    assert result["status"] == "warning"
    assert any(
        "internationalized" in item.lower()
        for item in result["findings"]
    )


def test_nonstandard_port_warns():
    result = analyze_url("https://example.com:8443")
    assert result["status"] == "warning"
    assert any("8443" in item for item in result["findings"])


def test_check_url_compatibility_wrapper():
    status, findings = check_url("https://example.com")
    assert status == "low"
    assert findings
