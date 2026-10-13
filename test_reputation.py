
from reputation import lookup_virustotal, url_to_vt_id


def test_url_encoding_returns_text():
    result = url_to_vt_id("https://example.com")
    assert isinstance(result, str)
    assert result
    assert "=" not in result


def test_missing_api_key_does_not_make_request():
    result = lookup_virustotal("https://example.com", "")
    assert result["status"] == "error"
    assert "not configured" in result["message"]


def test_existing_report_not_found(monkeypatch):
    class FakeResponse:
        status_code = 404

    def fake_get(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr("reputation.requests.get", fake_get)

    result = lookup_virustotal(
        "https://example.com",
        "test-api-key",
    )

    assert result["status"] == "not_found"
    assert "does not mean" in result["message"]


def test_malicious_report_is_flagged(monkeypatch):
    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 2,
                            "suspicious": 1,
                            "harmless": 10,
                            "undetected": 5,
                        }
                    }
                }
            }

    def fake_get(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr("reputation.requests.get", fake_get)

    result = lookup_virustotal(
        "https://example.com",
        "test-api-key",
    )

    assert result["status"] == "reported"
    assert result["malicious"] == 2
    assert result["suspicious"] == 1
