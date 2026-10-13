
import base64

import requests


VIRUSTOTAL_URL_API = "https://www.virustotal.com/api/v3/urls"


def url_to_vt_id(url):
    """Encode a URL in the format expected by VirusTotal's URL endpoint."""
    return (
        base64.urlsafe_b64encode(url.encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )


def lookup_virustotal(url, api_key):
    """Look up an existing URL report. Never submit a new scan."""

    if not api_key or not api_key.strip():
        return {
            "status": "error",
            "message": "VirusTotal API key is not configured.",
        }

    url_id = url_to_vt_id(url)
    endpoint = f"{VIRUSTOTAL_URL_API}/{url_id}"

    try:
        response = requests.get(
            endpoint,
            headers={"x-apikey": api_key.strip()},
            timeout=15,
        )

        if response.status_code == 404:
            return {
                "status": "not_found",
                "message": (
                    "VirusTotal has no existing report for this URL. "
                    "This does not mean the URL is safe."
                ),
            }

        response.raise_for_status()
        payload = response.json()

        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))

        return {
            "status": "reported" if malicious or suspicious else "clean",
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "message": (
                "Existing VirusTotal report retrieved. "
                "Detection results are not a guarantee."
            ),
        }

    except requests.Timeout:
        return {
            "status": "error",
            "message": "VirusTotal request timed out. Try again later.",
        }

    except requests.RequestException as exc:
        status_code = getattr(
            getattr(exc, "response", None),
            "status_code",
            None,
        )

        if status_code in (401, 403):
            message = (
                "VirusTotal rejected the API key or access request. "
                "Check your key and API permissions."
            )
        elif status_code == 429:
            message = (
                "VirusTotal rate limit reached. Try again later."
            )
        else:
            message = (
                "Could not retrieve the VirusTotal report. "
                "Check your connection and API configuration."
            )

        return {"status": "error", "message": message}

    except (ValueError, TypeError, AttributeError):
        return {
            "status": "error",
            "message": "VirusTotal returned an unexpected response.",
        }
