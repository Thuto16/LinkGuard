
import ipaddress
import re
from urllib.parse import urlparse

import tldextract


# Use the bundled public suffix list without fetching it at runtime.
extract_domain = tldextract.TLDExtract(suffix_list_urls=())

KNOWN_BRANDS = {
    "amazon",
    "apple",
    "facebook",
    "github",
    "google",
    "instagram",
    "microsoft",
    "netflix",
    "openai",
    "outlook",
    "paypal",
}


def analyze_url(value):
    """Validate a URL and return a structured heuristic analysis."""

    def error(message):
        return {
            "status": "error",
            "url": None,
            "hostname": None,
            "registered_domain": None,
            "findings": [message],
        }

    # Validate the input.
    if not isinstance(value, str):
        return error("Please enter a URL as text.")

    value = value.strip()

    if not value:
        return error("Please enter a URL.")

    if any(char.isspace() or ord(char) < 32 for char in value):
        return error(
            "The URL contains whitespace or control characters."
        )

    if len(value) > 2048:
        return error("The URL is too long to analyze.")

    # Add HTTPS if the user did not provide a scheme.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value

    # Parse and validate the URL.
    try:
        parsed = urlparse(value)

        if parsed.scheme.lower() not in {"http", "https"}:
            return error("Only HTTP and HTTPS URLs are supported.")

        if not parsed.netloc or not parsed.hostname:
            return error("A valid hostname was not found.")

        # Accessing .port also validates the port number.
        port = parsed.port

    except ValueError:
        return error(
            "The URL contains an invalid hostname, port, or address."
        )

    hostname = parsed.hostname.rstrip(".").lower()

    if not hostname:
        return error("The hostname is empty.")

    findings = []
    registered_domain = None

    # Embedded credentials can be used to make URLs misleading.
    if parsed.username is not None or parsed.password is not None:
        findings.append(
            "The URL contains embedded credentials "
            "(username or password information)."
        )

    # Detect IP-address hostnames.
    try:
        ip_address = ipaddress.ip_address(hostname)
    except ValueError:
        ip_address = None

    if ip_address is not None:
        findings.append(
            "The website uses an IP address instead of a domain name."
        )

        if (
            ip_address.is_private
            or ip_address.is_loopback
            or ip_address.is_link_local
        ):
            findings.append(
                "The IP address is private, loopback, or link-local. "
                "Confirm that this destination is intentional."
            )

    else:
        # Convert internationalized hostnames to ASCII.
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            return error(
                "The hostname contains invalid international characters."
            )

        if len(ascii_hostname) > 253:
            return error("The hostname exceeds 253 characters.")

        labels = ascii_hostname.split(".")

        if any(not label for label in labels):
            return error(
                "The hostname contains an empty domain label."
            )

        # Validate each hostname label.
        for label in labels:
            if len(label) > 63:
                return error(
                    "A hostname label exceeds 63 characters."
                )

            if not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label,
            ):
                return error(
                    "The hostname contains an invalid domain label."
                )

        # Flag punycode labels for additional scrutiny.
        if any(label.startswith("xn--") for label in labels):
            findings.append(
                "The hostname contains an internationalized domain "
                "label. Check for lookalike characters."
            )

        if len(ascii_hostname) > 50:
            findings.append("The hostname is unusually long.")

        if ascii_hostname.count("-") >= 3:
            findings.append(
                "The hostname contains several hyphens."
            )

        # Analyze the hostname using the Public Suffix List.
        extracted = extract_domain(ascii_hostname)

        if extracted.domain and extracted.suffix:
            registered_domain = (
                f"{extracted.domain}.{extracted.suffix}"
            )

        subdomain = extracted.subdomain.lower()
        subdomain_labels = [
            label for label in subdomain.split(".") if label
        ]

        if len(subdomain_labels) >= 3:
            findings.append(
                "The URL contains several subdomain levels. "
                "Check which domain actually owns the website."
            )

        # A known brand appearing in a subdomain may be misleading.
        # This heuristic is not proof of impersonation.
        brand_labels = {
            label
            for label in subdomain_labels
            if label in KNOWN_BRANDS
        }

        if brand_labels:
            findings.append(
                "Possible brand impersonation: "
                + ", ".join(sorted(brand_labels))
                + " appears in a subdomain rather than the registered domain."
            )

        if not extracted.suffix:
            findings.append(
                "No recognized public domain suffix was found. "
                "This may be an unusual or internal hostname."
            )

    # Warn about unencrypted HTTP.
    if parsed.scheme.lower() == "http":
        findings.append(
            "The URL uses HTTP instead of encrypted HTTPS."
        )

    # Warn about non-standard ports.
    if port is not None and port not in {80, 443}:
        findings.append(
            f"The URL uses a non-standard web port ({port})."
        )

    # Check the overall URL length.
    if len(value) > 200:
        findings.append("The complete URL is unusually long.")

    return {
        "status": "warning" if findings else "low",
        "url": value,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "findings": findings or [
            "No obvious warning patterns were detected by these checks."
        ],
    }


def check_url(url):
    """Compatibility wrapper returning status and findings."""
    result = analyze_url(url)
    return result["status"], result["findings"]
