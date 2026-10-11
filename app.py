
import re
import ipaddress
from urllib.parse import urlparse

import streamlit as st

st.set_page_config(
    page_title="LinkGuard | URL Safety Checker",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ LinkGuard")
st.subheader("Check a link before you click.")
st.write(
    "Inspect URLs for common warning signs associated "
    "with phishing and suspicious links."
)

st.info(
    "This tool checks URL patterns only. It cannot "
    "guarantee that a website is safe or malicious."
)


def check_url(url):
    url = url.strip()
    findings = []

    if not url:
        return None, ["Please enter a URL."]

    if any(char.isspace() for char in url):
        return None, ["The URL contains spaces. Check your input."]

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if parsed.scheme not in ("http", "https") or not hostname:
            return None, ["This does not look like a valid web URL."]

        if parsed.username or parsed.password or "@" in parsed.netloc:
            findings.append("Contains an @ symbol or embedded login details.")

        try:
            ipaddress.ip_address(hostname)
            findings.append("Uses an IP address instead of a domain name.")
        except ValueError:
            pass

        if parsed.scheme.lower() == "http":
            findings.append("Uses HTTP instead of encrypted HTTPS.")

        if hostname.lower().startswith("xn--") or ".xn--" in hostname.lower():
            findings.append("Contains an internationalised domain name.")

        if len(hostname) > 50:
            findings.append("The domain name is unusually long.")

        if hostname.count("-") >= 3:
            findings.append("The domain contains several hyphens.")

        if len(url) > 200:
            findings.append("The URL is unusually long.")

        if findings:
            return "warning", findings

        return "low", ["No obvious warning patterns were detected."]

    except ValueError:
        return None, ["Unable to parse this URL. Check the address."]


url = st.text_input(
    "Paste a URL to inspect",
    placeholder="https://example.com/login"
)

if st.button("🔍 Check Link", use_container_width=True):
    result, findings = check_url(url)

    if result is None:
        st.error(findings[0])

    elif result == "warning":
        st.warning("⚠️ Potential warning signs detected")
        st.write("**Risk indicator: Warning**")

        for finding in findings:
            st.write(f"- {finding}")

    else:
        st.success("No obvious warning patterns detected")
        st.write("**Risk indicator: Low based on these checks**")

st.divider()
st.caption(
    "LinkGuard • Built with Python and Streamlit • "
    "Heuristic checks are not proof of website safety."
)
