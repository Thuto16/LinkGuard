
import os

import streamlit as st
from dotenv import load_dotenv

from reputation import lookup_virustotal
from url_analyzer import analyze_url


load_dotenv()

st.set_page_config(
    page_title="LinkGuard | URL Safety Checker",
    page_icon="🛡️",
    layout="centered",
)

st.title("🛡️ LinkGuard")
st.subheader("Check a link before you click.")

st.write(
    "Analyze a URL for common warning signs and, optionally, "
    "look up an existing threat-intelligence report."
)

st.warning(
    "No checker is perfect. A low-risk result does not prove a URL "
    "is safe, and a warning does not prove a URL is malicious."
)

url = st.text_input(
    "URL to inspect",
    placeholder="https://example.com/login",
)

api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

check_reputation = st.checkbox(
    "Also check an existing VirusTotal report",
    value=False,
    help=(
        "If enabled, the URL is sent to VirusTotal to retrieve an "
        "existing report. Do not submit private or sensitive URLs."
    ),
)

if check_reputation and not api_key:
    st.info(
        "To enable reputation checks, configure VIRUSTOTAL_API_KEY "
        "in your local .env file. Local URL analysis still works."
    )

if st.button("🔍 Analyze URL", use_container_width=True):
    analysis = analyze_url(url)

    if analysis["status"] == "error":
        st.error("URL validation failed.")

        for finding in analysis["findings"]:
            st.write(f"- {finding}")

    else:
        st.subheader("URL analysis")

        st.write(f"**Hostname:** `{analysis['hostname']}`")

        if analysis["registered_domain"]:
            st.write(
                "**Registered domain:** "
                f"`{analysis['registered_domain']}`"
            )

        if analysis["status"] == "warning":
            st.warning("Potential warning signs detected.")

            for finding in analysis["findings"]:
                st.write(f"- {finding}")

        else:
            st.success("No obvious warning patterns detected.")

            for finding in analysis["findings"]:
                st.write(f"- {finding}")

        if check_reputation and api_key:
            st.divider()
            st.subheader("VirusTotal reputation")

            # Only perform the external lookup after explicit opt-in.
            with st.spinner("Retrieving existing report..."):
                report = lookup_virustotal(
                    analysis["url"],
                    api_key,
                )

            if report["status"] == "reported":
                st.error("VirusTotal reports potential threats.")
                st.write(
                    f"**Malicious detections:** {report['malicious']}"
                )
                st.write(
                    f"**Suspicious detections:** {report['suspicious']}"
                )
                st.write(
                    f"**Harmless detections:** {report['harmless']}"
                )
                st.write(
                    f"**Undetected:** {report['undetected']}"
                )
                st.caption(report["message"])

            elif report["status"] == "clean":
                st.success(
                    "No malicious or suspicious detections in the "
                    "retrieved report."
                )
                st.write(
                    f"**Harmless detections:** {report['harmless']}"
                )
                st.write(
                    f"**Undetected:** {report['undetected']}"
                )
                st.caption(report["message"])

            elif report["status"] == "not_found":
                st.info(report["message"])

            else:
                st.error(report["message"])

st.divider()

st.caption(
    "LinkGuard • Python • Streamlit • Heuristic analysis "
    "with optional VirusTotal lookup"
)

st.caption(
    "Privacy: external reputation lookups disclose the URL to "
    "VirusTotal. Avoid checking confidential or private URLs."
)
