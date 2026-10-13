
# 🛡️ LinkGuard

LinkGuard is a Python and Streamlit application that analyzes URLs for
common warning signs and optionally retrieves an existing VirusTotal report.

## Features

- URL validation and normalization
- Detection of IP-address URLs
- HTTP versus HTTPS warning
- Suspicious subdomain and known-brand impersonation heuristics
- Internationalized-domain and punycode warnings
- Checks for unusual ports, long URLs, and malformed hostnames
- Optional VirusTotal existing-report lookup
- Automated tests with pytest
- API-key configuration through a local environment file

## Technology

- Python
- Streamlit
- tldextract
- Requests
- python-dotenv
- pytest

## Setup

### 1. Download or clone the project

Open a terminal in the project folder.

### 2. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 3. Run the application

```bash
python -m streamlit run app.py
```

## Optional VirusTotal integration

LinkGuard can retrieve an existing URL report from VirusTotal.

1. Create an account with VirusTotal and review its API terms.
2. Obtain an API key through your account.
3. Create a local file named `.env` in the project folder.
4. Add the following line:

```text
VIRUSTOTAL_API_KEY=your_real_api_key_here
```

5. Restart Streamlit.

The `.env` file is excluded from Git by `.gitignore`.

Reputation checks are optional and require explicit selection in the interface.
They retrieve an existing report; they do not automatically submit new URLs
for scanning.

A URL lookup discloses the URL to VirusTotal. Do not check confidential URLs.

## Run automated tests

```bash
python -m pytest -v
```

The tests use mocked responses for the reputation API, so they do not require
a real API key or make actual VirusTotal requests.

## Important limitations

- Heuristic warnings are not proof that a URL is malicious.
- No warnings do not guarantee that a URL is safe.
- The known-brand list is limited and cannot cover every company.
- Public suffix data may not always be current.
- A URL with no existing VirusTotal report is not necessarily safe.
- Reputation services can produce false positives and false negatives.
- An API lookup may fail because of network issues, access restrictions,
  or rate limits.

## Privacy and security

Never commit API keys or `.env` files to a public repository.
Do not submit private or confidential URLs to external reputation services.

## Documentation

- Streamlit: https://docs.streamlit.io/
- tldextract: https://github.com/john-kurkowski/tldextract
- VirusTotal API: https://docs.virustotal.com/reference/overview
- pytest: https://docs.pytest.org/

## Disclaimer

LinkGuard is an educational URL-analysis tool, not a guarantee of website
safety or a replacement for browser security protections.
