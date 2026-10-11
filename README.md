# 🛡️ LinkGuard — Phishing URL Checker

LinkGuard is a lightweight cybersecurity web application built with Python and Streamlit. It checks URLs for common warning signs associated with phishing and suspicious links.

## Features

- Detects URLs containing IP addresses instead of domain names.
- Flags unencrypted HTTP connections.
- Identifies URLs containing embedded credentials or `@` symbols.
- Checks for unusually long domains, URLs, and suspicious domain patterns.
- Provides simple explanations of detected warning signs.

## Technologies Used

- Python
- Streamlit
- Regular Expressions
- Python Standard Library

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/Thuto16/LinkGuard.git
cd LinkGuard
```

### 2. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 3. Run the application

```bash
python -m streamlit run app.py
```

## Limitations

LinkGuard uses basic URL-pattern heuristics. It does not verify a website's reputation or confirm whether a URL is malicious. A warning does not prove a link is dangerous, and no warning does not guarantee safety.

## Future Improvements

- Integrate a reputable URL reputation service.
- Improve detection of misleading subdomains.
- Add automated tests.
- Improve accessibility and interface styling.

## Author

**Oratile Thuto Mabe**

GitHub: [@Thuto16](https://github.com/Thuto16)