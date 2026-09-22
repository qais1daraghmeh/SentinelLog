
# SentinelLog - Security Log Analyzer & Threat Detection Tool

SentinelLog is a Python-based cybersecurity tool designed to parse authentication logs, analyze login behaviors, and detect potential security threats such as brute-force attacks.

## 🚀 Features
- **Log Parsing:** Extracts timestamps, IP addresses, usernames, and statuses.
- **Threat Detection:** Identifies multiple failed login attempts and targeted usernames.
- **Risk Scoring:** Calculates a risk score based on attack severity.
- **Automated Testing:** Fully tested using `pytest`.

## 💻 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/qais1daraghmeh/SentinelLog.git
   cd SentinelLog
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   .\.venv\Scripts\activate
   pip install -r requirements.txt
   ```

## 🛡️ Usage

Run the tool against any authentication log file:
```bash
python -m src.sentinellog.cli examples/sample_auth.log
```

## ⚠️ Disclaimer
This tool is intended for authorized, defensive security log analysis only.


