\# SentinelX — Security Log Analysis and Incident Investigation



\## Overview



SentinelX is a Python-based cybersecurity project that analyzes application security logs, identifies suspicious activity, assigns heuristic risk scores, and presents potential incidents through an interactive dashboard.



\## Features



\* Security log analysis

\* Detection of possible SQL injection and path traversal indicators

\* Identification of potential brute-force login activity

\* Heuristic incident risk scoring

\* Structured JSON incident reports

\* Interactive dashboard with charts and filters

\* Synthetic security log generation

\* Basic automated detection tests



\## Technology Stack



\* Python

\* Streamlit

\* Pandas

\* Plotly

\* JSON



\## Project Setup



\### 1. Clone or download the project



Open PowerShell in the project directory.



\### 2. Create a virtual environment



```powershell

python -m venv .venv

```



\### 3. Activate the environment



```powershell

.\\.venv\\Scripts\\Activate.ps1

```



\### 4. Install dependencies



```powershell

python -m pip install -r requirements.txt

```



\### 5. Generate synthetic security logs



```powershell

python generate\_logs.py

```



\### 6. Run the tests



```powershell

python test\_detector.py

```



\### 7. Launch the dashboard



```powershell

python -m streamlit run app.py

```



\## Limitations



The detection rules and risk scores are heuristic indicators intended for demonstration and educational use. A finding does not prove that an attack occurred. The project is not a replacement for a production security monitoring system.



\## Responsible Use



Use synthetic logs or authorized security data. Test vulnerable applications only in an isolated environment that you control.



