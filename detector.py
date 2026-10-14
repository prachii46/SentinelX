import re
from urllib.parse import unquote

import pandas as pd


SQL_PATTERNS = [
    r"\bunion\s+select\b",
    r"\bor\s+1\s*=\s*1\b",
    r"\bdrop\s+table\b",
    r"\bselect\b.+\bfrom\b",
]

TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
]

SENSITIVE_PATHS = {
    "/.env",
    "/admin",
    "/backup",
    "/config",
    "/phpmyadmin",
}


def normalize_path(path):
    """
    Decode URL-encoded characters for inspection.
    This is a detection helper, not a URL security filter.
    """
    return unquote(str(path)).lower()


def detect_request(row):
    """
    Return rule-based indicators for a single request.
    """

    path = normalize_path(row["path"])
    findings = []

    # SQL injection-like patterns
    for pattern in SQL_PATTERNS:
        if re.search(pattern, path, re.IGNORECASE):
            findings.append({
                "type": "Possible SQL Injection",
                "severity": "HIGH",
                "score": 35,
                "reason": (
                    "Request contains a SQL-like "
                    "pattern requiring investigation."
                ),
            })
            break

    # Path traversal indicators
    for pattern in TRAVERSAL_PATTERNS:
        if re.search(pattern, path):
            findings.append({
                "type": "Possible Path Traversal",
                "severity": "HIGH",
                "score": 35,
                "reason": (
                    "Request contains a directory "
                    "traversal indicator."
                ),
            })
            break

    # Sensitive-looking endpoint discovery
    if path in SENSITIVE_PATHS:
        findings.append({
            "type": "Sensitive Path Discovery",
            "severity": "MEDIUM",
            "score": 20,
            "reason": (
                "Request targets a path commonly "
                "worth reviewing during security audits."
            ),
        })

    # Authentication failures
    if (
        str(row["path"]).split("?")[0] == "/login"
        and int(row["status"]) == 401
    ):
        findings.append({
            "type": "Authentication Failure",
            "severity": "LOW",
            "score": 5,
            "reason": "The login request returned HTTP 401.",
        })

    return findings


def detect_brute_force(df):
    """
    Flag sources with at least 10 failed logins
    within any rolling 60-second interval.
    """

    findings = []

    login_events = df[
        (df["path"].astype(str).str.split("?").str[0] == "/login")
        & (pd.to_numeric(df["status"], errors="coerce") == 401)
    ].copy()

    if login_events.empty:
        return findings

    login_events["timestamp"] = pd.to_datetime(
        login_events["timestamp"],
        errors="coerce",
    )

    login_events = login_events.dropna(
        subset=["timestamp"]
    )

    for ip, group in login_events.groupby("ip"):
        group = group.sort_values("timestamp")

        times = group["timestamp"].tolist()

        left = 0

        for right in range(len(times)):
            while (
                times[right] - times[left]
            ).total_seconds() > 60:
                left += 1

            count = right - left + 1

            if count >= 10:
                findings.append({
                    "ip": ip,
                    "type": "Possible Brute-Force Attack",
                    "severity": "HIGH",
                    "score": 40,
                    "evidence": (
                        f"{count} failed logins "
                        "within a 60-second window."
                    ),
                })
                break

    return findings


def correlate_authentication_events(df):
    """
    Group authentication events by source and time.
    Identify repeated failures followed by success.
    Return incident records with supporting evidence.
    """
    # 1. Keep login events.
    # 2. Sort by source IP and timestamp.
    # 3. Identify 401 events within a rolling window.
    # 4. Check for a subsequent 200 response.
    # 5. Return one incident with the relevant timestamps.
    pass