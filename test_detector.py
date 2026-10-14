import pandas as pd

from detector import detect_request, detect_brute_force


def test_sql_injection_indicator():
    row = {
        "ip": "10.0.0.91",
        "method": "GET",
        "path": "/search?q=%27%20OR%201%3D1--",
        "status": 400,
    }

    findings = detect_request(row)

    assert any(
        finding["type"] == "Possible SQL Injection"
        for finding in findings
    )


def test_path_traversal_indicator():
    row = {
        "ip": "10.0.0.92",
        "method": "GET",
        "path": "/files/../../etc/passwd",
        "status": 403,
    }

    findings = detect_request(row)

    assert any(
        finding["type"] == "Possible Path Traversal"
        for finding in findings
    )


def test_brute_force_detection():
    start = pd.Timestamp("2026-10-11T10:00:00")

    rows = []

    for i in range(12):
        rows.append({
            "timestamp": start + pd.Timedelta(seconds=i * 3),
            "ip": "10.0.0.90",
            "path": "/login",
            "status": 401,
        })

    df = pd.DataFrame(rows)

    findings = detect_brute_force(df)

    assert any(
        finding["ip"] == "10.0.0.90"
        for finding in findings
    )


def test_normal_request():
    row = {
        "ip": "10.0.0.11",
        "method": "GET",
        "path": "/products",
        "status": 200,
    }

    findings = detect_request(row)

    assert findings == []


if __name__ == "__main__":
    test_sql_injection_indicator()
    test_path_traversal_indicator()
    test_brute_force_detection()
    test_normal_request()

    print("All detection tests passed.")