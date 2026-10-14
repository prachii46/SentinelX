import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

OUTPUT = Path("data/sample_logs/security_events.csv")
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

start = datetime(2026, 10, 11, 10, 0, 0)

events = []

normal_ips = [
    "10.0.0.11",
    "10.0.0.12",
    "10.0.0.13",
    "10.0.0.14",
]

normal_paths = [
    "/",
    "/home",
    "/products",
    "/about",
    "/contact",
    "/login",
    "/dashboard",
]

def add_event(
    ip,
    method,
    path,
    status,
    seconds,
    user_agent="Mozilla/5.0",
):
    events.append({
        "timestamp": (
            start + timedelta(seconds=seconds)
        ).isoformat(),
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "user_agent": user_agent,
    })


# 1. Normal activity
for i in range(150):
    ip = random.choice(normal_ips)
    path = random.choice(normal_paths)

    status = 200

    if path == "/login" and random.random() < 0.15:
        status = 401

    add_event(
        ip=ip,
        method=random.choice(["GET", "POST"]),
        path=path,
        status=status,
        seconds=i * 3,
    )


# 2. Simulated repeated login failures
for i in range(18):
    add_event(
        ip="10.0.0.90",
        method="POST",
        path="/login",
        status=401,
        seconds=600 + i * 3,
    )


# Successful login after the failures
add_event(
    ip="10.0.0.90",
    method="POST",
    path="/login",
    status=200,
    seconds=660,
)


# 3. Simulated SQL injection indicators
add_event(
    ip="10.0.0.91",
    method="GET",
    path="/search?q=%27%20OR%201%3D1--",
    status=400,
    seconds=800,
)

add_event(
    ip="10.0.0.91",
    method="GET",
    path="/search?q=UNION%20SELECT",
    status=400,
    seconds=805,
)


# 4. Simulated path traversal indicator
add_event(
    ip="10.0.0.92",
    method="GET",
    path="/files/../../etc/passwd",
    status=403,
    seconds=900,
)


# 5. Simulated sensitive-path discovery
suspicious_paths = [
    "/.env",
    "/admin",
    "/backup",
    "/config",
    "/phpmyadmin",
]

for i, path in enumerate(suspicious_paths):
    add_event(
        ip="10.0.0.93",
        method="GET",
        path=path,
        status=404,
        seconds=1000 + i * 2,
    )


# Sort events chronologically
events.sort(key=lambda row: row["timestamp"])


with OUTPUT.open(
    "w",
    newline="",
    encoding="utf-8",
) as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "timestamp",
            "ip",
            "method",
            "path",
            "status",
            "user_agent",
        ],
    )

    writer.writeheader()
    writer.writerows(events)


print(f"Generated {len(events)} events.")
print(f"Saved to: {OUTPUT}")