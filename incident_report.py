import json
from datetime import datetime, timezone


def create_incident_report(finding):
    """
    Convert a detected security finding into a structured incident report.
    """

    incident = {
        "incident_id": f"INC-{datetime.now(timezone.utc):%Y%m%d%H%M%S}",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "incident_type": finding.get("type", "Unknown"),
        "severity": finding.get("severity", "UNKNOWN"),
        "source_ip": str(finding.get("ip", "Unknown")),
        "risk_score": finding.get("score", 0),
        "description": finding.get(
            "description",
            "Suspicious activity detected in security logs."
        ),
        "recommended_action": (
            "Review the associated events and verify whether the "
            "activity is legitimate before taking action."
        )
    }

    return incident


def incident_to_json(incident):
    """
    Convert an incident dictionary into readable JSON.
    """

    return json.dumps(incident, indent=4)


if __name__ == "__main__":
    # Sample finding for testing.
    sample_finding = {
        "type": "Possible Brute-Force Attack",
        "severity": "HIGH",
        "ip": "10.0.0.90",
        "score": 40,
        "description": "Multiple failed login attempts detected."
    }

    report = create_incident_report(sample_finding)

    print("INCIDENT REPORT")
    print("=" * 40)
    print(incident_to_json(report))