def calculate_risk(findings):
    """
    Calculate an illustrative incident risk score.

    This is a demo heuristic, not a calibrated
    probability of compromise.
    """

    if not findings:
        return {
            "score": 0,
            "severity": "LOW",
        }

    # Use the strongest signal instead of blindly
    # adding every finding and double-counting events.
    strongest_score = max(
        int(item.get("score", 0))
        for item in findings
    )

    # Add a small amount for multiple distinct findings.
    distinct_types = {
        item.get("type")
        for item in findings
    }

    additional_score = max(
        0,
        len(distinct_types) - 1,
    ) * 10

    score = min(
        100,
        strongest_score + additional_score,
    )

    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "score": score,
        "severity": severity,
    }