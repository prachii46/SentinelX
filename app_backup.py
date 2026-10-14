from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from detector import detect_request, detect_brute_force
from risk_engine import calculate_risk
from incident_report import create_incident_report, incident_to_json


st.set_page_config(
    page_title="SentinelX SOC",
    page_icon="🛡️",
    layout="wide",
)


st.title("🛡️ SentinelX")
st.subheader(
    "Security Event Detection and Incident Investigation"
)

st.caption(
    "Analyze application logs, identify suspicious "
    "patterns, and prioritize investigations."
)


DEFAULT_FILE = Path(
    "data/sample_logs/security_events.csv"
)


def load_data(uploaded_file):
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
    elif DEFAULT_FILE.exists():
        df = pd.read_csv(DEFAULT_FILE)
    else:
        return pd.DataFrame()

    required_columns = {
        "timestamp",
        "ip",
        "method",
        "path",
        "status",
    }

    missing = required_columns - set(df.columns)

    if missing:
        raise ValueError(
            "Missing required columns: "
            + ", ".join(sorted(missing))
        )

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
    )

    df["status"] = pd.to_numeric(
        df["status"],
        errors="coerce",
    )

    df = df.dropna(
        subset=[
            "timestamp",
            "ip",
            "method",
            "path",
            "status",
        ]
    ).copy()

    df["status"] = df["status"].astype(int)

    return df


uploaded_file = st.file_uploader(
    "Upload an application log CSV",
    type=["csv"],
)


try:
    df = load_data(uploaded_file)
except Exception as error:
    st.error(f"Unable to read the file: {error}")
    st.stop()


if df.empty:
    st.info(
        "Upload a CSV file or generate the sample dataset."
    )
    st.stop()


# Per-request detections
request_findings = []

for _, row in df.iterrows():
    findings = detect_request(row)

    for finding in findings:
        request_findings.append({
            "timestamp": row["timestamp"],
            "ip": row["ip"],
            "path": row["path"],
            "status": row["status"],
            **finding,
        })


findings_df = pd.DataFrame(request_findings)


# Correlated authentication findings
brute_force_findings = detect_brute_force(df)

incident_rows = []

for finding in brute_force_findings:
    incident_rows.append({
        "timestamp": None,
        "ip": finding["ip"],
        "path": "/login",
        "status": 401,
        "type": finding["type"],
        "severity": finding["severity"],
        "score": finding["score"],
        "reason": finding["evidence"],
    })


if not findings_df.empty:
    for _, row in findings_df.iterrows():
        incident_rows.append({
            "timestamp": row["timestamp"],
            "ip": row["ip"],
            "path": row["path"],
            "status": row["status"],
            "type": row["type"],
            "severity": row["severity"],
            "score": row["score"],
            "reason": row["reason"],
        })


incidents = pd.DataFrame(incident_rows)


# Summary metrics
total_events = len(df)

suspicious_events = (
    len(findings_df)
    if not findings_df.empty
    else 0
)

high_risk_incidents = (
    int(
        incidents["severity"].isin(
            ["HIGH", "CRITICAL"]
        ).sum()
    )
    if not incidents.empty
    else 0
)


col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Events Analyzed",
    total_events,
)

col2.metric(
    "Suspicious Findings",
    suspicious_events,
)

col3.metric(
    "High-Risk Findings",
    high_risk_incidents,
)

col4.metric(
    "Unique Source IPs",
    df["ip"].nunique(),
)


st.divider()


left, right = st.columns(2)


with left:
    st.markdown("### HTTP Status Codes")

    status_counts = (
        df["status"]
        .value_counts()
        .rename_axis("HTTP Status")
        .reset_index(name="Count")
    )

    fig = px.bar(
        status_counts,
        x="HTTP Status",
        y="Count",
        title="Distribution of HTTP Responses",
    )

    st.plotly_chart(
        fig,
        use_container_width=True,
    )


with right:
    st.markdown("### Findings by Type")

    if not incidents.empty:
        type_counts = (
            incidents["type"]
            .value_counts()
            .rename_axis("Finding Type")
            .reset_index(name="Count")
        )

        fig = px.bar(
            type_counts,
            x="Finding Type",
            y="Count",
            title="Detected Indicators",
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
        )
    else:
        st.success("No suspicious indicators detected.")


st.divider()


st.markdown("## Incident Explorer")


if incidents.empty:
    st.success(
        "No suspicious indicators were detected "
        "by the configured rules."
    )
else:
    selected_severity = st.multiselect(
        "Filter by severity",
        options=[
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        ],
        default=[
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        ],
    )

    filtered = incidents[
        incidents["severity"].isin(
            selected_severity
        )
    ].copy()

    st.dataframe(
        filtered,
        use_container_width=True,
        hide_index=True,
    )

    if not filtered.empty:
        selected_index = st.selectbox(
            "Choose a finding to investigate",
            options=filtered.index.tolist(),
            format_func=lambda index: (
                f"{filtered.loc[index, 'type']} | "
                f"{filtered.loc[index, 'ip']}"
            ),
        )

        selected = filtered.loc[selected_index]

        st.markdown("### Investigation Details")

        st.write(
            f"**Finding:** {selected['type']}"
        )

        st.write(
            f"**Source:** {selected['ip']}"
        )

        st.write(
            f"**Endpoint:** {selected['path']}"
        )

        st.write(
            f"**Severity:** {selected['severity']}"
        )

        st.write(
            f"**Evidence:** {selected['reason']}"
        )

        score = calculate_risk([
            {
                "type": selected["type"],
                "score": selected["score"],
            }
        ])

        st.progress(
            score["score"] / 100,
            text=(
                f"Illustrative Risk Score: "
                f"{score['score']}/100"
            ),
        )

        st.info(
            "This is a rule-based finding. "
            "Validate the surrounding events before "
            "concluding that a compromise occurred."
        )


with st.expander("View Raw Events"):
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
    )


st.caption(
    "SentinelX is a research prototype using "
    "synthetic or user-provided logs. "
    "It is not a replacement for a production SIEM."
)
st.subheader("AI Incident Analyst — Incident Report")


    selected_finding = incident_rows[selected_index]

    if st.button("Generate Incident JSON"):
        incident = create_incident_report(selected_finding)

        st.json(incident)

        st.download_button(
            label="Download Incident Report",
            data=incident_to_json(incident),
            file_name="sentinelx_incident.json",
            mime="application/json"
        )
else:
    st.info("No findings are available to investigate.")