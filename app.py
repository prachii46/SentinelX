import json
from pathlib import Path
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import streamlit as st

from detector import detect_request, detect_brute_force
from incident_report import create_incident_report, incident_to_json
from risk_engine import calculate_risk


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="SentinelX | Security Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0B1120;
        color: #F1F5F9;
    }

    .block-container {
        max-width: 1600px;
        padding-top: 1.8rem;
        padding-bottom: 2rem;
    }

    section[data-testid="stSidebar"] {
        background-color: #101827;
        border-right: 1px solid #263449;
    }

    section[data-testid="stSidebar"] * {
        color: #E2E8F0;
    }

    h1, h2, h3 {
        color: #F8FAFC !important;
    }

    div[data-testid="stMetric"] {
        background-color: #141D2F;
        border: 1px solid #263449;
        border-radius: 10px;
        padding: 18px;
    }

    div[data-testid="stMetricLabel"] {
        color: #94A3B8;
    }

    div[data-testid="stMetricValue"] {
        color: #F8FAFC;
    }

    .sx-eyebrow {
        color: #60A5FA;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 2px;
        margin-bottom: 8px;
    }

    .sx-subtitle {
        color: #94A3B8;
        font-size: 14px;
        margin-top: -5px;
    }

    .sx-panel {
        background-color: #141D2F;
        border: 1px solid #263449;
        border-radius: 10px;
        padding: 18px;
        margin-bottom: 12px;
    }

    .sx-muted {
        color: #94A3B8;
        font-size: 13px;
    }

    .stButton > button {
        background-color: #2563EB;
        color: white;
        border: 1px solid #3B82F6;
        border-radius: 7px;
        font-weight: 600;
    }

    .stButton > button:hover {
        background-color: #1D4ED8;
        color: white;
        border-color: #60A5FA;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid #263449;
        border-radius: 8px;
    }

    hr {
        border-color: #263449;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# CONSTANTS
# ============================================================

REQUIRED_COLUMNS = [
    "timestamp",
    "ip",
    "method",
    "path",
    "status",
]

SEVERITY_ORDER = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "UNKNOWN",
]

SEVERITY_COLORS = {
    "CRITICAL": "#EF4444",
    "HIGH": "#F97316",
    "MEDIUM": "#F59E0B",
    "LOW": "#22C55E",
    "UNKNOWN": "#94A3B8",
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_text(value, default="Unknown"):
    """Convert values to display-safe strings."""

    if value is None:
        return default

    try:
        if pd.isna(value):
            return default
    except (TypeError, ValueError):
        pass

    return str(value)


def normalize_severity(value):
    """Normalize severity labels."""

    severity = safe_text(value, "UNKNOWN").upper()

    if severity not in SEVERITY_ORDER:
        return "UNKNOWN"

    return severity


def load_security_logs(uploaded_file):
    """Load and validate a security log CSV."""

    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)

    else:
        sample_path = (
            Path(__file__).parent
            / "data"
            / "sample_logs"
            / "security_events.csv"
        )

        if not sample_path.exists():
            return None, (
                "Upload a CSV file to begin, or generate sample logs "
                "using python generate_logs.py."
            )

        df = pd.read_csv(sample_path)

    # Normalize column names.
    df.columns = [
        str(column).strip().lower()
        for column in df.columns
    ]

    missing = [
        column
        for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing:
        return None, (
            "The CSV is missing required columns: "
            + ", ".join(missing)
        )

    # Keep the columns required by the detection engine.
    df = df.copy()

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
        utc=True,
    )

    df["ip"] = df["ip"].fillna("Unknown").astype(str)
    df["method"] = df["method"].fillna("GET").astype(str).str.upper()
    df["path"] = df["path"].fillna("/").astype(str)

    df["status"] = pd.to_numeric(
        df["status"],
        errors="coerce",
    )

    # Remove unusable records.
    df = df.dropna(
        subset=["timestamp", "status"]
    ).copy()

    df["status"] = df["status"].astype(int)

    df = df.sort_values("timestamp").reset_index(drop=True)

    return df, None


def normalize_finding(finding, source_row=None):
    """
    Normalize a detection result into a consistent dictionary.

    Existing detector output is preserved, while missing context
    is populated from the associated log event when available.
    """

    result = dict(finding)

    if source_row is not None:
        for key in [
            "timestamp",
            "ip",
            "method",
            "path",
            "status",
        ]:
            if key not in result:
                result[key] = source_row.get(key, "Unknown")

    # Support common alternative field names.
    if "type" not in result:
        result["type"] = result.get(
            "finding_type",
            result.get("rule", "Suspicious Activity"),
        )

    if "ip" not in result:
        result["ip"] = result.get(
            "source_ip",
            "Unknown",
        )

    if "description" not in result:
        result["description"] = result.get(
            "message",
            "Suspicious activity matched a detection rule.",
        )

    result["type"] = safe_text(result["type"])
    result["ip"] = safe_text(result["ip"])
    result["severity"] = normalize_severity(
        result.get("severity", "UNKNOWN")
    )

    try:
        result["score"] = float(result.get("score", 0))
    except (ValueError, TypeError):
        result["score"] = 0.0

    return result


def analyze_logs(df):
    """Run the project's existing detection functions."""

    findings = []

    # Analyze each request.
    for _, row in df.iterrows():
        row_dict = row.to_dict()

        detected = detect_request(row_dict)

        if not detected:
            continue

        for finding in detected:
            normalized = normalize_finding(
                finding,
                source_row=row_dict,
            )

            findings.append(normalized)

    # Detect repeated failed login attempts.
    brute_force_findings = detect_brute_force(df)

    if brute_force_findings:
        for finding in brute_force_findings:
            normalized = normalize_finding(finding)
            findings.append(normalized)

    return findings


def build_findings_dataframe(findings):
    """Convert findings into a display-ready DataFrame."""

    columns = [
        "timestamp",
        "type",
        "severity",
        "score",
        "ip",
        "method",
        "path",
        "status",
        "description",
    ]

    if not findings:
        return pd.DataFrame(columns=columns)

    result = pd.DataFrame(findings)

    for column in columns:
        if column not in result.columns:
            result[column] = "Unknown"

    result["severity"] = result["severity"].apply(
        normalize_severity
    )

    result["score"] = pd.to_numeric(
        result["score"],
        errors="coerce",
    ).fillna(0)

    return result


def get_risk_details(finding):
    """
    Obtain a risk score using risk_engine.py when possible.

    The fallback uses the finding's existing score. Scores are
    heuristic indicators, not probabilities of an attack.
    """

    try:
        risk = calculate_risk([finding])

        if isinstance(risk, dict):
            score = risk.get(
                "score",
                risk.get("risk_score", finding.get("score", 0)),
            )

            severity = risk.get(
                "severity",
                finding.get("severity", "UNKNOWN"),
            )

        elif isinstance(risk, (int, float)):
            score = risk
            severity = finding.get("severity", "UNKNOWN")

        else:
            score = finding.get("score", 0)
            severity = finding.get("severity", "UNKNOWN")

        score = max(0, min(100, int(float(score))))

        return score, normalize_severity(severity)

    except Exception:
        try:
            score = max(
                0,
                min(100, int(float(finding.get("score", 0)))),
            )
        except (ValueError, TypeError):
            score = 0

        return score, normalize_severity(
            finding.get("severity", "UNKNOWN")
        )


def style_severity(value):
    """Apply color styling to severity labels."""

    color = SEVERITY_COLORS.get(
        normalize_severity(value),
        "#94A3B8",
    )

    return (
        f"color: {color}; "
        "font-weight: bold;"
    )


def make_chart_layout(fig, title):
    """Apply consistent styling to Plotly charts."""

    fig.update_layout(
        title=title,
        template="plotly_dark",
        paper_bgcolor="#141D2F",
        plot_bgcolor="#141D2F",
        font=dict(
            family="Arial",
            color="#E2E8F0",
        ),
        title_font_size=17,
        margin=dict(
            l=20,
            r=20,
            t=55,
            b=20,
        ),
        legend_title_text="",
    )

    return fig


def render_findings_table(findings_df):
    """Display findings with severity styling."""

    if findings_df.empty:
        st.success(
            "No suspicious indicators were detected "
            "in the current dataset."
        )
        return

    display_columns = [
        "timestamp",
        "type",
        "severity",
        "score",
        "ip",
        "method",
        "path",
        "status",
    ]

    display_df = findings_df[display_columns].copy()

    st.dataframe(
        display_df.style.map(
            style_severity,
            subset=["severity"],
        ),
        use_container_width=True,
        hide_index=True,
    )


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        """
        <div style="padding: 8px 0 14px 0;">
            <div style="font-size:28px; font-weight:800;">
                🛡️ SentinelX
            </div>
            <div style="
                color:#94A3B8;
                font-size:11px;
                letter-spacing:1.5px;
                margin-top:4px;
            ">
                SECURITY INTELLIGENCE
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "Overview",
            "Threat Analysis",
            "Incident Investigation",
            "Log Explorer",
            "Detection Rules",
        ],
        label_visibility="visible",
    )

    st.divider()

    st.markdown("### Data Source")

    uploaded_file = st.file_uploader(
        "Upload security logs",
        type=["csv"],
        help=(
            "Required columns: timestamp, ip, method, path, status"
        ),
    )

    st.caption(
        "Use synthetic logs or data you are authorized to analyze."
    )

    st.divider()

    st.markdown("### Detection Engine")

    st.markdown(
        """
        <span style="color:#34D399;">●</span>
        Rule-based detection
        """,
        unsafe_allow_html=True,
    )

    st.caption("Results depend on the loaded data and detection rules.")


# ============================================================
# LOAD DATA AND RUN DETECTION
# ============================================================

try:
    df, load_error = load_security_logs(uploaded_file)

except Exception as error:
    st.error(f"Unable to read the CSV file: {error}")
    st.stop()


# ============================================================
# PAGE HEADER
# ============================================================

st.markdown(
    """
    <div class="sx-eyebrow">
        SECURITY OPERATIONS CENTER
    </div>

    <h1 style="
        font-size:34px;
        font-weight:800;
        margin:0;
    ">
        SentinelX
    </h1>

    <div class="sx-subtitle">
        Security Log Intelligence & Incident Investigation
    </div>
    """,
    unsafe_allow_html=True,
)

st.write("")


if load_error:
    st.info(load_error)

    st.markdown(
        """
        ### Get started

        1. Upload a CSV containing security events.
        2. Include `timestamp`, `ip`, `method`, `path`, and `status`.
        3. SentinelX will analyze the records using its detection rules.
        """
    )

    st.stop()


if df is None or df.empty:
    st.warning(
        "The CSV contains no usable security events."
    )
    st.stop()


# ============================================================
# DETECTION
# ============================================================

try:
    findings = analyze_logs(df)

except Exception as error:
    st.error(
        f"Detection failed. Check detector.py and the CSV schema. "
        f"Details: {error}"
    )
    st.stop()


findings_df = build_findings_dataframe(findings)


# ============================================================
# OVERVIEW METRICS
# ============================================================

total_events = len(df)

total_findings = len(findings_df)

high_risk_count = int(
    findings_df["severity"].isin(
        ["CRITICAL", "HIGH"]
    ).sum()
)

unique_finding_ips = (
    findings_df.loc[
        findings_df["ip"] != "Unknown",
        "ip",
    ].nunique()
    if not findings_df.empty
    else 0
)

st.markdown(
    f"""
    <div class="sx-muted">
        ANALYSIS PERIOD:
        {df["timestamp"].min().strftime("%d %b %Y %H:%M UTC")}
        —
        {df["timestamp"].max().strftime("%d %b %Y %H:%M UTC")}
    </div>
    """,
    unsafe_allow_html=True,
)

st.write("")

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.metric(
        "EVENTS ANALYZED",
        f"{total_events:,}",
    )

with c2:
    st.metric(
        "DETECTED FINDINGS",
        f"{total_findings:,}",
    )

with c3:
    st.metric(
        "HIGH / CRITICAL",
        f"{high_risk_count:,}",
    )

with c4:
    st.metric(
        "SOURCE IPs WITH FINDINGS",
        f"{unique_finding_ips:,}",
    )

st.caption(
    "Findings are rule-based indicators. They do not independently "
    "confirm that a successful attack occurred."
)

st.divider()


# ============================================================
# OVERVIEW PAGE
# ============================================================

if page == "Overview":

    st.subheader("Security Overview")

    left, right = st.columns([1.5, 1])

    with left:

        timeline = (
            df.set_index("timestamp")
            .resample("5min")
            .size()
            .reset_index(name="events")
        )

        fig = px.line(
            timeline,
            x="timestamp",
            y="events",
            markers=True,
        )

        fig.update_traces(
            line=dict(color="#60A5FA", width=2),
            marker=dict(size=5),
        )

        make_chart_layout(
            fig,
            "Security Event Timeline",
        )

        fig.update_xaxes(title="Time")
        fig.update_yaxes(title="Events")

        st.plotly_chart(
            fig,
            use_container_width=True,
        )

    with right:

        if findings_df.empty:

            st.info("No findings are available to chart.")

        else:

            severity_counts = (
                findings_df["severity"]
                .value_counts()
                .reindex(SEVERITY_ORDER, fill_value=0)
                .reset_index()
            )

            severity_counts.columns = [
                "severity",
                "count",
            ]

            severity_counts = severity_counts[
                severity_counts["count"] > 0
            ]

            fig = px.pie(
                severity_counts,
                names="severity",
                values="count",
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
                hole=0.65,
            )

            make_chart_layout(
                fig,
                "Finding Severity",
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
            )

    st.subheader("Recent Security Findings")

    if not findings_df.empty:

        recent = findings_df.copy()

        recent["timestamp"] = pd.to_datetime(
            recent["timestamp"],
            errors="coerce",
            utc=True,
        )

        recent = recent.sort_values(
            "timestamp",
            ascending=False,
        ).head(10)

        render_findings_table(recent)

    else:

        st.success(
            "No suspicious indicators were found in the loaded data."
        )


# ============================================================
# THREAT ANALYSIS PAGE
# ============================================================

elif page == "Threat Analysis":

    st.subheader("Threat Analysis")

    if findings_df.empty:

        st.success("No suspicious indicators detected.")

    else:

        left, right = st.columns(2)

        with left:

            type_counts = (
                findings_df["type"]
                .value_counts()
                .reset_index()
            )

            type_counts.columns = [
                "finding_type",
                "count",
            ]

            fig = px.bar(
                type_counts,
                x="count",
                y="finding_type",
                orientation="h",
                text="count",
            )

            fig.update_traces(
                marker_color="#60A5FA",
            )

            make_chart_layout(
                fig,
                "Findings by Detection Type",
            )

            fig.update_yaxes(
                categoryorder="total ascending",
                title="",
            )

            fig.update_xaxes(title="Findings")

            st.plotly_chart(
                fig,
                use_container_width=True,
            )

        with right:

            ip_counts = (
                findings_df[
                    findings_df["ip"] != "Unknown"
                ]["ip"]
                .value_counts()
                .head(10)
                .reset_index()
            )

            ip_counts.columns = [
                "source_ip",
                "findings",
            ]

            if not ip_counts.empty:

                fig = px.bar(
                    ip_counts,
                    x="source_ip",
                    y="findings",
                    text="findings",
                )

                fig.update_traces(
                    marker_color="#F97316",
                )

                make_chart_layout(
                    fig,
                    "Sources Associated with Findings",
                )

                fig.update_xaxes(title="Source IP")
                fig.update_yaxes(title="Findings")

                st.plotly_chart(
                    fig,
                    use_container_width=True,
                )

            else:

                st.info("No source IP information is available.")

        st.subheader("Filter Findings")

        severity_options = sorted(
            findings_df["severity"].unique().tolist()
        )

        selected_severities = st.multiselect(
            "Severity",
            severity_options,
            default=severity_options,
        )

        filtered = findings_df[
            findings_df["severity"].isin(
                selected_severities
            )
        ]

        render_findings_table(filtered)


# ============================================================
# INCIDENT INVESTIGATION PAGE
# ============================================================

elif page == "Incident Investigation":

    st.subheader("Incident Investigation")

    if findings_df.empty:

        st.info(
            "No findings are available to investigate. "
            "Upload logs containing events that match your detection rules."
        )

    else:

        # This list contains actual dictionaries, not DataFrame objects.
        finding_records = findings_df.to_dict(
            orient="records"
        )

        # Define selected_finding from the user's selection.
        selected_index = st.selectbox(
            "Select a finding to investigate",
            options=list(range(len(finding_records))),
            format_func=lambda index: (
                f'{finding_records[index].get("severity", "UNKNOWN")} | '
                f'{finding_records[index].get("type", "Unknown")} | '
                f'{finding_records[index].get("ip", "Unknown IP")} | '
                f'{finding_records[index].get("path", "Unknown path")}'
            ),
        )

        selected_finding = finding_records[
            selected_index
        ]

        # The selected finding is now defined.
        risk_score, risk_severity = get_risk_details(
            selected_finding
        )

        st.divider()

        st.markdown(
            f"### {selected_finding.get('type', 'Security Finding')}"
        )

        color = SEVERITY_COLORS.get(
            risk_severity,
            "#94A3B8",
        )

        st.markdown(
            f"""
            <div style="
                display:inline-block;
                background-color:#141D2F;
                border:1px solid {color};
                border-radius:8px;
                padding:10px 16px;
                margin-bottom:14px;
            ">
                <span style="
                    color:{color};
                    font-weight:800;
                ">
                    {risk_severity}
                </span>
                <span style="color:#94A3B8;">
                    &nbsp; | &nbsp; Heuristic Risk Score:
                </span>
                <span style="
                    color:#F8FAFC;
                    font-weight:800;
                ">
                    {risk_score}/100
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_a, col_b = st.columns(2)

        with col_a:

            st.markdown("#### Event Details")

            st.write(
                "**Source IP:**",
                safe_text(selected_finding.get("ip")),
            )

            st.write(
                "**Request method:**",
                safe_text(selected_finding.get("method")),
            )

            st.write(
                "**Requested path:**",
                safe_text(selected_finding.get("path")),
            )

            st.write(
                "**HTTP status:**",
                safe_text(selected_finding.get("status")),
            )

            st.write(
                "**Timestamp:**",
                safe_text(selected_finding.get("timestamp")),
            )

        with col_b:

            st.markdown("#### Detection Evidence")

            st.write(
                safe_text(
                    selected_finding.get("description"),
                    "No description was supplied by the detection rule.",
                )
            )

            st.caption(
                "The severity and score are heuristic indicators. "
                "Investigate the supporting events before concluding "
                "that an attack occurred."
            )

        st.divider()

        st.markdown("#### Structured Incident Report")

        if st.button(
            "Generate Incident JSON",
            type="primary",
            key="generate_incident_json",
        ):

            try:

                report_finding = dict(
                    selected_finding
                )

                # Ensure report fields use the expected names.
                report_finding["type"] = safe_text(
                    report_finding.get("type")
                )

                report_finding["severity"] = risk_severity
                report_finding["score"] = risk_score

                report_finding["ip"] = safe_text(
                    report_finding.get("ip")
                )

                report_finding["description"] = safe_text(
                    report_finding.get("description")
                )

                incident = create_incident_report(
                    report_finding
                )

                incident_json = incident_to_json(
                    incident
                )

                # Store the generated report for download.
                st.session_state["sentinelx_incident_json"] = (
                    incident_json
                )

                st.session_state["sentinelx_incident_id"] = (
                    selected_index
                )

            except Exception as error:

                st.error(
                    f"Could not generate the incident report: {error}"
                )

        # Display the report after the button has been clicked.
        if (
            "sentinelx_incident_json" in st.session_state
            and st.session_state.get(
                "sentinelx_incident_id"
            ) == selected_index
        ):

            incident_json = st.session_state[
                "sentinelx_incident_json"
            ]

            try:
                incident_object = json.loads(
                    incident_json
                )

                st.json(incident_object)

            except (ValueError, TypeError):

                st.code(
                    incident_json,
                    language="json",
                )

            st.download_button(
                label="Download Incident Report",
                data=incident_json,
                file_name="sentinelx_incident.json",
                mime="application/json",
                key="download_incident_json",
            )


# ============================================================
# LOG EXPLORER PAGE
# ============================================================

elif page == "Log Explorer":

    st.subheader("Security Log Explorer")

    search_term = st.text_input(
        "Search logs",
        placeholder="Search an IP address, path, method, or status...",
    )

    filtered_logs = df.copy()

    if search_term.strip():

        term = search_term.strip().lower()

        searchable = (
            filtered_logs.astype(str)
            .apply(
                lambda column: column.str.lower().str.contains(
                    term,
                    regex=False,
                    na=False,
                )
            )
            .any(axis=1)
        )

        filtered_logs = filtered_logs[
            searchable
        ]

    col_a, col_b = st.columns(2)

    with col_a:

        methods = sorted(
            filtered_logs["method"].unique().tolist()
        )

        selected_methods = st.multiselect(
            "HTTP Method",
            methods,
            default=methods,
        )

    with col_b:

        statuses = sorted(
            filtered_logs["status"].unique().tolist()
        )

        selected_statuses = st.multiselect(
            "HTTP Status",
            statuses,
            default=statuses,
        )

    filtered_logs = filtered_logs[
        filtered_logs["method"].isin(selected_methods)
        & filtered_logs["status"].isin(selected_statuses)
    ]

    st.caption(
        f"Showing {len(filtered_logs):,} of {len(df):,} events."
    )

    st.dataframe(
        filtered_logs,
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "Export Filtered Logs",
        data=filtered_logs.to_csv(index=False),
        file_name="sentinelx_filtered_logs.csv",
        mime="text/csv",
    )


# ============================================================
# DETECTION RULES PAGE
# ============================================================

elif page == "Detection Rules":

    st.subheader("Detection Rules")

    st.markdown(
        """
        These rules identify suspicious patterns in application logs.
        They are indicators for investigation, not proof of malicious activity.
        """
    )

    rules = [
        {
            "Rule": "Possible SQL Injection",
            "Purpose": (
                "Looks for SQL-like expressions in request paths "
                "or query strings."
            ),
            "Limitations": (
                "Legitimate search terms can resemble suspicious input."
            ),
        },
        {
            "Rule": "Possible Path Traversal",
            "Purpose": (
                "Looks for directory traversal patterns such as ../."
            ),
            "Limitations": (
                "Encoding and application-specific routing can affect results."
            ),
        },
        {
            "Rule": "Sensitive-Path Probing",
            "Purpose": (
                "Identifies requests for paths such as /.env, /backup, "
                "/config, and /phpmyadmin."
            ),
            "Limitations": (
                "A request to a sensitive path does not prove that "
                "information was exposed."
            ),
        },
        {
            "Rule": "Possible Brute-Force Activity",
            "Purpose": (
                "Groups failed login requests by source IP within "
                "a time window."
            ),
            "Limitations": (
                "Shared networks, automated tests, or legitimate users "
                "can generate repeated failures."
            ),
        },
    ]

    st.dataframe(
        pd.DataFrame(rules),
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

    st.markdown("#### Current Dataset")

    st.write(f"Events analyzed: {len(df):,}")
    st.write(f"Findings produced: {len(findings_df):,}")

    st.info(
        "Detection thresholds and risk scores should be validated "
        "against representative logs before operational use."
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.markdown(
    """
    <div style="
        text-align:center;
        color:#64748B;
        font-size:12px;
        padding:10px 0;
    ">
        SENTINELX · SECURITY LOG INTELLIGENCE
        <br>
        Educational prototype · Rule-based detection
    </div>
    """,
    unsafe_allow_html=True,
)