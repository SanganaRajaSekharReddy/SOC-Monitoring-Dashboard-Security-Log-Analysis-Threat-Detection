import streamlit as st
import matplotlib.pyplot as plt
import pandas as pd
import base64

from detector import analyse_security_logs


# --------------------------------------------------
# Page Configuration
# --------------------------------------------------

st.set_page_config(
    page_title="Cybersecurity Threat Detection Dashboard",
    page_icon=None,
    layout="wide"
)
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
BACKGROUND_IMAGE = BASE_DIR / "assets" / "cyber-background.jpg"

with open(BACKGROUND_IMAGE, "rb") as image_file:
    encoded_image = base64.b64encode(
        image_file.read()
    ).decode()

st.markdown(
    f"""
    <style>

    .stApp {{
        background-image:
            linear-gradient(
                rgba(5, 10, 20, 0.88),
                rgba(5, 10, 20, 0.94)
            ),
            url("data:image/jpeg;base64,{encoded_image}");

        background-size: cover;
        background-position: center;
        background-attachment: fixed;
        background-repeat: no-repeat;
    }}

    .main {{
        padding-top: 2rem;
    }}

    h1 {{
        font-size: 2.5rem;
        font-weight: 700;
        letter-spacing: 0.5px;
    }}

    h2, h3 {{
        font-weight: 600;
    }}

    [data-testid="stMetric"] {{
        background: rgba(20, 25, 35, 0.75);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 14px;
        padding: 20px;
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.25);
        backdrop-filter: blur(10px);
    }}

    [data-testid="stMetricValue"] {{
        font-size: 2rem;
        font-weight: 700;
    }}

    [data-testid="stFileUploader"] {{
        background: rgba(20, 25, 35, 0.70);
        border: 1px solid rgba(255, 255, 255, 0.10);
        border-radius: 14px;
        padding: 15px;
        backdrop-filter: blur(10px);
    }}

    [data-testid="stDataFrame"] {{
        border-radius: 12px;
        overflow: hidden;
    }}

    </style>
    """,
    unsafe_allow_html=True
)
# --------------------------------------------------
# Custom Styling
# --------------------------------------------------

st.markdown(
    """
    <style>

    .main {
        padding-top: 2rem;
    }

    h1 {
        font-size: 2.4rem;
        font-weight: 700;
    }

    h2 {
        margin-top: 1.5rem;
    }

    h3 {
        margin-top: 1rem;
    }

    [data-testid="stMetric"] {
        border: 1px solid rgba(128, 128, 128, 0.25);
        border-radius: 10px;
        padding: 15px;
    }

    [data-testid="stMetricValue"] {
        font-size: 2rem;
        font-weight: 700;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# --------------------------------------------------
# Dashboard Header
# --------------------------------------------------

st.title("Cybersecurity Threat Detection Dashboard")

st.caption(
    "Security log analysis, threat detection and risk assessment"
)

st.write(
    "Analyse authentication activity, identify suspicious behaviour "
    "and assess potential security risks."
)


# --------------------------------------------------
# Load and Analyse Security Logs
# --------------------------------------------------

uploaded_file = st.file_uploader(
    "Upload Security Log CSV",
    type=["csv"]
)

if uploaded_file is not None:

    logs, results = analyse_security_logs(
        uploaded_file
    )

else:

    logs, results = analyse_security_logs(
        "data/security_logs.csv"
    )


# --------------------------------------------------
# Calculate Dashboard Metrics
# --------------------------------------------------

total_events = len(logs)

failed_logins = len(
    logs[
        (logs["event_type"] == "LOGIN") &
        (logs["status"] == "FAILED")
    ]
)

threats_detected = len(
    results[
        results["risk_level"].isin(
            ["MEDIUM", "HIGH", "CRITICAL"]
        )
    ]
)

critical_threats = len(
    results[
        results["risk_level"] == "CRITICAL"
    ]
)


# --------------------------------------------------
# Security Overview
# --------------------------------------------------

st.divider()

st.subheader("Security Overview")

st.caption(
    "High-level summary of the security events analysed."
)

col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        "Total Events",
        total_events
    )


with col2:

    st.metric(
        "Failed Logins",
        failed_logins
    )


with col3:

    st.metric(
        "Threats Detected",
        threats_detected
    )


with col4:

    st.metric(
        "Critical Threats",
        critical_threats
    )


# --------------------------------------------------
# Charts
# --------------------------------------------------

st.divider()

st.subheader("Security Activity")

st.caption(
    "Visual analysis of authentication failures and detected risk levels."
)

left_column, right_column = st.columns(2)


# --------------------------------------------------
# Failed Login Activity
# --------------------------------------------------

with left_column:

    st.subheader("Failed Login Activity")

    st.caption(
        "Failed authentication attempts grouped by source IP address."
    )

    failed_logins_by_ip = (
        logs[
            (logs["event_type"] == "LOGIN") &
            (logs["status"] == "FAILED")
        ]
        ["ip_address"]
        .value_counts()
    )

    fig, ax = plt.subplots()

    failed_logins_by_ip.plot(
        kind="bar",
        ax=ax
    )

    ax.set_xlabel("IP Address")
    ax.set_ylabel("Failed Login Attempts")

    plt.xticks(rotation=45)

    st.pyplot(fig)


# --------------------------------------------------
# Risk Distribution
# --------------------------------------------------

with right_column:

    st.subheader("Risk Distribution")

    st.caption(
        "Detected risk levels across analysed IP addresses."
    )

    risk_distribution = results[
        "risk_level"
    ].value_counts()

    fig, ax = plt.subplots()

    risk_distribution.plot(
        kind="bar",
        ax=ax
    )

    ax.set_xlabel("Risk Level")
    ax.set_ylabel("Number of IP Addresses")

    plt.xticks(rotation=0)

    st.pyplot(fig)


# --------------------------------------------------
# Threat Analysis
# --------------------------------------------------

st.divider()

st.subheader("Threat Analysis")

st.caption(
    "Filter detected activity and review calculated security risk levels."
)


# --------------------------------------------------
# Risk Filter
# --------------------------------------------------

risk_options = [
    "ALL",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
]

selected_risk = st.selectbox(
    "Filter by risk level",
    risk_options
)


if selected_risk == "ALL":

    filtered_results = results

else:

    filtered_results = results[
        results["risk_level"] == selected_risk
    ]


# --------------------------------------------------
# Risk Table Styling
# --------------------------------------------------

def highlight_risk(row):

    risk = row["risk_level"]

    if risk == "CRITICAL":

        return [
            "background-color: #ffcccc"
            if column == "risk_level"
            else ""
            for column in row.index
        ]

    elif risk == "HIGH":

        return [
            "background-color: #ffe0cc"
            if column == "risk_level"
            else ""
            for column in row.index
        ]

    elif risk == "MEDIUM":

        return [
            "background-color: #fff3cd"
            if column == "risk_level"
            else ""
            for column in row.index
        ]

    elif risk == "LOW":

        return [
            "background-color: #e6f4ea"
            if column == "risk_level"
            else ""
            for column in row.index
        ]

    return [
        ""
        for column in row.index
    ]


st.dataframe(
    filtered_results.style.apply(
        highlight_risk,
        axis=1
    ),
    use_container_width=True
)


# --------------------------------------------------
# Security Event Timeline
# --------------------------------------------------

st.divider()

st.subheader("Security Event Timeline")

st.caption(
    "Chronological view of authentication and resource-access events."
)

timeline = logs.copy()

timeline["timestamp"] = pd.to_datetime(
    timeline["timestamp"],
    errors="coerce"
)

timeline = timeline.sort_values(
    "timestamp"
)


st.dataframe(
    timeline[
        [
            "timestamp",
            "ip_address",
            "username",
            "event_type",
            "status",
            "resource"
        ]
    ],
    use_container_width=True
)


# --------------------------------------------------
# Threat Investigation
# --------------------------------------------------

st.divider()

st.subheader("Threat Investigation")

st.caption(
    "Select an IP address to review its detected activity "
    "and recommended response."
)


if not results.empty:

    selected_ip = st.selectbox(
        "Select an IP address",
        results["ip_address"]
    )

    selected_threat = results[
        results["ip_address"] == selected_ip
    ].iloc[0]


    # --------------------------------------------------
    # Threat Metrics
    # --------------------------------------------------

    col1, col2, col3 = st.columns(3)


    with col1:

        st.metric(
            "Failed Attempts",
            selected_threat["failed_attempts"]
        )


    with col2:

        st.metric(
            "Risk Score",
            f'{selected_threat["risk_score"]}/100'
        )


    with col3:

        st.metric(
            "Risk Level",
            selected_threat["risk_level"]
        )


    # --------------------------------------------------
    # Recommended Action
    # --------------------------------------------------

    st.write("Recommended Action")

    st.info(
        selected_threat["recommendation"]
    )


else:

    st.success(
        "No suspicious login activity detected."
    )