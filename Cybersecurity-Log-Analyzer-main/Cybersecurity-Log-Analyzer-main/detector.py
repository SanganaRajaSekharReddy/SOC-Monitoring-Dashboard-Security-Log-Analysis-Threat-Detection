import pandas as pd


REQUIRED_COLUMNS = [
    "timestamp",
    "ip_address",
    "username",
    "event_type",
    "status",
    "resource"
]


def calculate_risk(attempts):
    """
    Calculate a risk score and risk level based on
    the number of failed login attempts.
    """

    if attempts >= 8:
        return 100, "CRITICAL"

    elif attempts >= 5:
        return 75, "HIGH"

    elif attempts >= 3:
        return 50, "MEDIUM"

    else:
        return 25, "LOW"


def get_recommendation(risk_level):
    """
    Provide a recommended security action based
    on the calculated risk level.
    """

    recommendations = {
        "CRITICAL": (
            "Immediately investigate the source IP, "
            "review authentication logs, and consider "
            "temporarily blocking the IP address."
        ),

        "HIGH": (
            "Investigate the source IP and review "
            "authentication activity for suspicious behaviour."
        ),

        "MEDIUM": (
            "Monitor the source IP and review recent "
            "authentication activity."
        ),

        "LOW": (
            "Continue monitoring the source IP."
        )
    }

    return recommendations[risk_level]


def validate_logs(logs):
    """
    Validate that the uploaded CSV contains
    the required security log columns.
    """

    missing_columns = [
        column
        for column in REQUIRED_COLUMNS
        if column not in logs.columns
    ]

    if missing_columns:
        return False, missing_columns

    return True, []


def analyse_security_logs(file_path):
    """
    Load security logs, validate the data,
    detect suspicious login activity, and
    calculate security risk.
    """

    logs = pd.read_csv(file_path)

    valid, missing_columns = validate_logs(logs)

    if not valid:
        raise ValueError(
            "Missing required columns: "
            + ", ".join(missing_columns)
        )

    failed_logins = logs[
        (logs["event_type"] == "LOGIN") &
        (logs["status"] == "FAILED")
    ]

    failed_attempts_by_ip = (
        failed_logins["ip_address"]
        .value_counts()
    )

    results = []

    for ip, attempts in failed_attempts_by_ip.items():

        risk_score, risk_level = calculate_risk(attempts)

        recommendation = get_recommendation(
            risk_level
        )

        results.append({
            "ip_address": ip,
            "failed_attempts": attempts,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommendation": recommendation
        })

    return logs, pd.DataFrame(results)


if __name__ == "__main__":

    logs, security_results = analyse_security_logs(
        "data/security_logs.csv"
    )

    print("Security logs loaded successfully!")
    print(f"Number of events: {len(logs)}")

    print("\nSecurity Analysis:")
    print(security_results)