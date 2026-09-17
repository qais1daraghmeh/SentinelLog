from .models import SuspiciousActivity


def generate_report(
    statistics: dict,
    suspicious_activities: list[SuspiciousActivity],
    log_file: str,
) -> str:

    lines = []

    lines.append("=" * 50)
    lines.append("        SENTINELLOG SECURITY REPORT")
    lines.append("=" * 50)

    lines.append(f"Log File: {log_file}")
    lines.append("")

    lines.append("GENERAL STATISTICS")
    lines.append("-" * 50)

    lines.append(
        f"Total Events: {statistics['total_events']}"
    )

    lines.append(
        f"Failed Logins: {statistics['failed_logins']}"
    )

    lines.append(
        f"Successful Logins: {statistics['successful_logins']}"
    )

    lines.append(
        f"Unique IPs: {statistics['unique_ips']}"
    )

    lines.append(
        f"Unique Usernames: {statistics['unique_usernames']}"
    )

    lines.append(
        f"Suspicious IPs: {len(suspicious_activities)}"
    )

    lines.append("")

    lines.append("SUSPICIOUS ACTIVITY")
    lines.append("-" * 50)

    if not suspicious_activities:
        lines.append("No suspicious activity detected.")

    for activity in suspicious_activities:

        lines.append(
            f"[{activity.severity}] Suspicious Activity"
        )

        lines.append(
            f"IP Address: {activity.ip_address}"
        )

        lines.append(
            f"Reason: {activity.reason}"
        )

        lines.append(
            f"Failed Attempts: {activity.failed_attempts}"
        )

        lines.append(
            f"Unique Usernames: {activity.unique_usernames}"
        )

        lines.append(
            f"Risk Score: {activity.risk_score}/100"
        )

        lines.append("")

    lines.append("=" * 50)

    return "\n".join(lines)


def save_report(report: str, output_file: str) -> None:

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(report)