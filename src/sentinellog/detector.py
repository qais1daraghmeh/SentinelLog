from collections import defaultdict
from datetime import timedelta

from .models import SuspiciousActivity
from .parser import LogEvent


FAILED_ATTEMPT_THRESHOLD = 5
HIGH_RISK_THRESHOLD = 20
MULTIPLE_USERNAME_THRESHOLD = 3
TIME_WINDOW_MINUTES = 10


def calculate_risk_score(
    failed_attempts: int,
    unique_usernames: int,
) -> int:
    score = 0

    if failed_attempts >= HIGH_RISK_THRESHOLD:
        score += 60
    elif failed_attempts >= FAILED_ATTEMPT_THRESHOLD:
        score += 35

    if unique_usernames >= MULTIPLE_USERNAME_THRESHOLD:
        score += 25

    if failed_attempts >= 50:
        score += 15

    return min(score, 100)


def get_severity(risk_score: int) -> str:
    if risk_score >= 70:
        return "HIGH"

    if risk_score >= 40:
        return "MEDIUM"

    return "LOW"


def detect_suspicious_activity(
    events: list[LogEvent],
) -> list[SuspiciousActivity]:

    failed_by_ip = defaultdict(list)

    for event in events:
        if event.status == "FAILED":
            failed_by_ip[event.ip_address].append(event)

    suspicious = []

    for ip_address, failed_events in failed_by_ip.items():

        failed_events.sort(
            key=lambda event: event.timestamp
            if event.timestamp
            else 0
        )

        max_failed_attempts = 0
        max_unique_usernames = 0

        for index, current_event in enumerate(failed_events):

            if current_event.timestamp is None:
                continue

            window_start = current_event.timestamp
            window_end = window_start + timedelta(
                minutes=TIME_WINDOW_MINUTES
            )

            window_events = [
                event
                for event in failed_events[index:]
                if event.timestamp
                and event.timestamp <= window_end
            ]

            failed_attempts = len(window_events)

            unique_usernames = len(
                {
                    event.username
                    for event in window_events
                }
            )

            max_failed_attempts = max(
                max_failed_attempts,
                failed_attempts
            )

            max_unique_usernames = max(
                max_unique_usernames,
                unique_usernames
            )

        if not failed_events or max_failed_attempts == 0:
            max_failed_attempts = len(failed_events)

            max_unique_usernames = len(
                {
                    event.username
                    for event in failed_events
                }
            )

        risk_score = calculate_risk_score(
            max_failed_attempts,
            max_unique_usernames
        )

        severity = get_severity(risk_score)

        if risk_score >= 40:
            reason_parts = []

            if max_failed_attempts >= FAILED_ATTEMPT_THRESHOLD:
                reason_parts.append(
                    "Multiple failed login attempts"
                )

            if max_unique_usernames >= MULTIPLE_USERNAME_THRESHOLD:
                reason_parts.append(
                    "Multiple usernames targeted"
                )

            reason = " and ".join(reason_parts)

            suspicious.append(
                SuspiciousActivity(
                    ip_address=ip_address,
                    reason=reason,
                    failed_attempts=max_failed_attempts,
                    unique_usernames=max_unique_usernames,
                    risk_score=risk_score,
                    severity=severity,
                )
            )

    suspicious.sort(
        key=lambda activity: activity.risk_score,
        reverse=True
    )

    return suspicious