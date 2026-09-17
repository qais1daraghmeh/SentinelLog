from collections import Counter

from .parser import LogEvent


def analyze_events(events: list[LogEvent]) -> dict:
    """
    Generate general statistics from parsed authentication events.
    """

    total_events = len(events)

    failed_logins = sum(
        1 for event in events
        if event.status == "FAILED"
    )

    successful_logins = sum(
        1 for event in events
        if event.status == "SUCCESS"
    )

    unique_ips = len({
        event.ip_address
        for event in events
    })

    unique_usernames = len({
        event.username
        for event in events
    })

    failed_by_ip = Counter(
        event.ip_address
        for event in events
        if event.status == "FAILED"
    )

    return {
        "total_events": total_events,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "unique_ips": unique_ips,
        "unique_usernames": unique_usernames,
        "failed_by_ip": dict(failed_by_ip),
    }