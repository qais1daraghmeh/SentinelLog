from src.sentinellog.parser import parse_line
from src.sentinellog.detector import detect_suspicious_activity


def test_detect_brute_force():

    lines = [
        "2026-09-13 18:00:01 | 192.168.1.50 | admin | FAILED",
        "2026-09-13 18:01:01 | 192.168.1.50 | admin | FAILED",
        "2026-09-13 18:02:01 | 192.168.1.50 | admin | FAILED",
        "2026-09-13 18:03:01 | 192.168.1.50 | root | FAILED",
        "2026-09-13 18:04:01 | 192.168.1.50 | test | FAILED",
        "2026-09-13 18:05:01 | 192.168.1.50 | guest | FAILED",
    ]

    events = [
        parse_line(line)
        for line in lines
    ]

    events = [
        event
        for event in events
        if event is not None
    ]

    suspicious = detect_suspicious_activity(events)

    assert len(suspicious) >= 1
    assert suspicious[0].ip_address == "192.168.1.50"
    assert suspicious[0].failed_attempts >= 5