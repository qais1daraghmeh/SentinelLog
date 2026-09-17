from src.sentinellog.parser import parse_line


def test_parse_success():

    line = (
        "2026-09-13 18:00:01 | "
        "192.168.1.10 | admin | SUCCESS"
    )

    event = parse_line(line)

    assert event is not None
    assert event.ip_address == "192.168.1.10"
    assert event.username == "admin"
    assert event.status == "SUCCESS"


def test_parse_failed_login():

    line = (
        "2026-09-13 18:02:01 | "
        "192.168.1.50 | admin | FAILED"
    )

    event = parse_line(line)

    assert event is not None
    assert event.status == "FAILED"


def test_invalid_line():

    line = "invalid log entry"

    event = parse_line(line)

    assert event is None