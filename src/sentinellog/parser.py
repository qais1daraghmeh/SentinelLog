from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class LogEvent:
    timestamp: Optional[datetime]
    ip_address: str
    username: str
    status: str
    raw_line: str


def parse_line(line: str) -> Optional[LogEvent]:
    """
    Parse a simple authentication log line.

    Expected format:

    2026-09-11 18:30:10 | 192.168.1.50 | admin | FAILED
    """

    line = line.strip()

    if not line:
        return None

    parts = [part.strip() for part in line.split("|")]

    if len(parts) != 4:
        return None

    timestamp_text, ip_address, username, status = parts

    try:
        timestamp = datetime.strptime(
            timestamp_text,
            "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        timestamp = None

    status = status.upper()

    if status not in {"FAILED", "SUCCESS"}:
        return None

    return LogEvent(
        timestamp=timestamp,
        ip_address=ip_address,
        username=username,
        status=status,
        raw_line=line,
    )


def parse_file(file_path: str) -> list[LogEvent]:
    """
    Read a log file and return successfully parsed events.
    """

    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            event = parse_line(line)

            if event is not None:
                events.append(event)

    return events