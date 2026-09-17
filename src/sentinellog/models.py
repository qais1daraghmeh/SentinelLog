from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class SecurityEvent:
    timestamp: Optional[datetime]
    ip_address: str
    username: str
    status: str


@dataclass
class SuspiciousActivity:
    ip_address: str
    reason: str
    failed_attempts: int
    unique_usernames: int
    risk_score: int
    severity: str