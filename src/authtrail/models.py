"""Core data types shared by parsers, detectors, correlation, and renderers."""

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SUCCESS = "success"
FAILURE = "failure"
OTHER = "other"
OUTCOMES = (SUCCESS, FAILURE, OTHER)

# Event types produced by the parsers.
LOGIN = "login"
SUDO = "sudo"
INVALID_USER = "invalid_user"
ACCOUNT_LOCKOUT = "account_lockout"
SPECIAL_PRIVILEGES = "special_privileges"


class Severity(enum.IntEnum):
    """Alert and story severity. Ordered so that comparisons work naturally."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: object) -> "Severity":
        """Parse a severity name such as ``"high"`` (case-insensitive)."""
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            raise ValueError(
                f"unknown severity {value!r}; expected one of: {', '.join(SEVERITY_NAMES)}"
            ) from None

    @property
    def label(self) -> str:
        """Lower-case name used in output (``"high"``)."""
        return self.name.lower()

    def __str__(self) -> str:
        return self.label


SEVERITY_NAMES = tuple(s.label for s in Severity)


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """A pointer to the exact input line (or JSON record) behind an event."""

    file: str
    line: int
    raw: str

    @property
    def location(self) -> str:
        """``file:line`` reference."""
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly representation."""
        return {"ref": self.location, "file": self.file, "line": self.line, "raw": self.raw}


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """One normalized authentication event, whatever the source format."""

    timestamp: datetime  # always timezone-aware UTC
    source_format: str  # linux | macos | windows
    event_type: str  # login | sudo | invalid_user | account_lockout | special_privileges
    outcome: str  # success | failure | other
    evidence: EvidenceRef
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    method: str | None = None  # password | publickey | network | remote_interactive | sudo ...
    detail: str | None = None

    @property
    def user_key(self) -> str | None:
        """Case-folded user name used for grouping (Windows names are case-insensitive)."""
        return self.user.casefold() if self.user else None


@dataclass(frozen=True, slots=True)
class Technique:
    """A MITRE ATT&CK technique reference."""

    id: str
    name: str

    def to_dict(self) -> dict[str, str]:
        """JSON-friendly representation."""
        return {"id": self.id, "name": self.name}


@dataclass(slots=True)
class Alert:
    """A single rule firing, with the numbers and evidence that explain it."""

    rule_id: str
    rule_type: str
    title: str
    severity: Severity
    techniques: tuple[Technique, ...]
    users: tuple[str, ...]
    ips: tuple[str, ...]
    hosts: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    count: int
    reason: str
    evidence: tuple[EvidenceRef, ...]
    evidence_total: int
    facts: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    @property
    def entity(self) -> str:
        """Short ``user=... ip=...`` description of who/what the alert is about."""
        parts = []
        if self.users:
            parts.append(
                "user=" + ",".join(self.users[:3]) + ("..." if len(self.users) > 3 else "")
            )
        if self.ips:
            parts.append("ip=" + ",".join(self.ips))
        return " ".join(parts) or "-"


@dataclass(slots=True)
class StoryStep:
    """One step of an attack story timeline (derived from one alert)."""

    time: datetime
    narrative: str
    techniques: tuple[Technique, ...]
    severity: Severity
    alert_id: str
    evidence: tuple[EvidenceRef, ...]
    evidence_total: int


@dataclass(slots=True)
class Story:
    """A group of correlated alerts narrated as a single incident."""

    id: str
    title: str
    severity: Severity
    base_severity: Severity
    escalation: str | None
    first_seen: datetime
    last_seen: datetime
    users: tuple[str, ...]
    ips: tuple[str, ...]
    hosts: tuple[str, ...]
    alert_ids: tuple[str, ...]
    techniques: tuple[Technique, ...]
    steps: tuple[StoryStep, ...]
    actions: tuple[str, ...]
