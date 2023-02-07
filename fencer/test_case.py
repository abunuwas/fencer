from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

test_case_example = {
    "id": "asdf",
    "timestamp": "2023-02-01:09:00:00TZ:GMT",
    "category": "injection_attack",
    "target_test": "injection_attack__sql_injection__optional_query_parameters",
    "result": "fail",
    "severity": "medium",
    "description": {
        "http_method": "GET",
        "url": "http://localhost:5000/orders?limit=1' 1 OR 1",
        "base_url": "http://localhost:5000",
        "path": "/orders",
        "payload": None,
    }
}


class AttackStrategy(Enum):
    INJECTION = "injection"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SURFACE_ATTACKS = "surface_attacks"
    MASS_ASSIGNMENT = "mass_assignment"
    INSECURE_DESIGN = "insecure_design"


class TestResult(Enum):
    SUCCESS = "success"
    FAIL = "fail"
    UNDETERMINED = "undetermined"


class VulnerabilitySeverityLevel(Enum):
    ZERO = "zero"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class HTTPMethods(Enum):
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


@dataclass
class TestDescription:
    http_method: HTTPMethods
    url: str
    base_url: str
    path: str
    payload: Any = None


@dataclass
class TestCase:
    category: AttackStrategy
    test_target: str
    description: TestDescription

    # to be set by the object
    started: datetime | None = None
    ended: datetime | None = None

    # to be set after test run
    result: TestResult | None = None
    severity: VulnerabilitySeverityLevel | None = None

    def __post_init__(self):
        self.started = datetime.now(timezone.utc)

    def ended_test(self):
        self.ended = datetime.now(timezone.utc)

    def dict(self):
        return {
            "started": str(self.started),
            "ended": str(self.ended),
            "category": self.category.value,
            "target_test": self.test_target,
            "result": self.result.value,
            "severity": self.severity.value,
            "description": {
                "http_method": self.description.http_method.value,
                "url": self.description.url,
                "base_url": self.description.base_url,
                "path": self.description.path,
                "payload": self.description.payload,
            }
        }


@dataclass
class TestReporter:
    category: AttackStrategy
    number_tests: int
    failing_tests: int
    low_severity: int = 0
    medium_severity: int = 0
    high_severity: int = 0
