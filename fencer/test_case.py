from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

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

class Solutions(Enum):
    SQL_INJECTION = "https://portswigger.net/web-security/sql-injection"
    UNAUTHORIZED_ACCESS = "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
    BOLA = "https://owasp.org/API-Security/editions/2019/en/0xa1-broken-object-level-authorization/#how-to-prevent"
    BFLA = "https://owasp.org/API-Security/editions/2019/en/0xa5-broken-function-level-authorization/#how-to-prevent"
    XSS_INJECTION = "https://portswigger.net/web-security/cross-site-scripting"
    MASS_ASSIGNMENT = "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"
    @classmethod
    def sol_arr(cls):
        return [cls.SQL_INJECTION, cls.XSS_INJECTION, cls.UNAUTHORIZED_ACCESS, cls.BOLA, cls.BFLA, cls.MASS_ASSIGNMENT]

class AttackStrategy(Enum):
    SQL_INJECTION = "sql_injection"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SURFACE_ATTACKS = "surface_attacks"
    MASS_ASSIGNMENT = "mass_assignment"
    INSECURE_DESIGN = "insecure_design"
    XSS_INJECTION = "xss_injection"
    BOLA = "BOLA"
    BFLA = "BFLA"


class TestResult(Enum):
    SUCCESS = "success"
    FAIL = "fail"
    UNDETERMINED = "undetermined"
    ERROR = "error"


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
    started: Optional[datetime] = None
    ended: Optional[datetime] = None

    # to be set after test run
    result: Optional[TestResult] = None
    severity: Optional[VulnerabilitySeverityLevel] = None

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
