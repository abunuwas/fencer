import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import requests

from .main import APISpec

test_case = {
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


class TestReporter:
    def __init__(self):
        pass


class InjectionTestCaseRunner:
    def __init__(self, test_case: TestCase):
        self.test_case = test_case
        self.response = None

    def run(self):
        callable_ = getattr(requests, self.test_case.description.http_method.value.lower())
        self.response = callable_(
            self.test_case.description.url, json=self.test_case.description.payload
        )
        self.resolve_test_result()

    def resolve_test_result(self):
        """
        In this case, it's difficult to assess the severity of the failure without looking
        at the backend logs. We'll assume that:
        - Failure to response indicates major outage caused by the request
        - 500 status code indicates potential high severity and potential for leaking traceback
        Everything else is severity Zero.
        Until we can develop better heuristics for response analysis, this is the best we can do.
        """
        # If the server fails to respond, we assume we broke it
        if self.response is None:
            self.test_case.result = TestResult.FAIL
            self.test_case.severity = VulnerabilitySeverityLevel.HIGH
        # If the request causes a server error, it likely broke it
        elif self.response.status_code >= 500:
            self.test_case.result = TestResult.FAIL
            self.test_case.severity = VulnerabilitySeverityLevel.HIGH
        # Any status code below 500 indicates the response was correctly processed
        # (i.e. correctly accepted or rejected)
        else:
            self.test_case.result = TestResult.SUCCESS
            self.test_case.severity = VulnerabilitySeverityLevel.ZERO
        self.test_case.ended_test()


class TestRunner:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
        self.injection_tests = 0

    def run_sql_injection_attacks(self):
        failing_tests: list[TestCase] = []

        for endpoint in self.api_spec.endpoints:
            for url in endpoint.get_urls():
                self.injection_tests += 1
                test_case = InjectionTestCaseRunner(
                    test_case=TestCase(
                        category=AttackStrategy.INJECTION,
                        test_target="sql_injection__optional_query_parameters",
                        description=TestDescription(
                            http_method=getattr(HTTPMethods, endpoint.method.upper()),
                            url=url, base_url=endpoint.base_url, path=endpoint.path.path,
                        )
                    )
                )
                test_case.run()
                if test_case.test_case.result == TestResult.FAIL:
                    failing_tests.append(test_case.test_case)
                if endpoint.has_request_payload():
                    self.injection_tests += 1
                    test_case = InjectionTestCaseRunner(
                        test_case=TestCase(
                            category=AttackStrategy.INJECTION,
                            test_target="sql_injection__optional_query_parameters",
                            description=TestDescription(
                                http_method=getattr(HTTPMethods, endpoint.method.upper()),
                                url=url, base_url=endpoint.base_url, path=endpoint.path.path,
                                payload=endpoint.generate_safe_request_payload()
                            )
                        )
                    )
                    test_case.run()
                    if test_case.test_case.result == TestResult.FAIL:
                        failing_tests.append(test_case.test_case)
                    self.injection_tests += 1
                    test_case = InjectionTestCaseRunner(
                        test_case=TestCase(
                            category=AttackStrategy.INJECTION,
                            test_target="sql_injection__optional_query_parameters",
                            description=TestDescription(
                                http_method=getattr(HTTPMethods, endpoint.method.upper()),
                                url=url, base_url=endpoint.base_url, path=endpoint.path.path,
                                payload=endpoint.generate_unsafe_request_payload()
                            )
                        )
                    )
                    test_case.run()
                    if test_case.test_case.result == TestResult.FAIL:
                        failing_tests.append(test_case.test_case)
        failed_tests_file = Path('.fencer/injection_attacks.json')
        failed_tests_file.write_text(
            json.dumps([test.dict() for test in failing_tests], indent=4)
        )

    def run_unauthorized_access_attacks(self):
        pass

    def run_surface_attacks(self):
        pass

    def run_mass_assignment_attacks(self):
        pass

    def run_insecure_design_attacks(self):
        pass
