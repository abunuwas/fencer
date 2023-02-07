import click
import requests

from .main import APISpec
from .test_case import AttackStrategy, TestDescription, HTTPMethods, TestCase, TestResult, \
    VulnerabilitySeverityLevel, TestReporter


class UnauthorizedAccessTestCaseRunner:
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
        """
        # If the server fails to respond, endpoint is protected and there's no possibility for exploit,
        # but we can break the server, so we give it a medium severity
        if self.response is None:
            self.test_case.result = TestResult.FAIL
            self.test_case.severity = VulnerabilitySeverityLevel.MEDIUM
            # If response status code is 401 or 403, it's all good
        if self.response.status_code in [401, 403]:
            self.test_case.result = TestResult.SUCCESS
            self.test_case.severity = VulnerabilitySeverityLevel.ZERO
        # If the response status code is in the 2xx status code group, it's pretty bad
        elif self.response.status_code >= 200 < 300:
            self.test_case.result = TestResult.FAIL
            self.test_case.severity = VulnerabilitySeverityLevel.HIGH
        # In all other cases, the response isn't successful, but it's still
        # doing some processing, and that can be leveraged by hackers, so we
        # assign it a high severity
        else:
            self.test_case.result = TestResult.FAIL
            self.test_case.severity = VulnerabilitySeverityLevel.HIGH
        self.test_case.ended_test()


class TestAuthEndpoints:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
        self.auth_tests = 0
        self.reports: list[TestReporter] = []

    def test_authorized_endpoints(self):
        failing_tests = []
        for endpoint in self.api_spec.authorized_endpoints:
            click.echo(f"    {endpoint.method.upper()} {endpoint.base_url + endpoint.path.path}", nl=False)
            self.auth_tests += 1
            test_case = UnauthorizedAccessTestCaseRunner(
                test_case=TestCase(
                    category=AttackStrategy.UNAUTHORIZED_ACCESS,
                    test_target="unauthorized_access__access_authorized_endpoints_without_token",
                    description=TestDescription(
                        http_method=getattr(HTTPMethods, endpoint.method.upper()),
                        url=endpoint.safe_url, base_url=endpoint.base_url, path=endpoint.path.path,
                        payload=(
                            endpoint.generate_safe_request_payload()
                            if endpoint.has_request_payload() else None
                        ),
                    )
                )
            )
            test_case.run()
            if test_case.test_case.result == TestResult.FAIL:
                failing_tests.append(test_case.test_case)
                click.echo(" 🚨")
            else:
                click.echo(" ✅")
        return failing_tests
