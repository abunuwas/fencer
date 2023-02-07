import json
from dataclasses import dataclass
from pathlib import Path

import click
import requests

from .authorized_endpoints import TestAuthEndpoints
from .main import APISpec
from .test_case import AttackStrategy, TestCase, TestResult, VulnerabilitySeverityLevel, TestDescription, HTTPMethods, \
    TestReporter


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
        self.reports = []

    def run_sql_injection_through_query_parameters(self):
        failing_tests = []
        for endpoint in self.api_spec.endpoints:
            endpoint_failing_tests = []
            click.echo(f"    {endpoint.method.upper()} {endpoint.base_url + endpoint.path.path}", nl=False)
            for url in endpoint.get_urls_with_unsafe_query_params():
                self.injection_tests += 1
                test_case = InjectionTestCaseRunner(
                    test_case=TestCase(
                        category=AttackStrategy.INJECTION,
                        test_target="sql_injection__optional_query_parameters",
                        description=TestDescription(
                            http_method=getattr(HTTPMethods, endpoint.method.upper()),
                            url=url, base_url=endpoint.base_url, path=endpoint.path.path,
                            payload=endpoint.generate_safe_request_payload() if endpoint.has_request_payload() else None,
                        )
                    )
                )
                test_case.run()
                if test_case.test_case.result == TestResult.FAIL:
                    endpoint_failing_tests.append(test_case.test_case)
            if len(endpoint_failing_tests) > 0:
                failing_tests.extend(endpoint_failing_tests)
                click.echo(" 🚨")
            else:
                click.echo(" ✅")
        return failing_tests

    def run_sql_injection_through_path_parameters(self):
        failing_tests = []
        for endpoint in self.api_spec.endpoints:
            if not endpoint.has_path_params():
                continue
            endpoint_failing_tests = []
            click.echo(f"    {endpoint.method.upper()} {endpoint.base_url + endpoint.path.path}", nl=False)
            for url in endpoint.get_urls_with_unsafe_path_params():
                self.injection_tests += 1
                test_case = InjectionTestCaseRunner(
                    test_case=TestCase(
                        category=AttackStrategy.INJECTION,
                        test_target="sql_injection__optional_query_parameters",
                        description=TestDescription(
                            http_method=getattr(HTTPMethods, endpoint.method.upper()),
                            url=url, base_url=endpoint.base_url, path=endpoint.path.path,
                            payload=endpoint.generate_safe_request_payload() if endpoint.has_request_payload() else None,
                        )
                    )
                )
                test_case.run()
                if test_case.test_case.result == TestResult.FAIL:
                    endpoint_failing_tests.append(test_case.test_case)
            if len(endpoint_failing_tests) > 0:
                failing_tests.extend(endpoint_failing_tests)
                click.echo(" 🚨")
            else:
                click.echo(" ✅")
        return failing_tests

    def run_sql_injection_through_request_payloads(self):
        failing_tests = []
        for endpoint in self.api_spec.endpoints:
            if not endpoint.has_request_payload():
                continue
            click.echo(f"    {endpoint.method.upper()} {endpoint.base_url + endpoint.path.path}", nl=False)
            self.injection_tests += 1
            test_case = InjectionTestCaseRunner(
                test_case=TestCase(
                    category=AttackStrategy.INJECTION,
                    test_target="sql_injection__optional_query_parameters",
                    description=TestDescription(
                        http_method=getattr(HTTPMethods, endpoint.method.upper()),
                        url=endpoint.safe_url, base_url=endpoint.base_url, path=endpoint.path.path,
                        payload=endpoint.generate_unsafe_request_payload()
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

    def run_sql_injection_attacks(self):
        failing_tests: list[TestCase] = []

        sql_injection_through_query_params_msg = """
  > Testing SQL injection through URL query parameters
          """
        sql_injection_through_path_params_msg = """
  > Testing SQL injection through URL path parameters
          """
        sql_injection_through_request_payloads_msg = """
  > Testing SQL injection through request payloads
          """

        click.echo(sql_injection_through_query_params_msg)
        failing_query_params_tests = self.run_sql_injection_through_query_parameters()

        click.echo(sql_injection_through_path_params_msg)
        failing_path_params_tests = self.run_sql_injection_through_path_parameters()

        click.echo(sql_injection_through_request_payloads_msg)
        failing_payload_tests = self.run_sql_injection_through_request_payloads()

        failing_tests += failing_query_params_tests + failing_path_params_tests + failing_payload_tests

        self.reports.append(TestReporter(
            category=AttackStrategy.INJECTION,
            number_tests=self.injection_tests,
            failing_tests=len(failing_tests),
            low_severity=sum(1 for test in failing_tests if test.severity == VulnerabilitySeverityLevel.LOW),
            medium_severity=sum(1 for test in failing_tests if test.severity == VulnerabilitySeverityLevel.MEDIUM),
            high_severity=sum(1 for test in failing_tests if test.severity == VulnerabilitySeverityLevel.HIGH),
        ))

        failed_tests_file = Path('.fencer/injection_attacks.json')
        failed_tests_file.write_text(
            json.dumps([test.dict() for test in failing_tests], indent=4)
        )

    def run_unauthorized_access_attacks(self):
        test_runner = TestAuthEndpoints(api_spec=self.api_spec)
        failing_tests = test_runner.test_authorized_endpoints()
        self.reports.append(TestReporter(
            category=AttackStrategy.UNAUTHORIZED_ACCESS,
            number_tests=test_runner.auth_tests,
            failing_tests=len(failing_tests),
            low_severity=sum(1 for test in failing_tests if test.severity == VulnerabilitySeverityLevel.LOW),
            medium_severity=sum(1 for test in failing_tests if test.severity == VulnerabilitySeverityLevel.MEDIUM),
            high_severity=sum(1 for test in failing_tests if test.severity == VulnerabilitySeverityLevel.HIGH),
        ))
        failed_tests_file = Path('.fencer/unauthorized_access_attacks.json')
        failed_tests_file.write_text(
            json.dumps([test.dict() for test in failing_tests], indent=4)
        )

    def run_surface_attacks(self):
        pass

    def run_mass_assignment_attacks(self):
        pass

    def run_insecure_design_attacks(self):
        pass
