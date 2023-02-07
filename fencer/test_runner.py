import json
from pathlib import Path

import click

from .api_spec import APISpec
from .authorized_endpoints import TestAuthEndpoints
from .sql_injection import SQLInjectionTestRunner
from .test_case import AttackStrategy, TestCase, VulnerabilitySeverityLevel, TestReporter


class TestRunner:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
        self.reports = []

    def run_sql_injection_attacks(self):
        sql_injection_test_runner = SQLInjectionTestRunner(api_spec=self.api_spec)

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
        failing_query_params_tests = sql_injection_test_runner.run_sql_injection_through_query_parameters()

        click.echo(sql_injection_through_path_params_msg)
        failing_path_params_tests = sql_injection_test_runner.run_sql_injection_through_path_parameters()

        click.echo(sql_injection_through_request_payloads_msg)
        failing_payload_tests = sql_injection_test_runner.run_sql_injection_through_request_payloads()

        failing_tests += failing_query_params_tests + failing_path_params_tests + failing_payload_tests

        self.reports.append(TestReporter(
            category=AttackStrategy.INJECTION,
            number_tests=sql_injection_test_runner.injection_tests,
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
