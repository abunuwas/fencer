import json
from pathlib import Path

import click

from .api_spec import APISpec
from .BOLA import TestBOLA
from .BFLA import TestBFLA
from .authorized_endpoints import TestAuthEndpoints
from .sql_injection import SQLInjectionTestRunner
from .test_case import AttackStrategy, TestCase, VulnerabilitySeverityLevel, TestReporter
from .mass_assignment import TestMAEndpoints
from .xss_injection import XSSInjectionTestRunner

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
            category=AttackStrategy.SQL_INJECTION,
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
        
    def run_BOLA_attacks(self):
        test_runner = TestBOLA(api_spec=self.api_spec)
        failing_tests = test_runner.attack_analyzer()
        failed_tests_file = Path('.fencer/Broken_Object_Level_Authorization_attacks.json')
        with failed_tests_file.open('w', encoding='utf-8') as file:
            json.dump(failing_tests, file, ensure_ascii=False, indent=4)

    def run_BFLA_attacks(self):
        test_runner = TestBFLA(api_spec=self.api_spec)
        failing_tests: list[TestCase] = []
        
        BFLA_attack_through_path_params_msg = """
    > Testing BFLA attack through URL path parameters
            """
        BFLA_attack_through_request_payloads_msg = """
    > Testing BFLA attack through request payloads
            """
        click.echo(BFLA_attack_through_path_params_msg)
        failing_path_params_tests = test_runner.run_BFLA_attack_through_path_parameters()

        click.echo(BFLA_attack_through_request_payloads_msg)
        failing_payload_tests = test_runner.run_BFLA_attack_through_request_payloads()
        
        failing_tests += failing_path_params_tests + failing_payload_tests
        self.reports.append(TestReporter(
            category=AttackStrategy.BFLA,
            number_tests=test_runner.auth_tests,
            failing_tests=len(failing_tests),
            low_severity=sum(1 for test in failing_tests if test.severity == VulnerabilitySeverityLevel.LOW),
            medium_severity=sum(1 for test in failing_tests if test.severity == VulnerabilitySeverityLevel.MEDIUM),
            high_severity=sum(1 for test in failing_tests if test.severity == VulnerabilitySeverityLevel.HIGH),
        ))
        failed_tests_file = Path('.fencer/Broken_Function_Level_Authorization_attacks.json')
        failed_tests_file.write_text(
            json.dumps([test.dict() for test in failing_tests], indent=4)
        )
        
    def run_surface_attacks(self):
        pass

    def run_mass_assignment_attacks(self):
        test_runner = TestMAEndpoints(api_spec=self.api_spec)
        test_runner.test_MA_endpoints()

    def run_insecure_design_attacks(self):
        pass
    def run_xss_injection_attacks(self):
        xss_injection_test_runner = XSSInjectionTestRunner(api_spec=self.api_spec)

        failing_tests: list[TestCase] = []

        xss_injection_through_query_params_msg = """
  > Testing XSS injection through URL query parameters
          """
        xss_injection_through_path_params_msg = """
  > Testing XSS injection through URL path parameters
          """
        xss_injection_through_request_payloads_msg = """
  > Testing XSS injection through request payloads
          """

        click.echo(xss_injection_through_query_params_msg)
        failing_query_params_tests = xss_injection_test_runner.run_xss_injection_through_query_parameters()

        click.echo(xss_injection_through_path_params_msg)
        failing_path_params_tests = xss_injection_test_runner.run_xss_injection_through_path_parameters()

        click.echo(xss_injection_through_request_payloads_msg)
        failing_payload_tests = xss_injection_test_runner.run_xss_injection_through_request_payloads()

        failing_tests += failing_query_params_tests + failing_path_params_tests + failing_payload_tests

        self.reports.append(TestReporter(
            category=AttackStrategy.XSS_INJECTION,
            number_tests=xss_injection_test_runner.injection_tests,
            failing_tests=len(failing_tests),
            low_severity=sum(1 for test in failing_tests if test.severity == VulnerabilitySeverityLevel.LOW),
            medium_severity=sum(1 for test in failing_tests if test.severity == VulnerabilitySeverityLevel.MEDIUM),
            high_severity=sum(1 for test in failing_tests if test.severity == VulnerabilitySeverityLevel.HIGH),
        ))

        failed_tests_file = Path('.fencer/xss_injection_attacks.json')
        failed_tests_file.write_text(
            json.dumps([test.dict() for test in failing_tests], indent=4)
        )
    