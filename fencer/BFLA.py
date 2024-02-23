import random
from dataclasses import dataclass
from typing import List, Callable, Optional

import click
import requests
from requests.exceptions import JSONDecodeError
from jsf import JSF

from .api_spec import Endpoint, fake_parameter, APISpec
from .test_case import TestResult, TestCase, AttackStrategy, TestDescription, HTTPMethods, VulnerabilitySeverityLevel

AUTHORIZED_TOKEN = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYmNAZ21haWwuY29tIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDgzMjQ5MzUsImV4cCI6MTcwODkyOTczNX0.'\
                   'BjErFScOIk_9FXGVF2xkcLOnHlJMTB5G7Esi31GYRJpq2bItHtSVQzA6eJ4X96fGPnM0qrbVeUHqVM-bE96YMyRirAtKGUVJrivaLwOniJEdOOQ2-NPqSut'\
                   'bzWTmWgIQfZUoh_1q0gSVS13k-dw5963kUlGeL5d5XZuSIvO0lVufjCoo7ASJOu39RZ2mv109ig-QuX5FOnDcKM9Zx1kh9gcJBoahZyw4khebVDN5M7Z39qE0'\
                   'c1EhuJyZ34BXy0Vgq5HvuBC0pdKfR7c9X3tTmK9vemxyqTM-ui1TU_ftr_1fOBOk9BIy7lyj3Zh49Mi9t4xhbUOIk3wfG3qMx3BaHQ'

UNAUTHORIZED_TOKEN = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjYmFAZ21haWwuY29tIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDgzMjY3NTYsImV4cCI6MTcwODkzMTU1Nn0.'\
                     'bCnedndWp2M1W2NLpke_J9X1AO_5h7we4lZDcT7In0J3AqCGdVNIJKllTV6VJA9c_5CXN3cvlfpaZiCB17pMH1PUAaVKtKTvSQQNIGmgNJ--WZN--30Sp00'\
                     'kVc4-szaY8iR4PUZFw4CZO9PGBmpc-9nA4jUMR3Esj5DLE8ghpq1Gf7mYC1x3PVabSyvTk7JnRIfxnNOKlZb9B-0XiKRdU88URDiI9muHUgF8WC9EnNaYGhQO'\
                     '-f1O-O5dJM2iQuKhvJX2GhBtiShxIXr618ImISgQEESG0XnVMnmOiKl69hfkgT8aVdS2KYR8Wg4MaXc5m2NgDV6l05VtCrW95XSSbQ'

@dataclass
class BFLAEndpoint:
    endpoint:Endpoint
    fake_param_strategy: Optional[Callable] = None
    fake_payload_strategy = None

    def __post_init__(self):
        self.fake_param_strategy = (
            self.fake_param_strategy or fake_parameter
        )
        self.fake_payload_strategy = (
            self.fake_payload_strategy or JSF
        )
    def create_fake_parameter_with_path_position(self):
        urls = []
        for param in self.endpoint.path.path_params_list:
            #print(" ",param)
            path = self.endpoint.path.path.replace(f'{{{param}}}')

    def gets_url_with_test_path_params(self):
        urls = []
        if self.endpoint.path.has_path_params():
            urls.extend(self.create_fake_parameter_with_path_position())
            if self.endpoint.has_required_query_params():
                pass
        for url in urls:
            yield url


class BFLATestCaseRunner:
    def __init__(self,test_case: TestCase):
        self.test_case = test_case
        self.response = None

    def run(self,token):
        headers = {'Authorization': f'Bearer {token}'}
        callable_ = getattr(requests, self.test_case.description.http_method.value.lower())
        self.response = callable_(
            self.test_case.description.url, json=self.test_case.description.payload, headers=headers
        )
        self.resolve_test_result()

    def resolve_test_result(self):
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

class TestBFLA:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
        self.auth_tests = 0
    def run_BFLA_attack_through_path_parameters(self):
        failing_tests = []
        for endpoint in self.api_spec.authorized_endpoints:
            if not endpoint.has_path_params():
                continue
            BFLA_attack = BFLAEndpoint(endpoint)
            endpoint_failing_tests = []
            click.echo(f"    {endpoint.method.upper()} {endpoint.base_url + endpoint.path.path}", nl=False)
            for url in BFLA_attack.gets_url_with_test_path_params():
                self.auth_tests += 1
                BFLA_test_case = BFLATestCaseRunner(
                    test_case = TestCase(
                        category=AttackStrategy.BFLA,
                        test_target="Broken_Function_Level_Authorization_attack",
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
                BFLA_test_case.run(AUTHORIZED_TOKEN)
                if BFLA_test_case.test_case.result == TestResult.FAIL:
                    endpoint_failing_tests.append(BFLA_test_case.test_case)
            if len(endpoint_failing_tests) > 0:
                failing_tests.extend(endpoint_failing_tests)
                click.echo(" 🚨")
            else:
                click.echo(" ✅")
        return failing_tests
    
    def run_BFLA_attack_through_request_payloads(self):
        failing_tests = []
        for endpoint in self.api_spec.authorized_endpoints:
            if not endpoint.has_request_payload:
                continue 
            click.echo(f"    {endpoint.method.upper()} {endpoint.base_url + endpoint.path.path}", nl=False)
            self.auth_tests += 1
            BFLA_test_case = BFLATestCaseRunner(
                test_case = TestCase(
                    category=AttackStrategy.BFLA,
                    test_target="Broken_Function_Level_Authorization_attack",
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
            BFLA_test_case.run(AUTHORIZED_TOKEN)
            if BFLA_test_case.test_case.result == TestResult.FAIL:
                failing_tests.append(BFLA_test_case.test_case)
                click.echo(" 🚨")
            else:
                click.echo(" ✅")
        return failing_tests