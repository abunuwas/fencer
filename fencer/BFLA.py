import random
from dataclasses import dataclass
from typing import List, Callable, Optional

import click
import requests
from requests.exceptions import JSONDecodeError
from jsf import JSF

from .api_spec import Endpoint, fake_parameter, APISpec
from .test_case import TestResult, TestCase, AttackStrategy, TestDescription, HTTPMethods, VulnerabilitySeverityLevel
# cba token
AUTHORIZED_TOKEN = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjYmFAZ21haWwuY29tIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDkxNzg2MDksImV4cCI6MTcwOTc4MzQwOX0.mgvHiG'\
                   'uof2hfxlZ0eTRVcr_U-s3BW0DgDqZEUJCTT6ymWerwaCxbZftefgwrQaCOw1i7Ly2kLJivWO1Kn1Hz6UANCVH-Fpfb8n7hu3WgrG4LUj035h8v5QpZUpDAJhNhu'\
                   'oqSR_rwWXuxtvxHRIUgCnkls2BpB3TIcqfcaURrl3l_ujLR4T-UPH0bRc9mJ-6jT4Sub19baHD5ZXFKKIrgQ1G4GfxpoS4aeVLkvESQB-Kw3h2jsSovL37mHboH'\
                   'UR1MkosFaPkdfu-bVk4qY4rul_8hkQE6bbBj_Juv0c_9zziK1hsNXTjgsNfoqGAZUgENsPDObl-mTka2a9MD9SsNSw'
# hacker token
UNAUTHORIZED_TOKEN = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJoYWNrZXJAZ21haWwuY29tIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDg5MjUxMzUsImV4cCI6MTcwOTUyOTkzNX0.'\
                     'MCrnDpUn349qlblgTsdOaEfVYdR5tGYYHWqCj-yoabgxVeIi9MGjylyCkFdxjYVv5ghjOv6bnaps8FUbtlkfAAdtQODO2SHBMNSSPDcdXF3aUexIinkgvbPSSB'\
                     '8EXnJjXc38GLmhyUYqVvObE4YDzfvWTshNUAZzjbzxw2hx3tDXWE1qAz8eQD5UBEvPgK4xr6q7qIL6vcWDBPgJOsKVdbsE-4VqohFw0X0D52WDE-brdF_NTEE-'\
                     'pVrIiFHtJe39lStzIgY3syWxtG8sppiLoRl5dOxWFc6fcQGg6N6DVyAVDiSmD8OgBZw7wwhyjF9sBuSLtm1dvjYhmEJpWhXY6Q'

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
            for param_scheams in self.endpoint.path.path_params_schemas:
                replace_param = str(self.fake_param_strategy(param_scheams['schema']))
                path = self.endpoint.path.path.replace(f'{{{param}}}', replace_param)
                urls.append(self.endpoint.base_url + path)
        return urls

    def gets_url_with_test_path_params(self):
        urls = []
        if self.endpoint.path.has_path_params():
            if self.endpoint.has_required_path_params():
                urls.extend(self.create_fake_parameter_with_path_position())
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
        """
        try:
            print(self.response.status_code," ",self.response.json())
        except JSONDecodeError:
            print('Response format is not json.')
        """
        # If response status code is 401 or 403, it's all good
        if self.response.status_code in [401, 403]:
            self.test_case.result = TestResult.SUCCESS
            self.test_case.severity = VulnerabilitySeverityLevel.ZERO
        # If the response status code is in the 2xx status code group, it's pretty bad
        elif 200 <= self.response.status_code < 300:
            self.test_case.result = TestResult.FAIL
            self.test_case.severity = VulnerabilitySeverityLevel.HIGH
        # If the server fails to respond, endpoint is protected and there's no possibility for exploit,
        # but we can break the server, so we give it a medium severity
        elif self.response is None:
            self.test_case.result = TestResult.SUCCESS
            self.test_case.severity = VulnerabilitySeverityLevel.ZERO
        # In all other cases, the response isn't successful, but it's still
        # doing some processing, and that can be leveraged by hackers, so we
        # assign it a high severity
        else:
            self.test_case.result = TestResult.SUCCESS
            self.test_case.severity = VulnerabilitySeverityLevel.ZERO
        self.test_case.ended_test()

class TestBFLA:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
        self.auth_tests = 0
    def run_BFLA_attack_through_path_parameters(self):
        failing_tests = []
        for endpoint in self.api_spec.authorized_endpoints:
            if not endpoint.has_path_params() or endpoint.method == 'get':
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
                            url=url, base_url=endpoint.base_url, path=endpoint.path.path,
                            payload=(
                                endpoint.generate_safe_request_payload()
                                if endpoint.has_request_payload() else None
                            ),
                        )
                    )
                )
                BFLA_test_case.run(UNAUTHORIZED_TOKEN)
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
            if endpoint.method == 'get':
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
            BFLA_test_case.run(UNAUTHORIZED_TOKEN)
            if BFLA_test_case.test_case.result == TestResult.FAIL:
                failing_tests.append(BFLA_test_case.test_case)
                click.echo(" 🚨")
            else:
                click.echo(" ✅")
        return failing_tests