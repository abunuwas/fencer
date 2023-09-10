import random
import re
from dataclasses import dataclass
from typing import List, Callable, Optional

import click
import requests

from .api_spec import Endpoint, fake_parameter, APISpec
from .test_case import TestResult, TestCase, AttackStrategy, TestDescription, HTTPMethods, VulnerabilitySeverityLevel

@dataclass
class IDOREndpoint:
    endpoint: Endpoint
    fake_id_strategy: Optional[Callable] = None

    def fake_id(self):
        return str(random.randint(1,100)) 

    def __post_init__(self):
        self.fake_id_strategy = self.fake_id_strategy or self.fake_id

    def get_altered_url_with_different_ids(self): # 回傳改變後有偽造ID的URL
        # Detect all path parameters
        path_parameters = re.findall(r"\{(\w+)\}", self.endpoint.safe_url)
        
        altered_urls = []
        for param in path_parameters:
            altered_url = self.endpoint.safe_url.replace(f"{{{param}}}", self.fake_id_strategy())
            altered_urls.append(altered_url)
        
        return altered_urls

    def get_urls_with_altered_ids(self):
        for url in self.get_altered_url_with_different_ids():
            yield url


class IDORTestCaseRunner:
    def __init__(self, test_case: TestCase):
        self.test_case = test_case
        self.response = None

    def run(self):
        try:
            http_method = getattr(requests, self.test_case.description.http_method.value.lower())
            self.response = http_method(
                self.test_case.description.url, json=self.test_case.description.payload
            )
            self.resolve_test_result()
        except requests.RequestException as e:
            print(f"Error occurred while sending request: {e}")
            self.test_case.result = TestResult.ERROR

    def resolve_test_result(self):
        if self.response.status_code in [401, 403]:
            self.test_case.result = TestResult.SUCCESS
        elif self.response.status_code == 200:
            self.test_case.result = TestResult.FAIL
        self.test_case.ended_test()


class IDORTestRunner:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
        self.idor_tests = 0
        self.reports = []
    def create_account(self):
        create_account_endpoint = None
        for endpoint in self.api_spec.endpoints:
            if endpoint.method == "post" and "/signup" in endpoint.path:
                create_account_endpoint = endpoint
                break
        if create_account_endpoint:
            # 生成有效載荷
            payload = create_account_endpoint.generate_safe_request_payload()

            # 發送請求
            response = requests.post(create_account_endpoint.safe_url, json=payload)

            # 檢查回應
            if response.status_code == 200:
                print("Successfully created an account with the generated payload!")
                return response.json()
            else:
                print(f"Failed to create an account. Status Code: {response.status_code}")
        else:
            print("Could not find the specified endpoint.")

    def run_idor_tests(self):
        failing_tests = []
        account_info = self.create_account()
        for endpoint in self.api_spec.endpoints:
            idor_endpoint = IDOREndpoint(endpoint)
            for altered_url in idor_endpoint.get_urls_with_altered_ids():
                self.idor_tests += 1
                click.echo(f"    {endpoint.method.upper()} {altered_url}", nl=False)

                test_case = IDORTestCaseRunner(
                    test_case=TestCase(
                        category=AttackStrategy.IDOR,
                        test_target="idor_test",
                        description=TestDescription(
                            http_method=getattr(HTTPMethods, endpoint.method.upper()),
                            url=altered_url, base_url=endpoint.base_url, path=endpoint.path.path,
                            payload=None  # Adjust as needed
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
