import random
from dataclasses import dataclass

import click
import requests
from jsf import JSF

from .api_spec import Endpoint, fake_parameter, APISpec
from .test_case import TestResult, TestCase, AttackStrategy, TestDescription, HTTPMethods, VulnerabilitySeverityLevel

sql_injection_strategies = [
    "' OR 1=1 --",
    "' UNION SELECT * FROM information_schema.tables --",
    '"; DROP TABLE users --',
    "'; SELECT user, password FROM users WHERE '1' = '1",
    "'; SELECT id FROM users WHERE '1' = '1",
    "' OR '1' = '1",
    "' OR username LIKE '%",
    ' OR "1"="1"',
    "%' AND 1=0 UNION SELECT * FROM information_schema.tables --",
    "%' OR 1=1; --",
    "' UNION SELECT NULL, table_name FROM information_schema.tables WHERE 2 > 1 \"\"",
]

nosql_injection_strategies = []


@dataclass
class SQLInjectionEndpoint:
    endpoint: Endpoint

    def get_safe_url_path_with_unsafe_required_query_params(self):
        urls = []
        for param in self.endpoint.required_query_params:
            for strategy in sql_injection_strategies:
                param_value = f'?{param["name"]}={strategy}'
                other_params = [
                    other_param for other_param in self.endpoint.required_query_params
                    if other_param['name'] != param['name']
                ]
                if len(other_params) > 0:
                    param_value += '&'
                other_params = '&'.join(
                    f"{other_param['name']}={fake_parameter(param['schema'])}"
                    for other_param in other_params
                )
                url = self.endpoint.safe_url_path_without_query_params + param_value + other_params
                urls.append(url)
        return urls

    def get_safe_url_path_with_unsafe_optional_query_params(self):
        urls = []
        base_url = (
            self.endpoint.safe_url_path_with_safe_required_query_params
            if self.endpoint.has_required_query_params()
            else self.endpoint.safe_url_path_without_query_params
        )
        if self.endpoint.has_required_query_params():
            for param in self.endpoint.optional_query_params:
                for strategy in sql_injection_strategies:
                    param_value = f'?{param["name"]}={strategy}'
                    other_params = [
                        other_param for other_param in self.endpoint.optional_query_params
                        if other_param['name'] != param['name']
                    ]
                    if len(other_params) > 0:
                        param_value += '&'
                    other_params = '&'.join(
                        f"{other_param['name']}={fake_parameter(param['schema'])}"
                        for other_param in other_params
                    )
                    url = base_url + param_value + other_params
                    urls.append(url)
        return urls

    def get_unsafe_url_path_without_query_params(self):
        urls = []
        for param in self.endpoint.path.path_params_list:
            for strategy in sql_injection_strategies:
                path = self.endpoint.path.path.replace(param, strategy)
                urls.append(self.endpoint.base_url + path)
        return urls

    def get_unsafe_url_path_with_safe_required_query_params(self):
        urls = []
        for base_url in self.get_unsafe_url_path_without_query_params():
            urls.append(
                base_url + '?'
                + '&'.join(f"{param['name']}={fake_parameter(param['schema'])}"
                           for param in self.endpoint.required_query_params)
            )
        return urls

    def get_urls_with_unsafe_query_params(self):
        urls = []
        if self.endpoint.has_required_query_params():
            urls.extend(self.get_safe_url_path_with_unsafe_required_query_params())
        if self.endpoint.has_optional_query_params():
            urls.extend(self.get_safe_url_path_with_unsafe_optional_query_params())
        for url in urls:
            yield url

    def get_urls_with_unsafe_path_params(self):
        urls = []
        if self.endpoint.path.has_path_params():
            urls.extend(self.get_unsafe_url_path_without_query_params())
            if self.endpoint.has_required_query_params():
                urls.extend(self.get_unsafe_url_path_with_safe_required_query_params())
        for url in urls:
            yield url

    def _inject_dangerous_sql_in_payload(self, payload, schema):
        # need to include anyOf, allOf
        if schema['type'] == 'array':
            return [
                self._inject_dangerous_sql_in_payload(item, schema['items'])
                for item in payload
            ]
        if schema['type'] == 'object':
            # sometimes properties aren't specified so soft access
            for name, description in schema.get('properties', {}).items():
                # property may not be required
                if name not in payload:
                    continue
                if description['type'] == 'string':
                    payload[name] = random.choice(sql_injection_strategies)
                if description['type'] == 'array':
                    payload[name] = self._inject_dangerous_sql_in_payload(
                        payload[name], description
                    )
        return payload

    def generate_unsafe_request_payload(self):
        # this should be plural returning an array of payloads with different
        # sql injection strategies
        schema = self.endpoint.body['content']['application/json']['schema']
        if 'allOf' in schema:
            schema = schema['allOf'][0]
        if 'anyOf' in schema:
            schema = schema['anyOf'][0]
        payload = JSF(schema).generate()
        return self._inject_dangerous_sql_in_payload(payload, schema)


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


class SQLInjectionTestRunner:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
        self.injection_tests = 0
        self.reports = []

    def run_sql_injection_through_query_parameters(self):
        failing_tests = []
        for endpoint in self.api_spec.endpoints:
            sql_injection = SQLInjectionEndpoint(endpoint)
            endpoint_failing_tests = []
            click.echo(f"    {endpoint.method.upper()} {endpoint.base_url + endpoint.path.path}", nl=False)
            for url in sql_injection.get_urls_with_unsafe_query_params():
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
            sql_injection = SQLInjectionEndpoint(endpoint)
            endpoint_failing_tests = []
            click.echo(f"    {endpoint.method.upper()} {endpoint.base_url + endpoint.path.path}", nl=False)
            for url in sql_injection.get_urls_with_unsafe_path_params():
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
            sql_injection = SQLInjectionEndpoint(endpoint)
            click.echo(f"    {endpoint.method.upper()} {endpoint.base_url + endpoint.path.path}", nl=False)
            self.injection_tests += 1
            test_case = InjectionTestCaseRunner(
                test_case=TestCase(
                    category=AttackStrategy.INJECTION,
                    test_target="sql_injection__optional_query_parameters",
                    description=TestDescription(
                        http_method=getattr(HTTPMethods, endpoint.method.upper()),
                        url=endpoint.safe_url, base_url=endpoint.base_url, path=endpoint.path.path,
                        payload=sql_injection.generate_unsafe_request_payload()
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
