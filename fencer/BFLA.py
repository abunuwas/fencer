import random
from dataclasses import dataclass
from typing import List, Callable, Optional

import click
import requests
from jsf import JSF

from .api_spec import Endpoint, fake_parameter, APISpec
from .test_case import TestResult, TestCase, AttackStrategy, TestDescription, HTTPMethods, VulnerabilitySeverityLevel

AUTHORIZED_TOKEN = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYmNAZ21haWwuY29tIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDgzMjQ5MzUsImV4cCI6MTcwODkyOTczNX0.'\
                   'BjErFScOIk_9FXGVF2xkcLOnHlJMTB5G7Esi31GYRJpq2bItHtSVQzA6eJ4X96fGPnM0qrbVeUHqVM-bE96YMyRirAtKGUVJrivaLwOniJEdOOQ2-NPqSut'\
                   'bzWTmWgIQfZUoh_1q0gSVS13k-dw5963kUlGeL5d5XZuSIvO0lVufjCoo7ASJOu39RZ2mv109ig-QuX5FOnDcKM9Zx1kh9gcJBoahZyw4khebVDN5M7Z39qE0'\
                   'c1EhuJyZ34BXy0Vgq5HvuBC0pdKfR7c9X3tTmK9vemxyqTM-ui1TU_ftr_1fOBOk9BIy7lyj3Zh49Mi9t4xhbUOIk3wfG3qMx3BaHQ'

class TestBFLA:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
        self.paths = api_spec.paths

    def send_request(token,endpoint):
        headers = {'Authorization': f'Bearer {token}'}
        API_endpoint = endpoint.base_url + endpoint.path.path
        response = getattr(requests,endpoint.method)(API_endpoint,headers=headers)
        return response.status_code, response.json()

    def test_BFLA_attack(self):
        for endpoint in self.api_spec.authorized_endpoints:
            click.echo(f"    {endpoint.method.upper()} {endpoint.base_url + endpoint.path.path}", nl=False)
            self.send_request(AUTHORIZED_TOKEN,endpoint)

            