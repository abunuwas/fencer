import random
import re
from dataclasses import dataclass
from typing import List, Callable, Optional

import click
import requests

from .api_spec import APISpec
from .test_case import TestResult, TestCase, AttackStrategy, TestDescription, HTTPMethods,\
      VulnerabilitySeverityLevel
        
class MSTestRunner:   
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
        self.endpoint_groups = {}
        self.MS_tests = 0
    def run_mass_assignment_through_request_payloads(self):
        failing_tests = {}
        endpoint_body = {}
        output_field = set()
        input_field = set()
        only_read_field = set()
        for endpoint in self.api_spec.endpoints:
            if endpoint.method.upper() != "GET":
                if endpoint.responses.get('200', {}).get('content', {}).get('application/json', {}).get('schema',{}).get('properties'):
                    for response in endpoint.responses.get('200', {}).get('content', {}).get('application/json', {}).get('schema',{}).get('properties'):
                        output_field.add(response)
            if not endpoint.has_request_payload():
                continue
            else:
                if endpoint.method.upper() != "GET":
                    for request in endpoint.body.get('content', {}).get('application/json', {}).get('schema',{}).get('properties'):
                        input_field.add(request)
        only_read_field = output_field - input_field
        click.echo(f"   output_field : {output_field}")
        click.echo(f"   input_field : {input_field}")
        click.echo(f"   only_read_field : {only_read_field}")

        for endpoint in self.api_spec.endpoints:
            if not endpoint.has_request_payload():
                continue
            else:
                self.MS_tests += 1
                click.echo(f"    {endpoint.method.upper()} {endpoint.base_url + endpoint.path.path}", nl=False)
                result = set()
                for response in endpoint.responses.get('200', {}).get('content', {}).get('application/json', {}).get('schema', {}).get('properties', {}):
                    if response in only_read_field:
                        result.add(response)
                if result:
                    click.echo(" 🚨")
                    click.echo(f"    Fields that may generate mass assignment of read-only attributes in this API endpoint:{result}", nl=True)
                    failing_tests.update({endpoint.path.path:list(result)})
                else:
                    click.echo(" ✅")
        return failing_tests

class TestMAEndpoints:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
    def test_MA_endpoints(self):
        pass