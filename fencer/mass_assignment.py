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
    def run_mass_assignment_through_request_payloads(self):
        endpoint_body = {}
        for endpoint in self.api_spec.endpoints:
            if not endpoint.has_request_payload():
                if endpoint.responses.get('200', {}).get('content', {}).get('application/json', {}).get('schema',{}).get('properties'):
                    endpoint_body.update({endpoint.api_path:[endpoint.method,endpoint.api_path,[],list(endpoint.responses['200']['content']['application/json']['schema']['properties'].keys())]})
                else:
                    endpoint_body.update({endpoint.api_path:[endpoint.method,endpoint.api_path,[],[]]})
                continue
            
            if endpoint.responses.get('200', {}).get('content', {}).get('application/json', {}).get('schema',{}).get('properties'):
                endpoint_body.update({endpoint.api_path:[endpoint.method,endpoint.api_path,list(endpoint.body['content']['application/json']['schema']['properties'].keys()),list(endpoint.responses['200']['content']['application/json']['schema']['properties'].keys())]})
            else:
                endpoint_body.update({endpoint.api_path:[endpoint.method,endpoint.api_path,list(endpoint.body['content']['application/json']['schema']['properties'].keys()),[]]}) 
        
        for endpoint, require_list in endpoint_body.items():
        # 提取URL中的路径部分，即第一个斜杠后的内容
            path = endpoint.split('/')[3]
    
            # 将端点添加到相应的类别组中
            if path in self.endpoint_groups:
                self.endpoint_groups[path].append((endpoint, require_list))
            else:
                self.endpoint_groups[path] = [(endpoint, require_list)]

        for endpoint, require_list in self.endpoint_groups['v2']:
            path2 = endpoint.split('/')[4]

            if path2 in self.endpoint_groups:
                self.endpoint_groups[path2].append((endpoint, require_list))
            else:
                self.endpoint_groups[path2] = [(endpoint, require_list)]
        del self.endpoint_groups['v2']
        #找唯讀
        for category, endpoints in self.endpoint_groups.items():
            click.echo(f"Category: {category}")
            input_field = set({})
            output_field = set({})
            only_read_field = []
            for endpoint, require_list in endpoints:
                click.echo(f"    Endpoint: {require_list[0]} {require_list[1]}, Require: {require_list[2]}, Respones: {require_list[3]}")
                output_field.update(set(require_list[3]))
                input_field.update(set(require_list[2]))
            only_read_field = list(output_field - input_field)
            click.echo(f"   input_field : {input_field}")
            click.echo(f"   output_field : {output_field}")
            click.echo(f"   only_read_field : {only_read_field}")
        # 输出结果
    
        

        ''' 
            self.injection_tests += 1
            test_case = InjectionTestCaseRunner(
                test_case=TestCase(
                    category=AttackStrategy.XSS _INJECTION,
                    test_target="xss_injection__optional_query_parameters",
                    description=TestDescription(
                        http_method=getattr(HTTPMethods, endpoint.method.upper()),
                        url=endpoint.safe_url, base_url=endpoint.base_url, path=endpoint.path.path,
                        payload=xss_injection.generate_unsafe_request_payload()
                    )
                )
            )
            test_case.run(AUTHORIZED_TOKEN)
            if test_case.test_case.result == TestResult.FAIL:
                failing_tests.append(test_case.test_case)
                click.echo(" 🚨")
            else:
                click.echo(" ✅")
        '''

class TestMAEndpoints:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
    def test_MA_endpoints(self):
        pass