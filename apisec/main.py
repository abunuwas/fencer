import json
import re
from dataclasses import dataclass
from pathlib import Path

import requests


# create an openapi parser package
from colorama import init, Fore
from hypothesis_jsonschema import from_schema

base_url = 'http://localhost:5000'

spec_file = Path(__file__).parent / 'openapi.json'
spec = json.loads(spec_file.read_text())

dangerous_sql = "1' OR 1=1 --"

standard_http_methods = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head']


@dataclass
class Endpoint:
    base_url: str
    api_path: str
    method: str
    parameters: list
    body: dict | None
    responses: dict

    def __post_init__(self):
        self.path = APIPath(
            path=self.api_path,
            path_params_schemas=self.path_params
        )

    @property
    def required_query_params(self):
        return [
            param for param in self.parameters if param['in'] == 'query' and param['required']
        ]

    @property
    def optional_query_params(self):
        return [
            param for param in self.parameters if param['in'] == 'query' and not param['required']
        ]

    @property
    def path_params(self):
        return [
            param for param in self.parameters if param['in'] == 'path'
        ]

    @property
    def safe_url_path_without_query_params(self):
        return self.base_url + self.path.build_safe_path()

    @property
    def safe_url_path_with_safe_required_query_params(self):
        # here rather than safe query params what we have is random query params values
        # given by hypothesis, which isn't always the safest values so works for security test.
        # since we're testing security I guess we don't really need to bother much with sending
        # safe requests
        return (
                self.safe_url_path_without_query_params + '?'
                + '&'.join(f"{param['name']}={from_schema(param['schema']).example()}"
                           for param in self.required_query_params)
        )

    @property
    def safe_url_path_with_unsafe_required_query_params(self):
        return (
                self.safe_url_path_without_query_params + '?'
                + '&'.join(f"{param['name']}={dangerous_sql}" for param in self.required_query_params)
        )

    @property
    def safe_url_path_with_safe_optional_query_params(self):
        return (
                self.safe_url_path_without_query_params + '?'
                + '&'.join(f"{param['name']}={from_schema(param['schema']).example()}"
                           for param in self.optional_query_params)
        )

    @property
    def safe_url_path_with_unsafe_optional_query_params(self):
        return (
                self.safe_url_path_without_query_params + '?'
                + '&'.join(f"{param['name']}={dangerous_sql}" for param in self.optional_query_params)
        )

    @property
    def unsafe_url_path_without_query_params(self):
        return self.base_url + self.path.build_insecure_path()

    @property
    def unsafe_url_path_with_safe_required_query_params(self):
        return (
                self.unsafe_url_path_without_query_params + '?'
                + '&'.join(f"{param['name']}={from_schema(param['schema']).example()}"
                           for param in self.required_query_params)
        )

    @property
    def unsafe_url_path_with_unsafe_required_query_params(self):
        return (
                self.unsafe_url_path_without_query_params + '?'
                + '&'.join(f"{param['name']}={dangerous_sql}" for param in self.required_query_params)
        )

    @property
    def unsafe_url_path_with_safe_optional_query_params(self):
        return (
                self.unsafe_url_path_without_query_params + '?'
                + '&'.join(f"{param['name']}={from_schema(param['schema']).example()}"
                           for param in self.optional_query_params)
        )

    @property
    def unsafe_url_path_with_unsafe_optional_query_params(self):
        return (
                self.unsafe_url_path_without_query_params + '?'
                + '&'.join(f"{param['name']}={dangerous_sql}" for param in self.optional_query_params)
        )

    @property
    def urls(self):
        return [
            self.safe_url_path_without_query_params,
            self.safe_url_path_with_safe_required_query_params,
            self.safe_url_path_with_unsafe_required_query_params,
            self.safe_url_path_with_safe_optional_query_params,
            self.safe_url_path_with_unsafe_optional_query_params,
            self.unsafe_url_path_without_query_params,
            self.unsafe_url_path_with_safe_required_query_params,
            self.unsafe_url_path_with_unsafe_required_query_params,
            self.unsafe_url_path_with_safe_optional_query_params,
            self.unsafe_url_path_with_unsafe_optional_query_params,
        ]

    def get_urls(self):
        for url in self.urls:
            yield url

    def with_required_query_params(self):
        pass

    def without_required_query_params(self):
        pass

    def with_optional_query_params(self):
        pass


@dataclass
class APIPath:
    path: str
    path_params_schemas: list

    path_param_regex = re.compile('{.*?}')

    def __post_init__(self):
        self.path_params_list = self.path_param_regex.findall(self.path)
        self._undocumented_path_params = [
            param for param in self.path_params_schemas if param['name'] not in self.path
        ]

    def has_path_params(self):
        return len(self.path_params_list) > 0

    def has_undocumented_path_params(self):
        return len(self._undocumented_path_params) > 0

    def build_safe_path(self):
        if not self.has_path_params():
            return self.path

        path = self.path
        for param in self.path_params_schemas:
            path = path.replace(
                f'{{{param["name"]}}}',
                from_schema(param['schema']).example(),
            )

        if not self.has_undocumented_path_params():
            return path

        for param in self._undocumented_path_params:
            path = path.replace(
                f'{{{param["name"]}}}',
                from_schema({'type': 'string'}).example(),
            )

        return path

    def build_insecure_path(self):
        path = self.path
        for param in self.path_params_list:
            path = self.path.replace(param, dangerous_sql)
        return path


class APISpec:

    def __init__(self, base_url: str, spec: dict):
        self.base_url = base_url
        self.spec = spec
        self.servers = spec.get('servers')
        self.paths = spec['paths']
        self.components = spec['components']
        self.endpoints = []

    def load_endpoints(self):
        paths = self.paths.keys()
        for path in paths:
            http_methods = [method for method in self.paths[path].keys() if method in standard_http_methods]
            url_params = self.paths[path].get('parameters', [])
            # do options request and confirm only these methods are allowed
            for method in http_methods:
                self.endpoints.append(
                    Endpoint(
                        base_url=self.base_url,
                        api_path=path,
                        method=method,
                        parameters=url_params + self.paths[path][method].get('parameters', []),
                        body=self.paths[path][method].get('requestBody'),
                        responses=self.paths[path][method]['responses']
                    )
                )


api_spec = APISpec(base_url=base_url, spec=spec)
api_spec.load_endpoints()

# for endpoint in api_spec.endpoints:
#     print(endpoint.url)

init(autoreset=True)

counter = 0

for endpoint in api_spec.endpoints:
    for url in endpoint.get_urls():
        counter += 1
        print(endpoint.method.upper(), url)
        callable_ = getattr(requests, endpoint.method)
        response = callable_(url)
        print(response.status_code)
        try:
            content = response.json()
        except:
            content = response.content
        content = str(content)
        if response.status_code == 500:
            print(Fore.RED + content)
        else:
            print(content)


print(Fore.YELLOW + f'Total tests: {counter}')
