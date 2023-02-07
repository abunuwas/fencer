import random
import re
import string
import uuid
from dataclasses import dataclass
from datetime import datetime

import exrex
from jsf import JSF

dangerous_sql = "1' OR 1=1 --"

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

standard_http_methods = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head']


@dataclass
class NumberRanges:
    schema: dict

    @property
    def minimum(self):
        minimum = self.schema.get('minimum', 0)
        if self.schema.get('exclusiveMinimum'):
            minimum = self.schema['exclusiveMinimum'] + 1
        return minimum

    @property
    def maximum(self):
        total_max = 2147483647 if self.schema.get('format', '') == 'int32' else 9223372036854775807
        maximum = self.schema.get('maximum', total_max)
        if self.schema.get('exclusiveMaximum'):
            maximum = self.schema['exclusiveMaximum'] - 1
        return maximum


def fake_parameter(schema):
    if schema['type'] == 'string':
        if 'format' not in schema:
            if schema.get('pattern'):
                return exrex.getone(schema['pattern'])
            return ''.join(
                random.choice(string.ascii_letters)
                for _ in range(schema.get('minLength', 2), schema.get('maxLength', 20))
            )
        if schema['format'] == 'uuid':
            return str(uuid.uuid4())
        if schema['format'] == 'date':
            return str(datetime.now().date())
        if schema['format'] == 'date-time':
            return str(datetime.now())
        if schema['format'] == 'email':
            return 'test@example.com'
        if schema['format'] == 'ipv4':
            return '127.0.0.1'

    if schema['type'] == 'integer':
        ranges = NumberRanges(schema)
        return random.randint(ranges.minimum, ranges.maximum)
    if schema['type'] == 'number':
        if 'format' not in schema:
            ranges = NumberRanges(schema)
            return random.randint(ranges.minimum, ranges.maximum)
        if schema['format'] == 'float':
            return random.random() * 1000
        if schema['format'] == 'double':
            return round(random.random() * 1000, 2)

    if schema['type'] == 'boolean':
        return random.choice(['true', 'false'])


@dataclass
class Endpoint:
    base_url: str
    api_path: str
    method: str
    parameters: list
    body: dict | None
    responses: dict
    security: dict | list | None = None

    def __post_init__(self):
        self.path = APIPath(
            path=self.api_path,
            path_params_schemas=self.path_params
        )

    @property
    def query_params(self):
        return [
            param for param in self.parameters if param['in'] == 'query'
        ]

    @property
    def required_query_params(self):
        return [
            param for param in self.query_params if param['required']
        ]

    @property
    def optional_query_params(self):
        return [
            param for param in self.parameters if not param['required']
        ]

    @property
    def path_params(self):
        return [
            param for param in self.parameters if param['in'] == 'path'
        ]

    def has_query_params(self):
        return len(self.query_params) > 0

    def has_required_query_params(self):
        return len(self.required_query_params) > 0

    def has_optional_query_params(self):
        return len(self.optional_query_params) > 0

    def has_path_params(self):
        return len(self.path_params) > 0

    @property
    def safe_url_path_without_query_params(self):
        return self.base_url + self.path.build_safe_path()

    @property
    def safe_url_path_with_safe_required_query_params(self):
        return (
                self.safe_url_path_without_query_params + '?'
                + '&'.join(f"{param['name']}={fake_parameter(param['schema'])}"
                           for param in self.required_query_params)
        )

    def get_safe_url_path_with_unsafe_required_query_params(self):
        urls = []
        for param in self.required_query_params:
            for strategy in sql_injection_strategies:
                param_value = f'?{param["name"]}={strategy}'
                other_params = [
                    other_param for other_param in self.required_query_params
                    if other_param['name'] != param['name']
                ]
                if len(other_params) > 0:
                    param_value += '&'
                other_params = '&'.join(
                    f"{other_param['name']}={fake_parameter(param['schema'])}"
                    for other_param in other_params
                )
                url = self.safe_url_path_without_query_params + param_value + other_params
                urls.append(url)
        return urls

    def get_safe_url_path_with_unsafe_optional_query_params(self):
        urls = []
        base_url = (
            self.safe_url_path_with_safe_required_query_params
            if self.has_required_query_params()
            else self.safe_url_path_without_query_params
        )
        if self.has_required_query_params():
            for param in self.optional_query_params:
                for strategy in sql_injection_strategies:
                    param_value = f'?{param["name"]}={strategy}'
                    other_params = [
                        other_param for other_param in self.optional_query_params
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
        for param in self.path.path_params_list:
            for strategy in sql_injection_strategies:
                path = self.path.path.replace(param, strategy)
                urls.append(self.base_url + path)
        return urls

    def get_unsafe_url_path_with_safe_required_query_params(self):
        urls = []
        for base_url in self.get_unsafe_url_path_without_query_params():
            urls.append(
                base_url + '?'
                + '&'.join(f"{param['name']}={fake_parameter(param['schema'])}"
                           for param in self.required_query_params)
            )
        return urls

    @property
    def safe_url(self):
        if self.has_required_query_params():
            return self.safe_url_path_with_safe_required_query_params
        return self.safe_url_path_without_query_params

    def get_urls_with_unsafe_query_params(self):
        urls = []
        if self.has_required_query_params():
            urls.extend(self.get_safe_url_path_with_unsafe_required_query_params())
        if self.has_optional_query_params():
            urls.extend(self.get_safe_url_path_with_unsafe_optional_query_params())
        for url in urls:
            yield url

    def get_urls_with_unsafe_path_params(self):
        urls = []
        if self.path.has_path_params():
            urls.extend(self.get_unsafe_url_path_without_query_params())
            if self.has_required_query_params():
                urls.extend(self.get_unsafe_url_path_with_safe_required_query_params())
        for url in urls:
            yield url

    def has_request_payload(self):
        if self.body is None:
            return False
        return self.body.get('content', {}).get('application/json', {}).get('schema') is not None

    def generate_safe_request_payload(self):
        schema = self.body['content']['application/json']['schema']
        return JSF(schema).generate()

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
                    payload[name] = dangerous_sql
                if description['type'] == 'array':
                    payload[name] = self._inject_dangerous_sql_in_payload(
                        payload[name], description
                    )
        return payload

    def generate_unsafe_request_payload(self):
        schema = self.body['content']['application/json']['schema']
        if 'allOf' in schema:
            schema = schema['allOf'][0]
        if 'anyOf' in schema:
            schema = schema['anyOf'][0]
        payload = JSF(schema).generate()
        return self._inject_dangerous_sql_in_payload(payload, schema)


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
                fake_parameter(param['schema']),
            )

        if not self.has_undocumented_path_params():
            return path

        for param in self._undocumented_path_params:
            path = path.replace(
                f'{{{param["name"]}}}',
                JSF({'type': 'string'}).generate().split(' ')[0],
            )

        return path


class APISpec:

    def __init__(self, base_url: str, spec: dict):
        self.base_url = base_url
        self.spec = spec
        self.servers = spec.get('servers')
        self.paths = spec['paths']
        self.components = spec['components']
        self.endpoints: list[Endpoint] = []

    @property
    def authorized_endpoints(self):
        if "securitySchemes" not in self.components:
            return []
        # If the spec doesn't have a global security requirement,
        # we filter for endpoints with a declared security scheme
        if "security" not in self.spec:
            return [
                endpoint for endpoint in self.endpoints
                if endpoint.security is not None and len(endpoint.security) > 0
            ]
        # If the spec has a global security requirement, we filter out
        # endpoints that override the global requirement with an empty
        # object or an empty array
        return [
            endpoint for endpoint in self.endpoints
            if endpoint.security is None or len(endpoint.security) > 0
        ]

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
                        body=self.resolve_body(self.paths[path][method].get('requestBody')),
                        responses=self.paths[path][method].get('responses'),
                        security=self.paths[path][method].get('security'),
                    )
                )

    def resolve_body(self, body: dict | None):
        if body is None:
            return

        if body.get('content') is None:
            return

        # we only support application/json atm
        if body['content'].get('application/json') is None:
            return

        if '$ref' in body['content']['application/json']['schema']:
            schema = self.resolve_schema(body['content']['application/json']['schema']['$ref'])
            body['content']['application/json']['schema'] = schema

        if 'allOf' in body['content']['application/json']['schema']:
            for index, schema in enumerate(body['content']['application/json']['schema']['allOf']):
                if '$ref' in schema:
                    schema = self.resolve_schema(schema['$ref'])
                    body['content']['application/json']['schema']['allOf'][index] = schema

        if 'anyOf' in body['content']['application/json']['schema']:
            for index, schema in enumerate(body['content']['application/json']['schema']['anyOf']):
                if '$ref' in schema:
                    schema = self.resolve_schema(schema['$ref'])
                    body['content']['application/json']['schema']['anyOf'][index] = schema

        return body

    def resolve_schema(self, schema_ref):
        schema_name = schema_ref.split('/')[-1]
        schema = self.spec['components']['schemas'][schema_name]

        if 'allOf' in schema:
            raise Exception('allOf not implemented')

        if 'anyOf' in schema:
            raise Exception('anyOf not implemented')

        for name, description in schema['properties'].items():
            if '$ref' in description:
                property_schema = self.resolve_schema(description['$ref'])
                schema['properties'][name] = property_schema
                continue

            if description['type'] == 'array' and '$ref' in description['items']:
                items_schema = self.resolve_schema(description['items']['$ref'])
                description['items'] = items_schema

        return schema
