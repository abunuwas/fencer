import re
from dataclasses import dataclass

from jsf import JSF

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
        # here rather than safe query params what we have is random query params values
        # given by hypothesis, which isn't always the safest values so works for security test.
        # since we're testing security I guess we don't really need to bother much with sending
        # safe requests
        return (
                self.safe_url_path_without_query_params + '?'
                + '&'.join(f"{param['name']}={JSF(param['schema']).generate()}"
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
        if self.has_required_query_params():
            return (
                self.safe_url_path_with_safe_required_query_params + '?'
                + '&'.join(f"{param['name']}={JSF(param['schema']).generate()}"
                           for param in self.optional_query_params)
            )
        return (
                self.safe_url_path_without_query_params + '?'
                + '&'.join(f"{param['name']}={JSF(param['schema']).generate()}"
                           for param in self.optional_query_params)
        )

    @property
    def safe_url_path_with_unsafe_optional_query_params(self):
        if self.has_required_query_params():
            return (
                    self.safe_url_path_with_safe_required_query_params + '?'
                    + '&'.join(f"{param['name']}={dangerous_sql}" for param in self.optional_query_params)
            )
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
                + '&'.join(f"{param['name']}={JSF(param['schema']).generate()}"
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
        if self.has_required_query_params():
            return (
                    self.unsafe_url_path_with_safe_required_query_params + '?'
                    + '&'.join(f"{param['name']}={JSF(param['schema']).generate()}"
                               for param in self.optional_query_params)
            )
        return (
                self.unsafe_url_path_without_query_params + '?'
                + '&'.join(f"{param['name']}={JSF(param['schema']).generate()}"
                           for param in self.optional_query_params)
        )

    @property
    def unsafe_url_path_with_unsafe_optional_query_params(self):
        if self.has_required_query_params():
            return (
                    self.unsafe_url_path_with_safe_required_query_params + '?'
                    + '&'.join(f"{param['name']}={dangerous_sql}" for param in self.optional_query_params)
            )
        return (
                self.unsafe_url_path_without_query_params + '?'
                + '&'.join(f"{param['name']}={dangerous_sql}" for param in self.optional_query_params)
        )

    @property
    def safe_url(self):
        return self.safe_url_path_with_safe_required_query_params

    def get_urls_with_unsafe_query_params(self):
        urls = []
        if self.has_required_query_params():
            urls.append(self.safe_url_path_with_unsafe_required_query_params)
        if self.has_optional_query_params():
            urls.append(self.safe_url_path_with_unsafe_optional_query_params)
        for url in urls:
            yield url

    def get_urls_with_unsafe_path_params(self):
        urls = []
        if self.path.has_path_params():
            urls.append(self.unsafe_url_path_without_query_params)
            if self.has_required_query_params():
                urls.append(self.unsafe_url_path_with_safe_required_query_params)
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
                JSF(param['schema']).generate(),
            )

        if not self.has_undocumented_path_params():
            return path

        for param in self._undocumented_path_params:
            path = path.replace(
                f'{{{param["name"]}}}',
                JSF({'type': 'string'}).generate(),
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
        self.endpoints: list[Endpoint] = []

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
                        responses=self.paths[path][method]['responses']
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
