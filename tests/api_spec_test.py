from pathlib import Path

import pytest
import yaml

from fencer.api_spec import APISpec, BasicEndpoint, Endpoint, APIPath


@pytest.fixture
def orders_spec():
    return yaml.safe_load((Path(__file__).parent / 'orders_api_spec.yaml').read_text())


def test_load_endpoints(orders_spec):
    api_spec = APISpec(spec=orders_spec, base_url='')
    api_spec.load_endpoints()
    spec_endpoints = [
        endpoint.endpoint for endpoint in api_spec.endpoints
    ]
    expected_endpoints = [
        BasicEndpoint(method='get', path='/orders', base_url=''),
        BasicEndpoint(method='post', path='/orders', base_url=''),
        BasicEndpoint(method='get', path='/orders/{order_id}', base_url=''),
        BasicEndpoint(method='put', path='/orders/{order_id}', base_url=''),
        BasicEndpoint(method='delete', path='/orders/{order_id}', base_url=''),
        BasicEndpoint(method='post', path='/orders/{order_id}/cancel', base_url=''),
    ]
    assert len(expected_endpoints) == len(spec_endpoints)
    for endpoint in expected_endpoints:
        assert endpoint in spec_endpoints


def test_capture_undocumented_path_parameter():
    path = '/orders/{order_id}/cancel/{something_else}/path/{somethingSomething}'
    path_obj = APIPath(path=path)
    undocumented_params = ['order_id', 'something_else', 'somethingSomething']
    for param in undocumented_params:
        assert param in path_obj.undocumented_path_params


def test_produce_safe_path_with_undocumented_path_param():
    path = '/orders/{order_id}'
    path_obj = APIPath(path=path)
    safe_path = path_obj.build_safe_path(fake_param_strategy=lambda _: 'something')
    assert safe_path == '/orders/something'


def test_produce_safe_path_with_documented_path_param():
    path = '/orders/{order_id}'
    path_obj = APIPath(path=path, path_params_schemas=[{'name': 'order_id', 'schema': {'type': 'integer'}}])
    safe_path = path_obj.build_safe_path()
    param_value = safe_path.split('/')[-1]
    assert param_value.isdigit()


def test_produce_safe_query_param_value():
    path = '/orders'
    endpoint = Endpoint(
        base_url='', method='', responses={}, api_path=path,
        parameters=[{'name': 'order_id', 'schema': {'type': 'integer'}, 'in': 'query', 'required': True}]
    )
    safe_url = endpoint.safe_url_path_with_safe_required_query_params
    query_param_value = safe_url.split('?')[-1].split('=')[-1]
    assert query_param_value.isdigit()


def test_resolve_component(orders_spec):
    api_spec = APISpec(spec=orders_spec, base_url='')
    component = api_spec.resolve_schema(schema_ref='#/components/schemas/OrderItemSchema')
    expected = {
        'type': 'object',
        'required': ['product', 'size'],
        'properties': {
            'product': {'type': 'string'},
            'size': {'type': 'string', 'enum': ['small', 'medium', 'big']},
            'quantity': {'type': 'integer', 'format': 'int64', 'default': 1, 'minimum': 1}
        }
    }
    assert component == expected


def test_resolve_anyof_component():
    spec = {
        'paths': [],
        'components': {
            'schemas': {
                'ComponentA': {
                    'type': 'object',
                    'properties': {'property_a': {'type': 'string'}},
                },
                'ComponentB': {
                    'type': 'object',
                    'properties': {'property_b': {'type': 'string'}},
                },
                'ComponentC': {
                    'type': 'object',
                    'properties': {},
                    'anyOf': [
                        {'$ref': '#/components/schemas/ComponentA'},
                        {'$ref': '#/components/schemas/ComponentB'},
                    ]
                }
            }
        }
    }
    api_spec = APISpec(spec=spec, base_url='')
    component = api_spec.resolve_schema(schema_ref='#/components/schemas/ComponentC')
    expected = {
        'type': 'object',
        'properties': {},
        'anyOf': [
            {
                'type': 'object',
                'properties': {'property_a': {'type': 'string'}},
            },
            {
                'type': 'object',
                'properties': {'property_b': {'type': 'string'}},
            }
        ]
    }
    assert component == expected


def test_resolve_allof_component():
    spec = {
        'paths': [],
        'components': {
            'schemas': {
                'ComponentA': {
                    'type': 'object',
                    'properties': {'property_a': {'type': 'string'}},
                },
                'ComponentB': {
                    'type': 'object',
                    'properties': {'property_b': {'type': 'string'}},
                },
                'ComponentC': {
                    'type': 'object',
                    'properties': {},
                    'allOf': [
                        {'$ref': '#/components/schemas/ComponentA'},
                        {'$ref': '#/components/schemas/ComponentB'},
                    ]
                }
            }
        }
    }
    api_spec = APISpec(spec=spec, base_url='')
    component = api_spec.resolve_schema(schema_ref='#/components/schemas/ComponentC')
    expected = {
        'type': 'object',
        'required': [],
        'properties': {
            'property_a': {'type': 'string'},
            'property_b': {'type': 'string'},
        },
        'allOf': [
            {'$ref': '#/components/schemas/ComponentA'},
            {'$ref': '#/components/schemas/ComponentB'},
        ],
    }
    assert component == expected
