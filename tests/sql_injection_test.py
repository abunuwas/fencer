from fencer.api_spec import Endpoint
from fencer.sql_injection import SQLInjectionEndpoint


def test_generate_unsafe_required_query_params():
    path = '/orders'
    endpoint = Endpoint(
        base_url='', method='', responses={}, api_path=path,
        parameters=[{'name': 'order_id', 'schema': {'type': 'string'}, 'in': 'query', 'required': True}]
    )
    sql_injection = SQLInjectionEndpoint(endpoint=endpoint, sql_injection_strategies=['drop table users;'])
    injection_url = sql_injection.get_safe_url_path_with_unsafe_required_query_params()
    assert injection_url == ['/orders?order_id=drop table users;']


def test_generate_unsafe_optional_query_params():
    path = '/orders'
    endpoint = Endpoint(
        base_url='', method='', responses={}, api_path=path,
        parameters=[{'name': 'order_id', 'schema': {'type': 'string'}, 'in': 'query', 'required': False}]
    )
    sql_injection = SQLInjectionEndpoint(endpoint=endpoint, sql_injection_strategies=['drop table users;'])
    injection_url = sql_injection.get_safe_url_path_with_unsafe_optional_query_params()
    assert injection_url == ['/orders?order_id=drop table users;']


def test_generate_unsafe_url_without_optional_query_params():
    path = '/orders/{order_id}'
    endpoint = Endpoint(
        base_url='', method='', responses={}, api_path=path,
        parameters=[{'name': 'order_id', 'schema': {'type': 'string'}, 'in': 'path', 'required': True}]
    )
    sql_injection = SQLInjectionEndpoint(endpoint=endpoint, sql_injection_strategies=['drop table users;'])
    injection_url = sql_injection.get_unsafe_url_path_without_query_params()
    assert injection_url == ['/orders/drop table users;']


def test_generate_unsafe_url_with_safe_required_params():
    path = '/orders/{order_id}'
    endpoint = Endpoint(
        base_url='', method='', responses={}, api_path=path,
        parameters=[
            {'name': 'order_id', 'schema': {'type': 'string'}, 'in': 'path', 'required': True},
            {'name': 'something', 'schema': {'type': 'string'}, 'in': 'query', 'required': True},
        ]
    )
    sql_injection = SQLInjectionEndpoint(
        endpoint=endpoint,
        fake_param_strategy=lambda _: 'else',
        sql_injection_strategies=['drop table users;'],
    )
    injection_url = sql_injection.get_unsafe_url_path_with_safe_required_query_params()
    assert injection_url == ['/orders/drop table users;?something=else']


def test_generate_unsafe_request_payload():
    path = '/orders/{order_id}'
    endpoint = Endpoint(
        base_url='', method='', api_path=path,
        body={
            'content': {
                'application/json': {
                    'schema': {
                        'type': 'object',
                        'required': ['a'],
                        'properties': {
                            'a': {'type': 'string'},
                        }
                    }
                }
            }
        }
    )
    sql_injection = SQLInjectionEndpoint(
        endpoint=endpoint, sql_injection_strategies=['drop table users;']
    )
    injection_payload = sql_injection.generate_unsafe_request_payload()
    assert injection_payload == {'a': 'drop table users;'}
