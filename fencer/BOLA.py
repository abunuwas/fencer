import random
import re
from dataclasses import dataclass
from typing import List, Callable, Optional

import click
import requests

from .api_spec import APISpec
from .test_case import TestResult, TestCase, AttackStrategy, TestDescription, HTTPMethods,\
      VulnerabilitySeverityLevel

standard_http_methods = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head']

table_2_parameters_properties = {
     'path': {
        'description': 'Parameters in the path of the URI.',
        'vulnerabilities': ['BOLA']
    },
    'query': {
        'description': 'Parameters in the query string of the URI.',
        'vulnerabilities': ['BOLA']
    },
    'body': {
        'description': 'Parameters in the JSON body of the request.',
        'vulnerabilities': ['BOLA']
    },
    'header': {
        'description': 'Parameters in the request header.',
        'vulnerabilities': ['BOLA']
    }
}

class TestBOLA:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
        self.paths = api_spec.paths
        
    def is_identifier(self,parameter): # If parameter is_identifier then return True else return False
        if parameter.get('in') == 'path' and parameter.get('require',True):
            return True
        return False
        
    def check_authorization(self,operation_dict):
        if len(operation_dict.get('security')) > 0:
            return True
        return False
    
    def only_operation_parameters(self,operation_dict):
        paramters = operation_dict.get('parameters',[])
        request_body = operation_dict.get('requestBody', {})
        if paramters and not request_body:
            return True
        return False


    def annotate_with_parameters_table2_properties(self,item):
        if 'in' in item:
            parameter_location = item['in']
        parameter_level_properties = {
            'is_identifier':self.is_identifier(item),
            'Location':parameter_location,
            'type':item['schema']['type']
        }
        item['Parameter-level-properties'] = parameter_level_properties
        return item
    
    def annotate_with_operation_table2_properties(self,operation_dict):
        parameter:dict
        if 'parameters' in operation_dict:
            parameter = operation_dict['parameters']
            if self.is_identifier(parameter):
                identified = 'single'
            else:
                identified = 'Zero'

        method_level_properties = {
            'operation_only_parameters_specified':self.only_operation_parameters(operation_dict),
            'parameter_required':parameter.get('require'),
            'has_body':'requestBody' in operation_dict,
            'identifier_used':identified,
            'authorization_required':self.check_authorization(operation_dict)
        }
        operation_dict['method_level_properties'] = method_level_properties

    def properties_analyzer(self):
        if 'securitySchemes' in self.api_spec.components: # 如果有Security authorization
            if self.paths:    #api_spc是否有Paths屬性
                for path,path_data in self.paths.items(): # path代表API端點，而path_data代表此端點所包含的物件和屬性
                    #print(path)
                    if 'parameters' in path_data:
                        for parameters in path_data['parameters']:
                          annotate_parameters = self.annotate_with_parameters_table2_properties(parameters)
                          #print(annotate_parameters)
                    #print(path_data.keys())
                    
                    for method in path_data: # Get path_data keys about http_method
                        #print(method)
                        if method in standard_http_methods: # 檢查path item是否有operation物件(GET、POST,etc)
                            operation_dict = path_data[method]
                            self.annotate_with_operation_table2_properties(operation_dict)
                            if 'parameters' in operation_dict:
                                parameters = operation_dict['parameters']
                                self.annotate_with_parameters_table2_properties(parameters)
            else:
                print("No paths object")
        else:
            return
        
    def attack_analyzer(self):
        pass