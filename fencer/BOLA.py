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
"""
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
"""
class TestBOLA:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
        self.paths = api_spec.paths

    def has_require(self,parameter):
        if not parameter or parameter.get('require') == 'false':
            return False
        return True
    
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
    
    def annotate_with_operation_table2_properties(self,operation_dict,parameter):
       
        if self.is_identifier(parameter):
            identified = 'single'
        else:
            identified = 'Zero'

        method_level_properties = {
            'operation_only_parameters_specified':self.only_operation_parameters(operation_dict),
            'parameter_required':self.has_require(parameter),
            'has_body':'requestBody' in operation_dict,
            'identifier_used':identified,
            'authorization_required':self.check_authorization(operation_dict)
        }
        operation_dict['method_level_properties'] = method_level_properties
        return operation_dict
    
    def annotate_with_endpoint_table2_properties(self,count,path_data):
        if count == len(standard_http_methods):
            http_method_quantity = 'All'
        elif count > 1:
            http_method_quantity = 'Multiple'
        elif count == 1:
            http_method_quantity = 'Single'
        else:
            http_method_quantity = 'Empty'

        endpoint_level_properties = {
            'defined_http_verbs':http_method_quantity
        }
        path_data['endpoint_level_properties'] = endpoint_level_properties
        return path_data


    def properties_analyzer(self):
        if 'securitySchemes' in self.api_spec.components: # 如果有Security authorization
            if self.paths:    #api_spc是否有Paths屬性
                for path,path_data in self.paths.items(): # path代表API端點，而path_data代表此端點所包含的物件和屬性
                    if 'parameters' in path_data:
                        for parameters in path_data['parameters']:
                            self.annotate_with_parameters_table2_properties(parameters)
                    count = 0 # About endpoint http method quantity
                    for method in path_data: # Get path_data keys about http_method
                        if method in standard_http_methods: # 檢查path item是否有operation物件(GET、POST,etc)
                            count += 1
                            operation_dict = path_data[method]
                            if 'parameters' in operation_dict:
                                for parameters in operation_dict['parameters']:
                                    annotate_operation = self.annotate_with_operation_table2_properties(operation_dict,parameters)
                                    self.annotate_with_parameters_table2_properties(parameters)
                            else:
                                continue
                    annotate_path_data = self.annotate_with_endpoint_table2_properties(count,path_data)
                return annotate_path_data
            else:
                print("No paths object")
        else:
            return
        
    def attack_analyzer(self):
        annotate_API_specification = self.properties_analyzer() # 取得經由BOLA/IDOR_properites_analyzer標記過後的API規範檔
        #print(annotate_API_specification)
        