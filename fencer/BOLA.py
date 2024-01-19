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
        
    def annotate_with_parameters_table2_properties(self,item,table_2_properties):
        if 'in' in item:
            parameter_location = item['in']
        parameter_level_properties = {
            'is_identifier':self.is_identifier(item),
            'Location':parameter_location,
            'type':item['schema']['type']
        }
        item['Parameter-level-properties'] = parameter_level_properties
        return item
    
    def annotate_with_operation_table2_properties(self,operation):
        pass

    def properties_analyzer(self):
        if 'securitySchemes' in self.api_spec.components: # 如果有Security authorization
            if self.paths:    #api_spc是否有Paths屬性
                for path,path_data in self.paths.items(): # path代表API端點，而path_data代表此端點所包含的物件和屬性
                    if 'parameters' in path_data:
                        for parameters in path_data['parameters']:
                          annotate_parameters = self.annotate_with_parameters_table2_properties(parameters,table_2_parameters_properties)
                          print(annotate_parameters)
                    """
                    if any(method in standard_http_methods for method in self.paths[path].keys()): # 檢查path item是否有operation物件(GET、POST,etc)
                        operation = self.paths[path].keys() # 取得Path中的Http_Method
                        if 'parameters' in operation:
                            parameters = path['parameters']
                            self.annotate_with_parameters_table_2_properties(parameters,table_2_parameters_properties)
                        else:
                            pass
                    """
            else:
                print("沒有paths物件")
        else:
            return
        
    def attack_analyzer(self):
        pass