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
attack_vector_pattern = {
    'Enumeration':
    {
        'without_prior_knowledge':
        {
            'description':'Identifier is tampered for enumeration based on automatically or semiautomatically determined pattern',
            'condition':
            {
                'parameter_type':'integer',
                'uses_authorization':True,
                'parameter_not_empty':True,
                'number_of_identifier/parameter':'Single'
            }
        },
        'with_prior_knowledge':
        {
            'condition':
            {
                'parameter_type':'UUID',
                'uses_authorization':True,
                'parameter_not_empty':True,
                'number_of_identifier/parameter':'Single'
            }
        },
        'Add/Change_file_extension':
        {
            'condition':
            {
                'parameter_type':'string',
                'uses_authorization':True,
                'parameter_not_empty':True,
                'number_of_identifier/parameter':'Single'
            }
        },
        'Wildcard(*,%)replacement/appending':
        {
            'condition':
            {
                'parameter_type':'string',
                'uses_authorization':True,
                'parameter_not_empty':True,
                'number_of_identifier/parameter':'Single'
            }
        },
        'ID_encoding/decoding':
        {
            'condition':
            {
                'uses_authorization':True,
                'parameter_not_empty':True,
                'number_of_identifier/parameter':'Single'
            }
        },
        'JSON(List)appending':
        {
            'condition':
            {
                'parameter_type':'array',
                'uses_authorization':True,
                'parameter_not_empty':True,
                'number_of_identifier/parameter':'Single'
            }
        }
    },
    'Authorization_token_manipulation':
    {
        'Authorization_token_manipulation':
        {
            'condition':
            {
                'uses_authorization':True
            }
        }
    },
    'Parameter_pollution':
    {
        'Parameter_pollution':
        {
            'condition':
            {
                'Location_num':'Multiple', # If parameter have same name and location type is difference,then that location_num is multiple.
                'uses_authorization':True,
                'number_of_identifier/parameter':'Multiple'
            }
        }
    },
    'Endpoint_verb_tampering':
    {
        'Adding_parameters_used_in_other_HTTP_Methods':
        {
            'condition':
            {
                'endpoint_properties_value':'Multiple',
                'uses_authorization':True,
            }
        },
        'Change_HTTP_Method(Verb_tampering)':
        {
            'description':"Request's verb is changed to another verb that is notspecified in the endpoint's description.",
            'condition':
            {
                'endpoint_properties_value':'All',
                'number_of_identifier/parameter':'Single'
            }
        }
    }
}
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
        item['Parameter_level_properties'] = parameter_level_properties
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
    
    def parameter_location_num(self):# If parameter have same name and location type is difference,then that location_num is multiple.
        pass

    def check_condition(self,attack_vector_pattern,endpoint_data,parameter_data,method_data):
        for attack_vector,techniques in attack_vector_pattern.items(): # iterator key e.g(Enumeration,Authorization_token_manipulation,...)
            #print(attack_vector," ",techniques)
            for techniques,techniques_info in techniques.items():
                #print(techniques," ",techniques_info)
                #if endpoint_data['defined_http_verbs'] == 
                
                if techniques_info['condition']['uses_authorization'] == method_data['authorization_required']:
                    if parameter_data and techniques_info['condition']['parameter_not_empty']: # If contain parameter
                        pass
                else:
                    return 

    def properties_analyzer(self):
        annotated_paths = {}
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
                                    self.annotate_with_operation_table2_properties(operation_dict,parameters)
                                    self.annotate_with_parameters_table2_properties(parameters)
                            else:
                                continue
                    annotate_path_data = self.annotate_with_endpoint_table2_properties(count,path_data)
                    annotated_paths[path] = annotate_path_data
                return annotated_paths
            else:
                print("No paths object")
        else:
            return {}
        
    def attack_analyzer(self):
        annotate_API_specification = self.properties_analyzer() # 取得經由BOLA/IDOR_properites_analyzer標記過後的API規範檔
        for path,path_data in annotate_API_specification.items():
            endpoint_data = path_data.get('endpoint_level_properties')
            for method in path_data:
                if method in standard_http_methods:
                    operation_dict = path_data[method]
                if 'method_level_properties' in operation_dict:
                    method_data = operation_dict['method_level_properties']
                else:
                    continue
                if 'parameters' in operation_dict:
                    for parameters in operation_dict['parameters']:
                        parameter_data = parameters['Parameter_level_properties']
                else:
                    continue
                if endpoint_data and parameter_data and method_data:
                    self.check_condition(attack_vector_pattern,endpoint_data,parameter_data,method_data)
                else:
                    print('Not contain endpoint_data or parameter_data or method_data')