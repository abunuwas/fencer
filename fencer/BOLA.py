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
            'description':'Identifier is tampered for enumeration based on automatically or semiautomatically determined pattern.'\
                          'In the simplest form,identifier is sequential and enumeration leads to targeting existing object with identifier being unknown at the start.',
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
            'description':"Targeted identifier structured in a way that it's hard to automatically enumerate it but still needed to check with a set of known identifiers of non-owned objects."\
                          "In combination with information disclosure vulnerability, impact of BOLA increases because an attacker would exploit vulnerability without bruteforcing techniques.",
            'condition':
            {
                'parameter_type':'string',
                'parameter_format':'uuid',
                'uses_authorization':True,
                'parameter_not_empty':True,
                'number_of_identifier/parameter':'Single'
            }
        },
        'Add/Change_file_extension':
        {
            'description':'A variation of enumeration when enumerated identifier is appended with an extension or changed to another extension.',
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
            'description':'A variation of enumeration when enumerated identifier is decorated with a wildcard or a special character.',
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
            'description':'A variation of enumeration when not only an encoded identifier is enumerated but a decoded identifier is substituted too.',
            'condition':
            {
                'uses_authorization':True,
                'parameter_not_empty':True,
                'number_of_identifier/parameter':'Single'
            }
        },
        'JSON(List)appending':
        {
            'description':"Parameter's type is array/list with one or few values and identifiers of non-owned objects are appended to that list to exploit improper access control.",
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
            'description':'Request is repeated with authorization cookies of another user to check whether authorization is incorrect.',
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
            'description':"Information in one request is processed and sent into different processing units of server."\
                          "Tampering with one of parameter's value is a way to check that authorization is consistent and "\
                          "there's no case that value from one location is used for authorization and value from another is used to access an object.",
            'condition':
            {
                'Location_num':'Multiple', # If parameter have same name but location type is difference,then that location_num is multiple.
                'uses_authorization':True,
                'number_of_identifier/parameter':'Multiple'
            }
        }
    },
    'Endpoint_verb_tampering':
    {
        'Adding_parameters_used_in_other_HTTP_Methods':
        {
            'description':'Authorization may be performed for a concrete verb and its parameters but service logic ignores requests verb',
            'condition':
            {
                'endpoint_properties_value':'Multiple',
                'uses_authorization':True,
            }
        },
        'Change_HTTP_Method(Verb_tampering)':
        {
            'description':"Request's verb is changed to another verb that is notspecified in the endpoint's description."\
                          "Incorrect behavior is when authorization checks are performed over described verbs and verb transformation is performed after authorization check (PUT->POST)",
            'condition':
            {
                'endpoint_properties_value':'Not_All',
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
            'type':item['schema']['type'],
            'format':item.get('schema').get('format',[])
        }
        item['Parameter_level_properties'] = parameter_level_properties
        return item
    
    def annotate_with_operation_table2_properties(self,operation_dict,parameter):
       
        if self.is_identifier(parameter):
            identified = 'Single'
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
        
    def parameter_location_num(self,operation_dict):# If parameter have same name and location type is difference,then that location_num is multiple.
        seen_parameters = {}
        location_num = 0
        for parameter in operation_dict.get('parameters',[]):
            parameter_name = parameter['name']
            parameter_location = parameter['in']
            if parameter_name in seen_parameters:   
                if seen_parameters[parameter_name] != parameter_location:
                    location_num += 1
            else:
                seen_parameters[parameter_name] = parameter_location
        return location_num

    def location_num_transfer(self,location_num):
        if location_num > 1:
            return 'Multiple'
        elif location_num == 1:
            return 'Single'
        else:
            return 'Empty'

    def check_condition(self,attack_vector_pattern,endpoint_data,parameter_data,method_data,location_num):
        attack_pattern = {}
        # check endpoint http method quantity
        for endpoint_key,endpoint_value in attack_vector_pattern['Endpoint_verb_tampering'].items():    
            if endpoint_data['defined_http_verbs'] == 'Multiple' and endpoint_value['condition']['endpoint_properties_value'] == 'Multiple':
                if method_data['authorization_required'] == endpoint_value['condition']['uses_authorization']:
                    attack_pattern.update({endpoint_key:endpoint_value['description']})
            elif endpoint_data['defined_http_verbs'] != 'All' and endpoint_value['condition']['endpoint_properties_value'] == 'Not_All':
                if method_data['identifier_used'] == endpoint_value['condition']['number_of_identifier/parameter']:
                    attack_pattern.update({endpoint_key:endpoint_value['description']})
        # check endpoint_method_parameter uses authorization,or not?
        for authorization_key,authorization_value in attack_vector_pattern['Authorization_token_manipulation'].items():
            if method_data['authorization_required'] == authorization_value['condition']['uses_authorization']:
                attack_pattern.update({authorization_key:authorization_value['description']})
        # check parameter have parameter_pollution Vulnerability?
        for parameter_key,parameter_value in attack_vector_pattern['Parameter_pollution'].items():
            if method_data['authorization_required'] == parameter_value['condition']['uses_authorization'] and \
            parameter_value['condition']['number_of_identifier/parameter'] == method_data['identifier_used'] and \
            parameter_value['condition']['Location_num'] == self.location_num_transfer(location_num):
                attack_pattern.update({parameter_key:parameter_value['description']})
        # check resource parameter can use enumeration attack?
        for enumeration_key,enumeration_value in attack_vector_pattern['Enumeration'].items():
            parameter_type = enumeration_value['condition'].get('parameter_type')
            if method_data['authorization_required'] == enumeration_value['condition']['uses_authorization'] and \
            (parameter_data and enumeration_value['condition']['parameter_not_empty']) and \
                method_data['identifier_used'] == enumeration_value['condition']['number_of_identifier/parameter']:
                    if parameter_type == parameter_data['type']:
                        attack_pattern.update({enumeration_key:enumeration_value['description']})
                    elif parameter_type == parameter_data['type'] and parameter_data['format'] == enumeration_value['condition']['format']:
                        attack_pattern.update({endpoint_key:enumeration_value['description']})
                    elif parameter_type == None:
                        attack_pattern.update({enumeration_key:enumeration_value['description']})
            else:
                continue

        return attack_pattern

    def properties_analyzer(self):
        annotated_paths = {}
        public_operation_dict = {}
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
                            public_operation_dict = operation_dict                          
                            if 'parameters' in operation_dict:
                                for parameters in operation_dict['parameters']:
                                    self.annotate_with_operation_table2_properties(operation_dict,parameters)
                                    self.annotate_with_parameters_table2_properties(parameters)
                            else: 
                                continue
                        else: # parameters not in http_method but have endpoint parameter.
                            for endpoint_parameter in path_data[method]:
                                self.annotate_with_operation_table2_properties(public_operation_dict,endpoint_parameter)
                    annotate_path_data = self.annotate_with_endpoint_table2_properties(count,path_data)
                    annotated_paths[path] = annotate_path_data
                return annotated_paths
            else:
                print("No paths object")
        else:
            return {}
        
    def attack_analyzer(self):
        annotate_API_specification = self.properties_analyzer() # 取得經由BOLA/IDOR_properites_analyzer標記過後的API規範檔
        All_endpoint_attack_pattern = {} # Store all checked endpoints in a dictionary
        Public_operation_dict = {}
        for path,path_data in annotate_API_specification.items():
            endpoint_data = path_data.get('endpoint_level_properties')
            for method in path_data:
                if method in standard_http_methods:
                    operation_dict = path_data[method]
                    Public_operation_dict = operation_dict
                    location_num = self.parameter_location_num(operation_dict)
                    if 'method_level_properties' in operation_dict:
                        method_data = operation_dict['method_level_properties']
                    else:
                        continue
                    if 'parameters' in operation_dict: # parameters in http_method 
                        for parameters in operation_dict['parameters']:
                            parameter_data = parameters['Parameter_level_properties']
                            if endpoint_data and parameter_data and method_data:
                                attack_pattern = self.check_condition(attack_vector_pattern,endpoint_data,parameter_data,method_data,location_num)
                                All_endpoint_attack_pattern.update({path:attack_pattern}) 
                            else:
                                print('Not contain endpoint_data or parameter_data or method_data')
                    else:
                        continue
                elif method == 'parameters': # parameters not in http_method
                    endpoint_parameters = path_data[method]
                    location_num = self.parameter_location_num(Public_operation_dict)
                    if 'method_level_properties' in Public_operation_dict:
                        method_data = Public_operation_dict['method_level_properties']
                    else:
                        continue

                    for value in endpoint_parameters:
                        if 'Parameter_level_properties' in value:
                            parameter_data = value['Parameter_level_properties']
                        else:
                            print('Not contain parameter_data')
                            continue

                    if endpoint_data and parameter_data and method_data:
                        attack_pattern = self.check_condition(attack_vector_pattern,endpoint_data,parameter_data,method_data,location_num)
                        All_endpoint_attack_pattern.update({path:attack_pattern})
                    else:
                        print('Not contain endpoint_data or parameter_data or method_data')
                else:
                    continue
        print(All_endpoint_attack_pattern)