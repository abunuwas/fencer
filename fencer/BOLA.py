import random
import re
from dataclasses import dataclass
from typing import List, Callable, Optional

import click
import requests

from .api_spec import Endpoint, fake_parameter, APISpec
from .test_case import TestResult, TestCase, AttackStrategy, TestDescription, HTTPMethods, VulnerabilitySeverityLevel

class TestBOLA:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec

    def properties_analyzer(self):
        if self.api_spec.authorized_endpoints(): # 如果有Security authorization
            if self.api_spec.paths:    #api_spc是否有Paths屬性
                for path in self.api_spec.paths:
                    pass
            else:
                return 
        else:
            return
    def attack_analyzer(self):
        pass