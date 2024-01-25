import random
import re
from dataclasses import dataclass
from typing import List, Callable, Optional

import click
import requests

from .api_spec import APISpec
from .test_case import TestResult, TestCase, AttackStrategy, TestDescription, HTTPMethods,\
      VulnerabilitySeverityLevel

class TestMAEndpoints:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
    def test_MA_endpoints(self):
        pass