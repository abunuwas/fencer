import random
import re
from dataclasses import dataclass
from typing import List, Callable, Optional

import click
import requests

from .api_spec import Endpoint, fake_parameter, APISpec
from .test_case import TestResult, TestCase, AttackStrategy, TestDescription, HTTPMethods, VulnerabilitySeverityLevel

