import random
from dataclasses import dataclass
from typing import List, Callable, Optional

import click
import requests

from .api_spec import APISpec
from .test_case import AttackStrategy, TestDescription, HTTPMethods, TestCase, TestResult, \
    VulnerabilitySeverityLevel

@dataclass
class JWTTestEndpoint:
    endpoint: Endpoint
    fake_param_strategy: Optional[Callable] = None
    jwt_generation_strategy: Optional[Callable] = None

    def __post_init__(self):
        self.fake_param_strategy = self.fake_param_strategy or default_fake_param_strategy
        self.jwt_generation_strategy = self.jwt_generation_strategy or default_jwt_generation_strategy

    def generate_unsafe_jwt_payload(self):
        # 使用所選策略生成不安全的 JWT 載荷
        return self.jwt_generation_strategy()

    def get_unsafe_url_with_jwt(self, jwt: str):
        # 生成帶有不安全 JWT 的 URL
        url = self.endpoint.safe_url  # 此處可能需要修改 URL 的結構
        return url
class JWTTestCaseRunner:
    def __init__(self, test_case: TestCase):
        self.test_case = test_case
        self.response = None

    def run(self):
        # 發送帶有不安全 JWT 的請求
        pass

    def resolve_test_result(self):
        # 解析測試結果，檢查 JWT 相關的漏洞
        pass
class JWTTestRunner:
    def __init__(self, api_spec: APISpec):
        self.api_spec = api_spec
        self.jwt_tests = 0
        self.reports = []

    def test_jwt_security(self):
    self.jwt_tests = 0  # 重新初始化 jwt_tests，用於統計測試數量
    self.reports = []  # 重新初始化 reports，用於儲存測試報告

    failing_tests = []  # 創建一個空列表，用於儲存測試失敗的案例

    # 迭代 API 的所有端點
    for endpoint in self.api_spec.endpoints:
        jwt_test = JWTTestEndpoint(endpoint)  # 創建 JWT 測試端點

        endpoint_failing_tests = []  # 創建一個空列表，用於儲存該端點內測試失敗的案例

        # 生成帶有不安全 JWT 的 URL
        jwt_payload = jwt_test.generate_unsafe_jwt_payload()
        jwt_url = jwt_test.get_unsafe_url_with_jwt(jwt_payload)

        self.jwt_tests += 1  # 增加 JWT 測試數量計數

        # 創建 JWT 測試案例
        test_case = JWTTestCaseRunner(
            test_case=TestCase(
                category=AttackStrategy.JWT,
                test_target="jwt_security_test",
                description=TestDescription(
                    http_method=getattr(HTTPMethods, endpoint.method.upper()),
                    url=jwt_url, base_url=endpoint.base_url, path=endpoint.path.path,
                    payload=endpoint.generate_safe_request_payload() if endpoint.has_request_payload() else None,
                )
            )
        )
        test_case.run()  # 執行 JWT 測試案例

        if test_case.test_case.result == TestResult.FAIL:
            endpoint_failing_tests.append(test_case.test_case)  # 如果測試案例失敗，將其添加到端點內的失敗案例列表

        if len(endpoint_failing_tests) > 0:
            failing_tests.extend(endpoint_failing_tests)  # 如果該端點有測試失敗的案例，將其添加到測試失敗的列表中

    return failing_tests  # 返回測試失敗的案例列表

