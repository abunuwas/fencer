# CHANGELOG

## 0.3.5

* Update README

## 0.3.4

* Make sure .fencer folder is created

## 0.3.3

* Due to JSF we can only support Python from 3.10 upwards, so removing support for older versions.
  Looking to create custom faker to resolve this problem

## 0.3.2

* Fix compatibility with older versions of Python

## 0.3.1

* Add missing dependencies to pyproject.toml

## 0.3.0

* Add test runner for authorized endpoints access test
* Improve schema parsing and component resolving
* Refactor test case logic into its own module
* Add more SQL injection strategies
* Generate granular SQL injection attacks per operation per parameter

## 0.2.0

* Improve test logs during execution
* Save failed test cases to .fencer folder
* Add test report at the end of execution
* Add parsing for YAML specs

## 0.1.0

* First iteration of fencer
