import json
from pathlib import Path

import click
import yaml
from tabulate import tabulate

from .test_runner import TestRunner
from . import __version__
from .main import APISpec


@click.group()
@click.version_option(__version__)
def cli():
    pass


@cli.command()
@click.option('--oas-file', type=click.Path(exists=True))
@click.option('--base-url', type=click.STRING)
def run(oas_file, base_url):
    click.echo(click.style(f"Running Fencer {__version__}", fg="green"))
    click.echo(click.style(f"OpenAPI specification file: {oas_file}", fg="green"))
    click.echo(click.style(f"Base URL: {base_url}", fg="green"))

    if oas_file.endswith(".js"):
        spec = json.loads(Path(oas_file).read_text())
    elif oas_file.endswith(".yaml"):
        spec = yaml.safe_load(Path(oas_file).read_text())
    else:
        raise Exception("File format not supported!")
    api_spec = APISpec(base_url=base_url, spec=spec)
    api_spec.load_endpoints()

    test_runner = TestRunner(api_spec=api_spec)

    injection_message = """
  -------------------------
  Testing injection attacks
  -------------------------"""
    click.echo(injection_message)

    test_runner.run_sql_injection_attacks()

    click.echo()

    click.echo(click.style("  SUMMARY", fg="green"))

    click.echo()
    click.echo(click.style("> Number of tests", fg="yellow"))
    click.echo(tabulate({
        "Test Category": [report.category.value for report in test_runner.reports],
        "Number of tests": [report.number_tests for report in test_runner.reports],
        "Failing tests": [report.failing_tests for report in test_runner.reports]
    }, tablefmt="fancy_grid", headers=["Test category", "Number of tests", "Failing tests"]))

    click.echo()
    click.echo(click.style("> Vulnerabilities found by severity", fg="red"))
    click.echo(tabulate({
        "Test category": [report.category.value for report in test_runner.reports],
        "Low": [report.low_severity for report in test_runner.reports],
        "Medium": [report.medium_severity for report in test_runner.reports],
        "High": [report.high_severity for report in test_runner.reports],
    }, tablefmt="fancy_grid", headers=["Test category", "Low", "Medium", "High"]))


if __name__ == "__main__":
    cli()
