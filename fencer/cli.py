import json
import time
from pathlib import Path

import click
from colorama import init as colorama_init, Fore

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

    # consider yaml specs too
    spec = json.loads(Path(oas_file).read_text())
    api_spec = APISpec(base_url=base_url, spec=spec)
    api_spec.load_endpoints()

    colorama_init(autoreset=True)

    test_runner = TestRunner(api_spec=api_spec)

    injection_message = """
  -------------------------
  Testing injection attacks
  -------------------------"""
    click.echo(injection_message)

    test_runner.run_sql_injection_attacks()

    print(Fore.YELLOW + f'Total tests: {test_runner.injection_tests}')


if __name__ == "__main__":
    cli()
