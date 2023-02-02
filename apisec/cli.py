import json
from pathlib import Path

import click
from colorama import init as colorama_init, Fore

from main import APISpec, call_endpoint


@click.group()
def run_test_group():
    """Run the security test suite"""
    pass


@run_test_group.command()
@click.option('--oas-file', type=click.Path(exists=True))
@click.option('--base-url', type=click.STRING)
def run(oas_file, base_url):
    # consider yaml specs too
    spec = json.loads(Path(oas_file).read_text())
    api_spec = APISpec(base_url=base_url, spec=spec)
    api_spec.load_endpoints()

    colorama_init(autoreset=True)

    counter = 0

    for endpoint in api_spec.endpoints:
        for url in endpoint.get_urls():
            counter += 1
            print(Fore.GREEN + endpoint.method.upper(), Fore.GREEN + url)
            call_endpoint(url, endpoint)
            if endpoint.has_request_payload():
                counter += 1
                call_endpoint(url, endpoint, endpoint.generate_safe_request_payload())
                counter += 1
                call_endpoint(url, endpoint, endpoint.generate_unsafe_request_payload())

    print(Fore.YELLOW + f'Total tests: {counter}')


cli = click.CommandCollection(sources=[run_test_group])


if __name__ == "__main__":
    cli()
