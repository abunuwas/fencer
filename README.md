# Fencer

[![pypi](https://img.shields.io/pypi/v/fencer.svg)](https://pypi.python.org/pypi/fencer)
[![versions](https://img.shields.io/pypi/pyversions/fencer.svg)](https://github.com/abunuwas/fencer)

Automated API security testing tool. 

**DO NOT run this against production!!**

Fencer is an automated API security testing tool. It's an experimental project to see how much of the API
security testing process can be automated. I believe that API security testing requires a holistic approach. 
An API is part of a bigger system, and the security configuration of the whole system affects the security of 
the API. However, it's also true that many security tests on APIs are easy to formalize and hence automate. The 
goal of this project is to capture all those formal test cases.

The starting point is the [OWASP Top 10 API Security Threats](https://owasp.org/www-project-api-security/) 
checklist. The goal is to create automated tests for each of those threats. Once we've covered OWASP, the goal
is to move beyond the checklist and add more tests for all sorts of common API security vulnerabilities. If you 
have suggestions about cases that should be covered and don't appear in the OWASP checklist, please raise an issue!

Use fencer responsibly. I suggest running fencer against development environments, or even better, against 
ephemeral environments in which you can do no harm to your systems. I'd generally advise against running fencer 
directly against production.  

---

## Limitations

Fencer is still pretty much work in progress. I'm adding new features every day, but there's still a long way to go.
I very much welcome contributions to make progress faster. At the moment, these are the most important limitations:

* Only works with Python 3.10 and upwards for now
* Only works with API specifications available as local files in JSON or YAML
* Only works with OpenAPI 3.X.X and probably has missing features
* A lot of tests are missing, e.g. noSQL injection, command injection, JWT tests, and so on. I'll include them as 
  soon as I can.
* The CLI is super simple at the moment but will soon get better.
* Failing tests are stored under a folder named `.fencer/` relative to the directory from which you run the tool.
  As soon as I can, I'll add commands to work with those tests and be able to visualise them and storage will be
  optional too.

## Requirements

Python 3.10+

## Installation

To install fencer, run the following command: 

```bash
$ pip install -U fencer
```

## Running fencer

After installation, you can run fencer directly from the command line. The basic test suite runs like this:

```bash
$ fencer --oas-file <path_to_openapi_spec> --base-url <base_url>
```

Replace `<path_to_openapi_spec>` with the path to the OpenAPI specification for your API in your local machine.
It only works with JSON specs at the moment. Replace also `<base_url>` with the base URL of the server you want
to test against.

For example:

```bash
$ fencer run --oas-file openapi.json --base-url http://localhost:5000
```

![image info](https://github.com/abunuwas/fencer/blob/742b9dd62bae3dadd838b7085336da7cdc98a06b/img/fencer_demo.gif)

## Contributing

Clone the repository and install it locally by running:

```bash
$ pipenv install -e .
```

I'm just getting started with this project, and I could use some help! I'll be uploading a contribution guideline
in the coming days, but if you have suggestions in the meantime, please raise an issue and let's have a chat!
