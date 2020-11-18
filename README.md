# AWS Tower

## Prerequisites

```bash
$ pip install -r requirements.txt
$ cp config/rules.json.sample config/rules.json # if you want to use --security feature
```

## Usage

```bash
$ ./aws_tower_cli.py --help
usage: aws_tower_cli.py [-h] [--version] {discover,scan} ...

positional arguments:
  {discover,scan}  commands
    discover       Discover assets in an AWS account
    scan           Scan AWS account to find security issues

optional arguments:
  -h, --help       show this help message and exit
  --version        show program's version number and exit
```

```bash
$ ./aws_tower_cli.py discover --help
usage: aws_tower_cli.py discover [-h] [-t {EC2,ELBV2,RDS}] [--public-only] [--verbose] [--brief] account

positional arguments:
  account               Account Name

optional arguments:
  -h, --help            show this help message and exit
  -t {EC2,ELBV2,RDS}, --type {EC2,ELBV2,RDS}
                        Types to display (default: display everything)
  --public-only         Display public assets only
  --verbose             Verbose output of the account assets
  --brief               Brief output of the account assets
```

```bash
$ ./aws_tower_cli.py scan --help
usage: aws_tower_cli.py scan [-h] [-t {EC2,ELBV2,RDS}] [--min-severity {info,low,medium,high,critical}] [--max-severity {info,low,medium,high,critical}] [--verbose] [--brief]
                             account

positional arguments:
  account               Account Name

optional arguments:
  -h, --help            show this help message and exit
  -t {EC2,ELBV2,RDS}, --type {EC2,ELBV2,RDS}
                        Types to display (default: display everything)
  --min-severity {info,low,medium,high,critical}
                        min severity level to report when security is enabled (default: low)
  --max-severity {info,low,medium,high,critical}
                        max severity level to report when security is enabled (default: high)
  --verbose             Verbose output of the account assets
  --brief               Brief output of the account assets
```

## Usage (lambda)

```bash
$ pip install -r requirements.lambda.txt --target ./package

$ cp config/lambda.config.sample config/lambda.config
$ export PATROWL_APITOKEN=xxxxxxxxxxxxxxx
$ export PATROWL_ASSETGROUP=1
$ export PATROWL_PRIVATE_ENDPOINT=http://localhost/
$ export PATROWL_PUBLIC_ENDPOINT=http://localhost/

$ python -c 'import aws_tower_lambda; aws_tower_lambda.main()'
```

## Findings

Some rules already exists in `config/rules.json.sample`, but you can add your own too.

### Define finding

You need to add your findings in `config/rules.json` with the following format:
```json
{
  "message": {
      "text": "{arg1}: Your text ({arg2}, {arg3}), your text",
      "args": {
          "arg1": {
              "type": "dict",
              "key": "key_in_dict",
              "variable": "dict"
          }, "arg2": {
              "type": "var",
              "variable": "my_variable"
          }, "arg3": {
              "type": "var",
              "variable": "my_variable"
          }
      }
  },
  "rules": [{
      "type": "in" (not_in, is_cidr, is_private_cidr, ...),
      "description": "Check if variable_in is in value_in",
      "values": [
        {
          "type": "value",
          "name": "value_in",
          "value": "all"
        }
      ],
      "variables": [
        {
          "type": "var",
          "name": "variable_in",
          "value": "ports"
        }
      ]
  }, {
    ...
  }],
  "severity": "high" (info, medium, high, critical)
}
```

### Types

Types already presents:

- in: check if `value_in` is in `variable_in`
- not_in: check if `value_in` is not in `variable_in`
- is_cidr: check if `source` is a CIDR (example: `0.0.0.0/0` is a valid cidr).
- is_private_cidr: check if `source` is a private CIDR (rfc 1918)
- is_in_networks: check if `source` is one the networks in `networks`
- is_ports: check if source is a port or range ports (example: 9000-90001 is valid)
- engine_deprecated_version: check if `engine` version is higher than `versions`

To add a new type, you must define it in `libs/patterns.py` with the following format:

- The method name must be: `_check_rule_{type}` where **type** is the name you want (like `is_cidr`, `type_regex`, ...)
- Use 2 arguments for your method (will be changed in next update)

## Documentation

To generate the documentation:
```bash
$ cd docs && make html
```

To update the documentation:
```bash
$ sphinx-apidoc -o docs/source .
```

# License
Licensed under the [Apache License](https://github.com/leboncoin/aws-tower/blob/master/LICENSE), Version 2.0 (the "License").

# Copyright
Copyright 2020 Leboncoin
