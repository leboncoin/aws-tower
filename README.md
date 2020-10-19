# AWS Tower

## Prerequisites

```bash
$ pip install -r requirements.txt
$ cp config/rules.json.sample config/rules.json # if you want to use --security feature
```

## Usage

```bash
$ ./aws_tower_cli.py --help
usage: aws_tower_cli.py [-h] [--version] [-a ACCOUNT] [--even-private] [-n] [--ec2] [--elbv2] [--rds] [--hide-sg] [-s] [--min_severity MIN_SEVERITY] [--max_severity MAX_SEVERITY]

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -a ACCOUNT, --account ACCOUNT
                        Account Name (default: None)
  --even-private        Display public and private assets (default: False)
  -n, --names-only      Display only names (default: False)
  --ec2                 Display EC2 (default: False)
  --elbv2               Display ELBV2 (default: False)
  --rds                 Display RDS (default: False)
  --hide-sg             Hide Security Groups (default: False)
  -s, --security        Check security issues on your services (default: False)
  --min_severity MIN_SEVERITY
                        min severity level to report when security is enabled (['info', 'low', 'medium', 'high', 'critical']) (default: info)
  --max_severity MAX_SEVERITY
                        max severity level to report when security is enabled (['info', 'low', 'medium', 'high', 'critical']) (default: critical)
```

## Usage (lambda)

```bash
$ pip install -r requirements.txt --target ./package

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
      "type": "in" (not_in, is_cidr, is_private_cidr, type_regex),
      "value": "all",
      "variable": "ports"
  }, {
    ...
  }],
  "severity": "high" (info, medium, high, critical)
}
```

### Types

Types already presents:

- in: check if `value` is in `variable`
- not_in: check if `value` is not in `variable`
- is_cidr: check if `source` is a CIDR (example: `0.0.0.0/0` is a valid cidr).
- is_private_cidr: check if `source` is a private CIDR (rfc 1918)
- type_regex: check if `ports` is a valid type (like `port_range`)

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
