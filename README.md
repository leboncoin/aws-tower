# AWS Tower

AWS Tower give the ability to discover and monitor AWS account to find vulnerabilities or misconfigurations.
Give also a brief overview for non-AWS expert.

Not related at all of the AWS Trusted Advisor.

AWS Services monitored:
- API Gateway
- CloudFront
- EC2
- EKS
- ALB/ELB
- IAM
- RDS
- S3
- VPC

## Prerequisites

```bash
$ pip install -r requirements.txt
$ cp config/rules.yaml.sample config/rules.yaml # if you want to use "audit"
$ cp config/subnet_allow_list.txt.sample config/subnet_allow_list.txt # if you want to use an allow list
```

## Usage

```bash
$ alias aws-tower='<path>/aws_tower_cli.py'
```

```bash
$ aws-tower --help
usage: aws_tower_cli.py [-h] [--version] [--no-color] [--no-cache] [--clean-cache] [-l] {discover,audit,iam} ...

positional arguments:
  {discover,audit,iam}  commands
    discover            Discover assets in an AWS account
    audit               Audit AWS account to find security issues
    iam                 Display IAM info for an AWS account

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --no-color            Disable colors
  --no-cache            Disable cache
  --clean-cache         Erase current cache by a new one
  -l, --layer           [BETA] Generate a layer for the ATT&CK navigator
```

```bash
$ aws-tower audit --help
usage: aws_tower_cli.py audit [-h] [-t {APIGW,CLOUDFRONT,EC2,EKS,ELB,IAM,RDS,S3,VPC}] [-m {info,low,medium,high,critical}] [-M {info,low,medium,high,critical}] [-n NAME]
                              [-f FILTER] [-v] [-b] [-s]
                              profile

positional arguments:
  profile               A valid profile name configured in the ~/.aws/config file

optional arguments:
  -h, --help            show this help message and exit
  -t {APIGW,CLOUDFRONT,EC2,EKS,ELB,IAM,RDS,S3,VPC}, --type {APIGW,CLOUDFRONT,EC2,EKS,ELB,IAM,RDS,S3,VPC}
                        Types to display (default: display everything)
  -m {info,low,medium,high,critical}, --min-severity {info,low,medium,high,critical}
                        min severity level to report when security is enabled (default: medium)
  -M {info,low,medium,high,critical}, --max-severity {info,low,medium,high,critical}
                        max severity level to report when security is enabled (default: high)
  -n NAME, --name NAME  [DEPRECATED] Filter this asset name
  -f FILTER, --filter FILTER
                        Filter by asset value (Ex: "something", "port:xxx", "engine:xxx", "version:xxx"
  -v, --verbose         Verbose output of the account assets
  -b, --brief           Brief output of the account assets
  -s, --summary         Summary of the account assets
```

```bash
$ aws-tower discover --help
usage: aws_tower_cli.py discover [-h] [-t {APIGW,CLOUDFRONT,EC2,EKS,ELB,IAM,RDS,S3,VPC}] [-p] [-n NAME] [-f FILTER] [-v] [-b] [-s] profile

positional arguments:
  profile               A valid profile name configured in the ~/.aws/config file

optional arguments:
  -h, --help            show this help message and exit
  -t {APIGW,CLOUDFRONT,EC2,EKS,ELB,IAM,RDS,S3,VPC}, --type {APIGW,CLOUDFRONT,EC2,EKS,ELB,IAM,RDS,S3,VPC}
                        Types to display (default: display everything)
  -p, --public-only     Display public assets only
  -n NAME, --name NAME  [DEPRECATED] Filter this asset name
  -f FILTER, --filter FILTER
                        Filter by asset value (Ex: "something", "port:xxx", "engine:xxx", "version:xxx"
  -v, --verbose         Verbose output of the account assets
  -b, --brief           Brief output of the account assets
  -s, --summary         Summary of the account assets
```

```bash
$ aws-tower iam --help
usage: aws_tower_cli.py iam [-h] [-s SOURCE] [-a ACTION] [--min-rights {admin,poweruser,reader}] [--service SERVICE] [-d] [-v] profile

positional arguments:
  profile               A valid profile name configured in the ~/.aws/config file

optional arguments:
  -h, --help            show this help message and exit
  -s SOURCE, --source SOURCE
                        Source arn
  -a ACTION, --action ACTION
                        Action to match
  --min-rights {admin,poweruser,reader}
                        Minimum actions rights
  --service SERVICE     Action Category to match
  -d, --display         Display informations about the source ARN
  -v, --verbose         Verbose output of the account assets
```

## Usage (lambda)

```bash
$ pip install -r requirements.lambda.txt --target ./package

$ cp config/lambda.config.sample config/lambda.config
$ export PATROWL_APITOKEN=xxxxxxxxxxxxxxx
$ export PATROWL_PRO_ASSETGROUP=1
$ export PATROWL_PRE_ASSETGROUP=2
$ export PATROWL_DEV_ASSETGROUP=3
$ export PATROWL_PRIVATE_ENDPOINT=http://localhost/
$ export PATROWL_PUBLIC_ENDPOINT=http://localhost/

$ python -c 'from monitoring.aws_lambda import aws_tower_child; aws_tower_child.main({ "my-account-profile": "arn:aws:iam::xxxxxxxxxxxxx:role/readonly", "env": "pro|pre|dev", "region_name": "eu-west-1", "meta_types": ["S3"] })'
```

## Findings

Some rules already exists in `config/rules.yaml.sample`, but you can add your own too.

### Define finding

You need to add your findings in `config/rules.yaml` with the following format:
```yaml
- message:
    text: '{arg1}: Your text ({arg2}, {arg3}), your text'
    args:
      arg1:
        type: dict
        key: key_in_dict
        variable: dict
      arg2:
        type: variable
        variable: my_variable
      arg3:
        type: variable
        variable: my_other_variable
  rules:
    - type: in # not_in, is_cidr, is_private_cidr, ...
      description: Check if 'all' is 'IN' 'ports'
      conditions:
        - type: constant
          name: data_element
          value: all
      data_sources:
        - type: variable
          name: data_list
          value: ports
  severity: medium # info, medium, high, critical
```

### Types

Types already presents:

- in: check if `data_element` is in `data_list`
- not_in: check if `data_element` is not in `data_list`
- has_attribute: check if `data_sources['asset']` has the attribute `conditions['attribute']`
- has_not_attribute: check if `data_sources['asset']` hasn't the attribute `conditions['attribute']`
- has_attribute_equal: check if `data_sources['attribute_value']` has the attribute equal to `conditions['attribute_value']`
- has_attribute_equal: check if `data_sources['attribute_value']` has the attribute not equal to `conditions['attribute_value']`
- is_cidr: check if `source` is a CIDR (example: `0.0.0.0/0` is a valid cidr).
- is_private_cidr: check if `source` is a private CIDR (rfc 1918)
- is_in_networks: check if `source` is one the networks in `networks`
- is_ports: check if source is a port or range ports (example: 9000-90001 is valid)
- engine_deprecated_version: check if `engine` version is higher than `versions`

To add a new type, you must define it in `libs/patterns.py` with the following format:

- The method name must be: `_check_rule_{type}` where **type** is the name you want (like `is_cidr`, `type_regex`, ...)
- Use 2 arguments for your method (will be changed in next update)

## Developers documentation

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
Copyright 2020-2022 Leboncoin
