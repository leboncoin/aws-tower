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
- Lightsail
- MQ
- RDS
- S3
- VPC

## Prerequisites

```bash
$ pip install -r requirements.txt
$ cp config/rules.yaml.sample config/rules.yaml # if you want to use "audit"
$ cp config/subnet_allow_list.txt.sample config/subnet_allow_list.txt # if you want to use a subnet allow list
$ cp config/trusted_accounts_list.txt.sample config/trusted_accounts_list.txt # if you want to use an aws account allow list
$ cp config/false_positives_list.txt.sample config/false_positives_list.txt # if you consider audited findings as false-positives
```

## Usage

```bash
$ alias aws-tower='<path>/aws_tower_cli.py'
```

```bash
$ aws-tower --help
usage: aws_tower_cli.py [-h] [--version] [--no-color] [--no-cache] [--clean-cache] [-l] [-p] {audit,discover,draw,iam} ...

positional arguments:
  {audit,discover,draw,iam}
                        commands
    audit               Audit AWS account to find security issues
    discover            Discover assets in an AWS account
    draw                Draw a threat model of your AWS account
    iam                 Display IAM info for an AWS account

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --no-color            Disable colors
  --no-cache            Disable cache
  --clean-cache         Erase current cache by a new one
  -l, --layer           [BETA] Generate a layer for the ATT&CK navigator
  -p, --list-profiles   List available profiles
```

```bash
$ aws-tower audit --help
usage: aws_tower_cli.py audit [-h] [-t {APIGW,CLOUDFRONT,EC2,EKS,ELB,IAM,LIGHTSAIL,MQ,RDS,S3,VPC}] [-m {info,low,medium,high,critical}] [-M {info,low,medium,high,critical}] [-f FILTER] [-v] [-b] [--false-positive-key] [-s] [-o OUTPUT] profile

positional arguments:
  profile               A valid profile name configured in the ~/.aws/config file

options:
  -h, --help            show this help message and exit
  -t {APIGW,CLOUDFRONT,EC2,EKS,ELB,IAM,LIGHTSAIL,MQ,RDS,S3,VPC}, --type {APIGW,CLOUDFRONT,EC2,EKS,ELB,IAM,LIGHTSAIL,MQ,RDS,S3,VPC}
                        Types to display (default: display everything)
  -m {info,low,medium,high,critical}, --min-severity {info,low,medium,high,critical}
                        min severity level to report when security is enabled (default: medium)
  -M {info,low,medium,high,critical}, --max-severity {info,low,medium,high,critical}
                        max severity level to report when security is enabled (default: high)
  -f FILTER, --filter FILTER
                        Filter by asset value (Ex: "something", "port:xxx", "engine:xxx", "version:xxx", "os:xxx"
  -v, --verbose         Verbose output of the account assets
  -b, --brief           Brief output of the account assets
  --false-positive-key  Display the unique "false-positive-key" label to consider those events as false-positive
  -s, --summary         Summary of the account assets
  -o OUTPUT, --output OUTPUT
                        Save the JSON output inside the specified file
```

```bash
$ aws-tower discover --help
usage: aws_tower_cli.py discover [-h] [-t {APIGW,CLOUDFRONT,EC2,EKS,ELB,IAM,LIGHTSAIL,MQ,RDS,S3,VPC}] [-p] [-f FILTER] [-v] [-b] [-s] [-o OUTPUT] profile

positional arguments:
  profile               A valid profile name configured in the ~/.aws/config file

options:
  -h, --help            show this help message and exit
  -t {APIGW,CLOUDFRONT,EC2,EKS,ELB,IAM,LIGHTSAIL,MQ,RDS,S3,VPC}, --type {APIGW,CLOUDFRONT,EC2,EKS,ELB,IAM,LIGHTSAIL,MQ,RDS,S3,VPC}
                        Types to display (default: display everything)
  -p, --public-only     Display public assets only
  -f FILTER, --filter FILTER
                        Filter by asset value (Ex: "something", "port:xxx", "engine:xxx", "version:xxx", "os:xxx"
  -v, --verbose         Verbose output of the account assets
  -b, --brief           Brief output of the account assets
  -s, --summary         Summary of the account assets
  -o OUTPUT, --output OUTPUT
                        Save the JSON output inside the specified file
```

```bash
$ aws-tower draw --help
usage: aws_tower_cli.py draw [-h] [-t {APIGW,CLOUDFRONT,EC2,EKS,ELB,IAM,LIGHTSAIL,MQ,RDS,S3,VPC}] [--limit] [--all] [--vpc-peering-dot VPC_PEERING_DOT] profile

positional arguments:
  profile               A valid profile name configured in the ~/.aws/config file

options:
  -h, --help            show this help message and exit
  -t {APIGW,CLOUDFRONT,EC2,EKS,ELB,IAM,LIGHTSAIL,MQ,RDS,S3,VPC}, --type {APIGW,CLOUDFRONT,EC2,EKS,ELB,IAM,LIGHTSAIL,MQ,RDS,S3,VPC}
                        Types to display (default: display everything)
  --limit               Restrict to only interesting assets among vulnerable
  --all                 All assets, without lonely nodes
  --vpc-peering-dot VPC_PEERING_DOT
                        Save VPC peering dot file
```

```bash
$ aws-tower iam --help
usage: aws_tower_cli.py iam [-h] [-s SOURCE] [-a ACTION] [--min-rights {admin,poweruser,reader}] [--service SERVICE] [-d] [--only-dangerous-actions] [-v] profile

positional arguments:
  profile               A valid profile name configured in the ~/.aws/config file

options:
  -h, --help            show this help message and exit
  -s SOURCE, --source SOURCE
                        Source arn
  -a ACTION, --action ACTION
                        Action to match
  --min-rights {admin,poweruser,reader}
                        Minimum actions rights
  --service SERVICE     Action Category to match
  -d, --display         Display informations about the source ARN
  --only-dangerous-actions
                        Display IAM dangerous actions only
  -v, --verbose         Verbose output of the account assets
```

## Usage: monitoring 'aws_lambda'

The method of monitoring use a cascade of Lambda to scan all of your accounts.

At the end, it sends the findings into another stack of lambda : "aws_alerting", that is presented below.

```bash
$ bash monitoring/aws_lambda/create_archive.sh

# Upload the zip file into AWS Lambda: aws_lambda.zip

# Create Lambda aws_tower_launcher:
## Handler : monitoring.aws_lambda.aws_tower_launcher.handler
## Duration: 15mn
## Add authorization: AWSLambdaRole

# Create Lambda aws_tower_child_account:
## Name: aws_tower_child_account
## Handler : monitoring.aws_lambda.aws_tower_child_account.handler
## Duration: 15mn
## Add authorization: AWSLambdaRole

# Create IAM role in the current account named: 'AWS-Tower' (service AWS Lambda)
## Authorization: AWSLambdaRole (optional)
## and the custom policy "Assume-AuditRole-Any-Accounts":
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::*:role/AuditRole"
        }
    ]
}

# Create Lambda aws_tower_auditor
## Name: aws_tower_auditor
## Handler : monitoring.aws_lambda.aws_tower_auditor.handler
## Duration: 5mn
## Associate IAM role above 'AWS-Tower'

# Create a role, in EACH AWS accounts, named 'AuditRole'
## Authorization: SecurityAudit (AWS built-in)
## Trusted relationship with the role of aws_tower_child
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Statement1",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::xxxxx:role/AWS-Tower"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

```

## Usage: monitoring 'aws_alerting'

This lambda receive events directly from another lambda.
If the event startswith "Add ", this mean this is a security event.
- Step 1: Store in S3 bucket 'aws-tower-findings'
- Step 2: Alerting via Slack

```bash
$ bash monitoring/aws_alerting/create_archive.sh

# Upload the zip file into AWS Lambda: archive_alerting.zip


monitoring.aws_alerting.aws_tower_alerting.handler

edit role
add policy
Get-Slack-Secret
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "arn:aws:secretsmanager:eu-west-3:xxxxx:secret:security_slack_alerts-*"
        }
    ]
}

s3-aws-tower-findings
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject"
            ],
            "Resource": "arn:aws:s3:::aws-tower-findings/*"
        }
    ]
}


```

## Usage: monitoring 'aws_lambda_patrowl'

```bash
$ pip install -r monitoring/aws_lambda_patrowl/requirements.txt --target ./package

$ cp config/lambda.config.sample config/lambda.config
$ export PATROWL_APITOKEN=xxxxxxxxxxxxxxx
$ export PATROWL_PRO_ASSETGROUP=1
$ export PATROWL_PRE_ASSETGROUP=2
$ export PATROWL_DEV_ASSETGROUP=3
$ export PATROWL_PRIVATE_ENDPOINT=http://localhost/
$ export PATROWL_PUBLIC_ENDPOINT=http://localhost/

$ python -c 'from monitoring.aws_lambda_patrowl import aws_tower_child; aws_tower_child.main({ "my-account-profile": "arn:aws:iam::xxxxxxxxxxxxx:role/readonly", "env": "pro|pre|dev", "region_name": "eu-west-1", "meta_types": ["S3"] })'
```


## Usage (layers)

```bash
$ aws-tower --layer > /tmp/aws-tower-layer.json
```

Then, go to [Attack Navigator](https://mitre-attack.github.io/attack-navigator/#comment_underline=false)

Click on "Open Existing Layer" -> "Upload from local"

Upload your generated file, `/tmp/aws-tower-layer.json`

You will have a warning, **Click No** to refuse the upgrade on Att&ck v12, stay in v11.


## Usage (draw)

```bash
# Display demo-account with only medium, high and critical findings
$ aws-tower draw demo-account

# Display demo-account, with all assets
$ aws-tower draw demo-account --all

# Display VPC peering connexion in demo-account
$ aws-tower draw demo-account --vpc-peering-dot /tmp/_vpc_demo_account.dot
$ dot -Tjpg /tmp/_vpc_demo_account.dot -o /tmp/_vpc_demo_account.jpg

# Display VPC peering connexion in all accounts
$ for account in $(aws-tower -p); do aws-tower draw $account --vpc-peering-dot "/tmp/_${account}.dot"; done
$ (echo 'graph {'; grep -h -- ';' /tmp/_*.dot | sort -u; echo '}')> /tmp/complete.dot
$ dot -Tjpg /tmp/complete.dot -o /tmp/graph.jpg
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
Copyright 2020-2023 Leboncoin
