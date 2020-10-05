# AWS Tower

## Prerequisites

```bash
pip install -r requirements.txt
```

## Usage

```bash
$ ./aws_tower_cli.py --help
usage: aws_tower_cli.py [-h] [--version] [-a ACCOUNT] [--even-private] [-n] [--ec2] [--elbv2] [--rds] [--hide-sg]

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -a ACCOUNT, --account ACCOUNT
                        Account Name
  --even-private        Display public and private assets
  -n, --names-only      Display only names
  --ec2                 Display EC2
  --elbv2               Display ELBV2
  --rds                 Display RDS
  --hide-sg             Hide Security Groups
```

## Usage (lambda)

```bash
$ pip install -r requirements.txt --target ./package

$ cp config.sample config
$ export PATROWL_APITOKEN=xxxxxxxxxxxxxxx
$ export PATROWL_ASSETGROUP=1
$ export PATROWL_PRIVATE_ENDPOINT=http://localhost/
$ export PATROWL_PUBLIC_ENDPOINT=http://localhost/

$ python -c 'import aws_tower_lambda; aws_tower_lambda.main()' 
```

# License
Licensed under the [Apache License](https://github.com/leboncoin/aws-tower/blob/master/LICENSE), Version 2.0 (the "License").

# Copyright
Copyright 2020 Leboncoin
