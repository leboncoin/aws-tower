# AWS Tower

## Prerequisites

```bash
pip install -r requirements.txt
```

## Usage

```bash
$ ./aws_tower_cli.py --help
usage: aws_tower_cli.py [-h] [--version] [-a ACCOUNT] [--all]

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -a ACCOUNT, --account ACCOUNT
                        Account Name
  --all                 Display all assets
```

## Usage (lambda)

```bash
$ pip install -r requirements.txt --target ./package

$ cp config.sample config
$ export PATROWL_APITOKEN=xxxxxxxxxxxxxxx
$ export PATROWL_ASSETGROUP=1
$ export PATROWL_PRIVATE_ENDPOINT=http://localhost/
$ export PATROWL_PUBLIC_ENDPOINT=http://localhost/
$ export SLACK_CHANNEL='#test'
$ export SLACK_ICON_EMOJI=':test:'
$ export SLACK_USERNAME=test
$ export SLACK_WEBHOOK=http://localhost/

$ python -c 'import aws_tower_lambda; aws_tower_lambda.main()' 
```

# License
Licensed under the [Apache License](https://github.com/leboncoin/aws-tower/blob/master/LICENSE), Version 2.0 (the "License").

# Copyright
Copyright 2020 Leboncoin
