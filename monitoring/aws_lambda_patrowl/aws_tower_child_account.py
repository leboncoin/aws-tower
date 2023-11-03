#!/usr/bin/env python
"""
AWS Tower Lambda Child Account

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
import json
import logging
import boto3
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Own library and config files
from config import variables

# Debug
# from pdb import set_trace as st

# pylint: disable=logging-fstring-interpolation

VERSION = '4.3.0'

LOGGER = logging.getLogger('aws-tower')

def call_lambda(row):
    """
    Call child lambda to do async task via boto3
    """
    LOGGER.warning(f'Calling lambda aws_tower_child with {row = }')
    try:
        boto3.client('lambda').invoke(
            FunctionName='aws_tower_child',
            InvocationType='Event',
            Payload=json.dumps(row)
        )
    except Exception as err_msg:
        LOGGER.error(f'Unable to call lambda aws_tower_child: {err_msg}')
        return False
    return True

def main(account):
    """
    Main function
    """
    aws_account_name = list(account.keys())[0]
    env = account['env']
    LOGGER.warning(f'{aws_account_name=}, {env=}')
    for meta_type in variables.META_TYPES:
        payload = {
            aws_account_name: account[aws_account_name],
            'env': env,
            'meta_types': [meta_type]
        }
        regions = variables.LAMBDA_SCAN_REGION_LIST
        if meta_type == 'EC2':
            regions = variables.AWS_ALL_REGION_LIST
        for region in regions:
            payload['region_name'] = region
            LOGGER.warning(f'Start scanning {aws_account_name=}, {env=}, {region=}, {meta_type=}...')
            call_lambda(payload)

def handler(event, context):
    """
    Specific entrypoint for lambda
    event = { "my-account-profile": "arn:aws:iam::xxxxxxxxxxxxx:role/readonly", "env": "pro|pre|dev" }
    """
    main(event)
