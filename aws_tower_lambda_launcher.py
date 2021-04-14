#!/usr/bin/env python
"""
AWS Tower Lambda Launcher

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""
from configparser import ConfigParser
import json
import logging

import boto3

# pylint: disable=logging-fstring-interpolation

LOGGER = logging.getLogger('aws-tower-launcher')

VERSION = '3.6.2'

def call_lambda(row):
    """
    Call child lambda to do async task via  boto3
    """
    LOGGER.warning(f'Calling lambda aws_tower with {row = }')
    try:
        boto3.client('lambda').invoke(
            FunctionName='aws_tower',
            InvocationType='Event',
            Payload=json.dumps(row)
        )
    except Exception as err_msg:
        LOGGER.error(f'Unable to call lambda aws_tower: {err_msg}')
        return False
    return True

def main():
    """
    Main function
    """
    config = ConfigParser()
    config.read('config/lambda.config')
    for profile in config.sections():
        if not profile.startswith('profile '):
            LOGGER.critical(f'Profile {profile} is malformed...')
            continue
        aws_account_name = profile.split()[1]
        if 'role_arn' not in config[profile]:
            LOGGER.critical(f'No role_arn in {profile}')
            continue
        if 'env' not in config[profile]:
            LOGGER.critical(f'No env in {profile}')
            continue
        payload = {aws_account_name: config[profile]['role_arn'], 'env': config[profile]['env']}
        LOGGER.warning(payload)
        call_lambda(payload)


def handler(event, context):
    """
    Specific entrypoint for lambda
    """
    main()
