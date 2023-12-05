#!/usr/bin/env python
"""
AWS Tower Lambda Launcher

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""
# Standard library imports
from configparser import ConfigParser
import json
import logging
import sys
import boto3

# Third party library imports
sys.path.append('package')

# pylint: disable=logging-fstring-interpolation

LOGGER = logging.getLogger('aws-tower-launcher')

VERSION = '4.6.0'

LOGGER = logging.getLogger('aws-tower')


def is_config_ok(config, profile):
    """
    Return True if the profile configuration is ok
    """
    if not profile.startswith('profile '):
        LOGGER.critical(f'Profile {profile} is malformed...')
        return False
    if 'role_arn' not in config[profile]:
        LOGGER.critical(f'No role_arn in {profile}')
        return False
    if 'env' not in config[profile]:
        LOGGER.critical(f'No env in {profile}')
        return False
    return True

def call_lambda(row):
    """
    Call child lambda to do async task via boto3
    """
    LOGGER.warning(f'Calling lambda aws_tower_child_account with {row = }')
    try:
        boto3.client('lambda').invoke(
            FunctionName='aws_tower_child_account',
            InvocationType='Event',
            Payload=json.dumps(row)
        )
    except Exception as err_msg:
        LOGGER.error(f'Unable to call lambda aws_tower_child_account: {err_msg}')
        return False
    return True

def main():
    """
    Main function
    """
    config = ConfigParser(strict=False)
    config.read('config/lambda.config')
    # A lambda per profile
    for profile in config.sections():
        if not is_config_ok(config, profile):
            continue
        aws_account_name = profile.split()[1]
        payload = {
            aws_account_name: config[profile]['role_arn'],
            'env': config[profile]['env']
        }
        LOGGER.warning(payload)
        call_lambda(payload)

def handler(event, context):
    """
    Specific entrypoint for lambda
    """
    main()
