#!/usr/bin/env python
"""
AWS Tower Auditor

Copyright 2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas_beguier@hotmail.com)
"""

# Standard library imports
import json
import logging
import sys
import boto3

# Third party library imports
sys.path.append('package')

# Own library and config files
from libs.scan import aws_scan
from libs.session import assume_role
from libs.tools import Cache, get_false_positive_key
from libs.patterns import Patterns
from config import variables

# Debug
# from pdb import set_trace as st

# pylint: disable=logging-fstring-interpolation

VERSION = '4.6.0'

LOGGER = logging.getLogger('aws-tower')

NO_CACHE = Cache('', '')

def call_lambda(row):
    """
    Call child lambda to do async task via boto3
    """
    LOGGER.warning(f'Calling lambda aws_tower_alerting with {row = }')
    try:
        boto3.client('lambda').invoke(
            FunctionName='aws_tower_alerting',
            InvocationType='Event',
            Payload=json.dumps(row)
        )
    except Exception as err_msg:
        LOGGER.error(f'Unable to call lambda aws_tower_alerting: {err_msg}')
        return False
    return True

def main(account):
    """
    Main function
    """
    patterns = Patterns(
        variables.FINDING_RULES_PATH,
        variables.SEVERITY_LEVELS,
        list(variables.SEVERITY_LEVELS.keys())[0],
        list(variables.SEVERITY_LEVELS.keys())[-1]
    )

    aws_account_name = list(account.keys())[0]
    env = account['env']
    meta_types = account['meta_types']
    region_name = None
    if 'region_name' in account:
        region_name = account['region_name']
    LOGGER.warning(f'Start scanning {aws_account_name=}, {env=}, {region_name=}, {meta_types=}...')
    try:
        audit_role_arn = account[aws_account_name]
        session = assume_role(audit_role_arn, "TargetSession", region_name)
        # Local debug
        # session = boto3.Session(profile_name=aws_account_name)
    except Exception as err_msg:
        LOGGER.critical(f"Can't get session: {err_msg}")
        return
    try:
        assets = aws_scan(
            session,
            NO_CACHE,
            iam_action_passlist=variables.IAM_ACTION_PASSLIST,
            iam_rolename_passlist=variables.IAM_ROLENAME_PASSLIST,
            public_only=False,
            meta_types=meta_types
        )
    except Exception as err_msg:
        LOGGER.critical(f"Can't parse report: {err_msg}")
        return
    LOGGER.warning(f'Stop scanning {aws_account_name=}, {env=}, {region_name=}...')

    count = 0
    for asset in assets:
        count += 1
        LOGGER.warning(f'Checking asset {count}/{len(assets)}: {asset.name}')
        asset.audit(patterns)
        asset.remove_false_positives()
        if asset.get_type() in ['IAM', 'CLOUDFRONT']:
            region_name = 'global'

        # Always new findings, that's the all point of standalone mode
        for new_finding in asset.security_issues:
            new_finding['title'] += f' [{get_false_positive_key(new_finding["title"], asset.get_type(), asset.name)}]'

            if new_finding['severity'] not in variables.ALERTING_SEVERITIES:
                continue

            if env != 'pro':
                if new_finding['severity'] == 'medium':
                    new_finding['severity'] = 'low'
                elif new_finding['severity'] in ['high', 'critical']:
                    new_finding['severity'] = 'medium'

            LOGGER.warning(f"Add a {new_finding['severity']} finding: {new_finding['title']} for asset {asset.name}")
            call_lambda({"id": get_false_positive_key(new_finding["title"], asset.get_type(), asset.name),
                "asset_name": asset.name,
                "asset_type": asset.get_type(),
                "title": new_finding["title"],
                "severity": new_finding["severity"],
                "account_name": aws_account_name,
                "region_name": region_name
            })
    return

def handler(event, context):
    """
    Specific entrypoint for lambda
    event = { "my-account-profile": "arn:aws:iam::xxxxxxxxxxxxx:role/AuditRole", "env": "pro|pre|dev", "region_name": "eu-west-1", "meta_types": ["S3", "..."] }
    """
    main(event)
