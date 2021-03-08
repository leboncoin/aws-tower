#!/usr/bin/env python
"""
AWS Tower Lambda

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""

# Standard library imports
import logging
import os
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Third party library imports
sys.path.append('package')
from patrowl4py.api import PatrowlManagerApi
from requests import Session

# Own library and config files
from libs.patrowl import add_asset, add_in_assetgroup, add_finding, get_assets, get_findings
from libs.patterns import Patterns
from libs.scan import aws_scan
from libs.session import get_session
from config import variables

# Debug
# from pdb import set_trace as st

# pylint: disable=logging-fstring-interpolation

VERSION = '3.1.0'

PATROWL = dict()
PATROWL['api_token'] = os.environ['PATROWL_APITOKEN']
PATROWL['assetgroup'] = int(os.environ['PATROWL_ASSETGROUP'])
PATROWL['private_endpoint'] = os.environ['PATROWL_PRIVATE_ENDPOINT']
PATROWL['public_endpoint'] = os.environ['PATROWL_PUBLIC_ENDPOINT']

LOGGER = logging.getLogger('aws-tower')

PATROWL_API = PatrowlManagerApi(
    url=PATROWL['private_endpoint'],
    auth_token=PATROWL['api_token']
)

SESSION = Session()

def main(account):
    """
    Main function
    """
    try:
        security_config = Patterns(
            variables.FINDING_RULES_PATH,
            variables.SEVERITY_LEVELS,
            list(variables.SEVERITY_LEVELS.keys())[0],
            list(variables.SEVERITY_LEVELS.keys())[-1]
        )
    except Exception as err_msg:
        LOGGER.critical(f"Can't get security config: {err_msg}")
        return

    aws_account_name = list(account.keys())[0]
    LOGGER.warning(f'Start scanning {aws_account_name}...')
    try:
        session = get_session(account[aws_account_name])
    except Exception as err_msg:
        LOGGER.critical(f"Can't get session: {err_msg}")
        return
    try:
        assets = aws_scan(
            session,
            public_only=False,
            meta_types=variables.META_TYPES
        )
    except Exception as err_msg:
        LOGGER.critical(f"Can't parse report: {err_msg}")
        return

    patrowl_assets = get_assets(PATROWL_API, PATROWL['assetgroup'])
    for asset in assets:
        asset.audit(security_config)
        asset_id = None
        asset_patrowl_name = f'[{aws_account_name}] {asset.name}'

        is_new_asset = True
        for patrowl_asset in patrowl_assets:
            if patrowl_asset['name'] == asset_patrowl_name:
                is_new_asset = False
                asset_id = patrowl_asset['id']
                continue

        for new_finding in security_config.extract_findings(asset):
            is_new_finding = True

            if new_finding['severity'] not in variables.ALERTING_SEVERITIES:
                continue

            # Get Patrowl findings only if we have a match
            if not is_new_asset:
                findings = get_findings(PATROWL_API, asset_id)
                for finding in findings:
                    if finding['title'] == new_finding['title'] and \
                        finding['severity'] == new_finding['severity']:
                        is_new_finding = False

            if is_new_finding:
                if is_new_asset:
                    LOGGER.warning(f'Add a new asset: {asset_patrowl_name}')
                    created_asset = add_asset(
                        PATROWL_API,
                        asset_patrowl_name,
                        asset_patrowl_name)
                    if not created_asset or 'id' not in created_asset:
                        LOGGER.critical(f'Error during asset {asset_patrowl_name} creation...')
                        continue
                    is_new_asset = False
                    asset_id = created_asset['id']
                    add_in_assetgroup(
                        PATROWL_API,
                        PATROWL['assetgroup'],
                        asset_id)
                    if 'info' in variables.ALERTING_SEVERITIES:
                        add_finding(
                            PATROWL_API,
                            asset_id,
                            f'Public {asset.get_type()} has been found in {aws_account_name}',
                            asset.report_brief(),
                            'info')
                LOGGER.warning(f"Add a {new_finding['severity']} finding: {new_finding['title']} for asset {asset_patrowl_name}")
                add_finding(
                    PATROWL_API,
                    asset_id,
                    new_finding['title'],
                    asset.report_brief(),
                    new_finding['severity'])
    return

def handler(event, context):
    """
    Specific entrypoint for lambda
    event = { "my-account-profile": "arn:aws:iam::xxxxxxxxxxxxx:role/readonly" }
    """
    main(event)
