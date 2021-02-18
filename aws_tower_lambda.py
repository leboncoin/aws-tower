#!/usr/bin/env python
"""
AWS Tower Lambda

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""

# Standard library imports
from configparser import ConfigParser
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

VERSION = '3.0.0'

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

def main():
    """
    Main function
    """
    config = ConfigParser()
    config.read('config/lambda.config')
    try:
        security_config = Patterns(
            variables.FINDING_RULES_PATH,
            variables.SEVERITY_LEVELS,
            list(variables.SEVERITY_LEVELS.keys())[0],
            list(variables.SEVERITY_LEVELS.keys())[-1]
        )
    except Exception as err_msg:
        LOGGER.critical(f"Can't get security config: {err_msg}")
    else:
        for profile in config.sections():
            if not profile.startswith('profile '):
                LOGGER.critical(f'Profile {profile} is malformed...')
                continue
            aws_account_name = profile.split()[1]
            if 'role_arn' not in config[profile]:
                LOGGER.critical(f'No role_arn in {profile}')
                continue
            LOGGER.warning(aws_account_name)
            try:
                session = get_session(config[profile]['role_arn'])
            except Exception as err_msg:
                LOGGER.critical(f"Can't get session: {err_msg}")
                continue
            try:
                assets = aws_scan(
                    session,
                    public_only=False,
                    meta_types=variables.META_TYPES
                )
            except Exception as err_msg:
                LOGGER.critical(f"Can't parse report: {err_msg}")
                continue
            patrowl_assets = get_assets(PATROWL_API, PATROWL['assetgroup'])
            for asset in assets:
                asset.audit(security_config)
                new_asset = True
                asset_id = None
                asset_patrowl_name = f'[{aws_account_name}] {asset.name}'
                for patrowl_asset in patrowl_assets:
                    if patrowl_asset['name'] == asset_patrowl_name:
                        new_asset = False
                        asset_id = patrowl_asset['id']
                        continue
                if new_asset:
                    LOGGER.warning(f'Add a new asset: {asset_patrowl_name}')
                    created_asset = add_asset(
                        PATROWL_API,
                        asset_patrowl_name,
                        asset_patrowl_name)
                    if not created_asset or 'id' not in created_asset:
                        LOGGER.critical(f'Error during asset {asset_patrowl_name} creation...')
                        continue
                    asset_id = created_asset['id']
                    add_in_assetgroup(
                        PATROWL_API,
                        PATROWL['assetgroup'],
                        asset_id)
                    add_finding(
                        PATROWL_API,
                        asset_id,
                        f'Public {asset.get_type()} has been found in {aws_account_name}',
                        asset.report_brief(),
                        'info')
                findings = get_findings(PATROWL_API, asset_id)
                for pattern in security_config.extract_findings(asset):
                    new_finding = True
                    for finding in findings:
                        if finding['title'] == pattern['title'] and \
                            finding['severity'] == pattern['severity']:
                            new_finding = False
                    if new_finding:
                        LOGGER.warning(f"Add a {pattern['severity']} finding: {pattern['title']} for asset {asset_patrowl_name}")
                        add_finding(
                            PATROWL_API,
                            asset_id,
                            pattern['title'],
                            asset.report_brief(),
                            pattern['severity'])

def handler(event, context):
    """
    Specific entrypoint for lambda
    """
    main()
