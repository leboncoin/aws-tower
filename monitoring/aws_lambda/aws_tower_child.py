#!/usr/bin/env python
"""
AWS Tower Lambda Child

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""

# Standard library imports
from hashlib import sha256
import logging
import os
import sys
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Third party library imports
sys.path.append('package')
from patrowl4py.api import PatrowlManagerApi
from requests import Session

# Own library and config files
from libs.patrowl import add_asset, add_finding, get_findings, update_finding
from libs.scan import aws_scan
from libs.session import get_session
from libs.tools import Cache
from libs.patterns import Patterns
from config import variables

# Debug
# from pdb import set_trace as st

# pylint: disable=logging-fstring-interpolation

VERSION = '4.3.0'

PATROWL = {}
PATROWL['api_token'] = os.environ['PATROWL_APITOKEN']
PATROWL['private_endpoint'] = os.environ['PATROWL_PRIVATE_ENDPOINT']
PATROWL['public_endpoint'] = os.environ['PATROWL_PUBLIC_ENDPOINT']

LOGGER = logging.getLogger('aws-tower')

PATROWL_API = PatrowlManagerApi(
    url=PATROWL['private_endpoint'],
    auth_token=PATROWL['api_token']
)

NO_CACHE = Cache('', '')

SESSION = Session()

def hashcode(message):
    """
    Return the 8th first char of the sha256
    """
    return sha256(message.encode()).hexdigest()[:8]

def get_patrowl_assets():
    """
    Return all patrowl assets, with a retry system
    """
    try:
        patrowl_assets = PATROWL_API.get_assets()
    except:
        LOGGER.warning('Error while getting all assets, retrying in 10 seconds...')
        time.sleep(10)
        try:
            patrowl_assets = PATROWL_API.get_assets()
        except:
            LOGGER.warning('Error while getting all assets, retrying in 30 seconds...')
            time.sleep(30)
            try:
                patrowl_assets = PATROWL_API.get_assets()
            except:
                LOGGER.critical('Unable to get patrowl assets...')
                patrowl_assets = []
    return patrowl_assets

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
        session = get_session(account[aws_account_name], region_name)
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

    patrowl_assets = get_patrowl_assets()

    count = 0
    for asset in assets:
        count += 1
        LOGGER.warning(f'Checking asset {count}/{len(assets)}: {asset.name}')
        asset.audit(patterns)
        asset_id = None
        asset_patrowl_name = f'[{aws_account_name}] {asset.name}'

        is_new_asset = True
        for patrowl_asset in patrowl_assets:
            if patrowl_asset['name'] == asset_patrowl_name:
                is_new_asset = False
                asset_id = patrowl_asset['id']
                continue

        for new_finding in asset.security_issues:
            is_new_finding = True

            # Strip finding title too long
            title_hashcode = hashcode(new_finding['title'])
            if len(new_finding['title']) > 150:
                new_finding['title'] = f'{new_finding["title"][:120]}...'
            # Add a hashcode at the end
            new_finding['title'] = f'{new_finding["title"]} [{title_hashcode}]'

            if new_finding['severity'] not in variables.ALERTING_SEVERITIES:
                continue

            # Get Patrowl findings only if we have a match
            if not is_new_asset:
                findings = get_findings(PATROWL_API, asset_id)
                if findings is None:
                    LOGGER.critical(f'Error during get_findings of {asset_id=} ...')
                    continue
                for finding in findings:
                    if finding['title'] == new_finding['title'] and \
                        finding['severity'] == new_finding['severity']:
                        is_new_finding = False
                        # Update the field 'updated_at'
                        update_finding(PATROWL_API, finding['id'])

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
                    asset_id = created_asset['id']
                    is_new_asset = False
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
                    asset.finding_description(new_finding['title']),
                    new_finding['severity'])
    return


def handler(event, context):
    """
    Specific entrypoint for lambda
    event = { "my-account-profile": "arn:aws:iam::xxxxxxxxxxxxx:role/readonly", "env": "pro|pre|dev", "region_name": "eu-west-1", "meta_types": ["S3", "..."] }
    """
    main(event)
