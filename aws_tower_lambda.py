#!/usr/bin/env python
"""
AWS Tower Lambda

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""

# Standard library imports
from hashlib import sha256
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
from libs.scan import aws_scan
from libs.session import get_session
from config import variables

# Debug
# from pdb import set_trace as st

# pylint: disable=logging-fstring-interpolation

VERSION = '3.6.2'

PATROWL = dict()
PATROWL['api_token'] = os.environ['PATROWL_APITOKEN']
PATROWL['assetgroup_pro'] = int(os.environ['PATROWL_PRO_ASSETGROUP'])
PATROWL['assetgroup_pre'] = int(os.environ['PATROWL_PRE_ASSETGROUP'])
PATROWL['assetgroup_dev'] = int(os.environ['PATROWL_DEV_ASSETGROUP'])
PATROWL['private_endpoint'] = os.environ['PATROWL_PRIVATE_ENDPOINT']
PATROWL['public_endpoint'] = os.environ['PATROWL_PUBLIC_ENDPOINT']

LOGGER = logging.getLogger('aws-tower')

PATROWL_API = PatrowlManagerApi(
    url=PATROWL['private_endpoint'],
    auth_token=PATROWL['api_token']
)

SESSION = Session()

def hashcode(message):
    """
    Return the 8th first char of the sha256
    """
    return sha256(message.encode()).hexdigest()[:8]

def main(account):
    """
    Main function
    """
    security_config = {
        'findings_rules_path': variables.FINDING_RULES_PATH,
        'severity_levels': variables.SEVERITY_LEVELS,
        'min_severity': list(variables.SEVERITY_LEVELS.keys())[0],
        'max_severity': list(variables.SEVERITY_LEVELS.keys())[-1]
    }

    aws_account_name = list(account.keys())[0]
    env = account['env']
    LOGGER.warning(f'Start scanning {aws_account_name=}, {env=}...')
    try:
        session = get_session(account[aws_account_name])
    except Exception as err_msg:
        LOGGER.critical(f"Can't get session: {err_msg}")
        return
    try:
        assets = aws_scan(
            session,
            action_passlist=variables.ACTION_PASSLIST,
            public_only=False,
            meta_types=variables.META_TYPES
        )
    except Exception as err_msg:
        LOGGER.critical(f"Can't parse report: {err_msg}")
        return

    patrowl_assets = get_assets(PATROWL_API, PATROWL[f'assetgroup_{env}'])
    patrowl_all_assets = PATROWL_API.get_assets()
    assets_to_add = []
    for asset in assets:
        asset.audit(security_config)
        asset_id = None
        asset_patrowl_name = f'[{aws_account_name}] {asset.name}'

        is_new_asset = True
        is_lost_asset = False
        for patrowl_asset in patrowl_assets:
            if patrowl_asset['name'] == asset_patrowl_name:
                is_new_asset = False
                asset_id = patrowl_asset['id']
                continue

        # In some cases, the assets is not attached to the asset group
        if is_new_asset:
            for patrowl_asset in patrowl_all_assets:
                if patrowl_asset['name'] == asset_patrowl_name:
                    is_lost_asset = True
                    is_new_asset = False
                    asset_id = patrowl_asset['id']
                    LOGGER.critical(f'asset {asset_patrowl_name} was lost..., {asset_id=}')

        # List of asset id, added at the end
        if is_new_asset or is_lost_asset:
            assets_to_add.append(asset_id)

        for new_finding in asset.security_issues:
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
                    if 'info' in variables.ALERTING_SEVERITIES:
                        add_finding(
                            PATROWL_API,
                            asset_id,
                            f'Public {asset.get_type()} has been found in {aws_account_name}',
                            asset.report_brief(),
                            'info')
                LOGGER.warning(f"Add a {new_finding['severity']} finding: {new_finding['title']} for asset {asset_patrowl_name}")
                # Strip finding title if too long and add a hashcode at the end
                if len(new_finding['title']) > 150:
                    new_finding['title'] = f'{new_finding["title"][:120]}... [{hashcode(new_finding["title"])}]'
                add_finding(
                    PATROWL_API,
                    asset_id,
                    new_finding['title'],
                    asset.finding_description(new_finding['title']),
                    new_finding['severity'])
    add_in_assetgroup(
        PATROWL_API,
        PATROWL[f'assetgroup_{env}'],
        assets_to_add)
    return

def handler(event, context):
    """
    Specific entrypoint for lambda
    event = { "my-account-profile": "arn:aws:iam::xxxxxxxxxxxxx:role/readonly", "env": "pro|pre|dev" }
    """
    main(event)
