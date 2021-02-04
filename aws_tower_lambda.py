#!/usr/bin/env python
"""
AWS Tower Lambda

Copyright 2020 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""

# Standard library imports
from configparser import ConfigParser
import json
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
from libs.display import parse_report
from libs.patrowl import add_asset, add_in_assetgroup, add_finding, get_assets, get_findings
from libs.patterns import Patterns
from libs.scan import aws_scan, compute_report
from libs.session import get_session
from config import variables

# Debug
# from pdb import set_trace as st

VERSION = '2.7.1'

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
        patterns = Patterns(
            variables.FINDING_RULES_PATH,
            variables.SEVERITY_LEVELS,
            list(variables.SEVERITY_LEVELS.keys())[0],
            list(variables.SEVERITY_LEVELS.keys())[-1]
        )
    except Exception as err_msg:
        LOGGER.critical(f"Can't get patterns: {err_msg}")
    else:
        for profile in config.sections():
            if not profile.startswith('profile '):
                LOGGER.critical('Profile %s is malformed...', profile)
                continue
            aws_account_name = profile.split()[1]
            if 'role_arn' not in config[profile]:
                LOGGER.critical('No role_arn in %s', profile)
                continue
            LOGGER.warning(aws_account_name)
            try:
                session = get_session(config[profile]['role_arn'])
            except Exception as err_msg:
                LOGGER.critical(f"Can't get session: {err_msg}")
                continue
            report = compute_report(report)
            try:
                report = parse_report(
                    aws_scan(
                        session,
                        public_only=True,
                        meta_types=variables.META_TYPES),
                    variables.META_TYPES)
            except Exception as err_msg:
                LOGGER.critical(f"Can't parse report: {err_msg}")
                continue
            assets = get_assets(PATROWL_API, PATROWL['assetgroup'])
            for report_type in report:
                for aws_asset in report[report_type]:
                    new_asset = True
                    asset_id = None
                    asset_patrowl_name = f'[{aws_account_name}] {aws_asset[variables.META_TYPES[report_type]["Name"]]}'
                    for asset in assets:
                        if asset['name'] == asset_patrowl_name:
                            new_asset = False
                            asset_id = asset['id']
                            continue
                    if new_asset:
                        LOGGER.warning('Add a new asset: %s', asset_patrowl_name)
                        created_asset = add_asset(
                            PATROWL_API,
                            asset_patrowl_name,
                            asset_patrowl_name)
                        if not created_asset:
                            LOGGER.critical('Error during asset %s creation...', asset_patrowl_name)
                            continue
                        asset_id = created_asset['id']
                        add_in_assetgroup(
                            PATROWL_API,
                            PATROWL['assetgroup'],
                            asset_id)
                        add_finding(
                            PATROWL_API,
                            asset_id,
                            f'Public {report_type} has been found in {aws_account_name}',
                            json.dumps(aws_asset, indent=4, sort_keys=True),
                            'info')
                    findings = get_findings(PATROWL_API, asset_id)
                    for pattern in patterns.extract_findings(aws_asset):
                        new_finding = True
                        for finding in findings:
                            if finding['title'] == pattern['title'] and \
                                finding['severity'] == pattern['severity']:
                                new_finding = False
                        if new_finding:
                            LOGGER.warning('Add a %s finding: %s for asset %s',
                                pattern['severity'],
                                pattern['title'],
                                asset_patrowl_name)
                            add_finding(
                                PATROWL_API,
                                asset_id,
                                pattern['title'],
                                json.dumps(aws_asset, indent=4, sort_keys=True),
                                pattern['severity'])

def handler(event, context):
    """
    Sepecific entrypoint for lambda
    """
    main()
