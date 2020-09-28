#!/usr/bin/env python
"""
AWS Tower Lambda

Copyright 2020 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
import json
import logging
import os
from pathlib import Path
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Third party library imports
sys.path.append('package')
from patrowl4py.api import PatrowlManagerApi
from requests import Session

# Own library
from libs.patrowl import add_asset, add_in_assetgroup, add_finding, get_assets, get_findings
from libs.pattern import get_dangerous_pattern
from libs.scan import ec2_scan, parse_report
from libs.session import get_session

# Debug
# from pdb import set_trace as st

VERSION = '2.0.3'

PATROWL = dict()
PATROWL['api_token'] = os.environ['PATROWL_APITOKEN']
PATROWL['assetgroup'] = int(os.environ['PATROWL_ASSETGROUP'])
PATROWL['private_endpoint'] = os.environ['PATROWL_PRIVATE_ENDPOINT']
PATROWL['public_endpoint'] = os.environ['PATROWL_PUBLIC_ENDPOINT']

LOGGER = logging.getLogger('aws-tower')

META = {
    'EC2': {
        'Name': 'Name'
    },
    'ELBV2': {
        'Name': 'DNSName'
    },
    'RDS': {
        'Name': 'Name'
    }
}

PATROWL_API = PatrowlManagerApi(
    url=PATROWL['private_endpoint'],
    auth_token=PATROWL['api_token']
)

SESSION = Session()

def main():
    """
    Main function
    """
    aws_config_path = Path('config')
    aws_config = aws_config_path.open()
    for line in aws_config.readlines():
        aws_account_name = line.split(' = ')[0]
        aws_account_id = line.split(' = ')[1].split('\n')[0]
        LOGGER.warning(aws_account_name)
        session = get_session(aws_account_id)
        try:
            report = parse_report(ec2_scan(session, public_only=True))
        except Exception as err_msg:
            LOGGER.warning(err_msg)
            continue
        assets = get_assets(PATROWL_API, PATROWL['assetgroup'])
        for report_type in report:
            for aws_asset in report[report_type]:
                new_asset = True
                asset_id = None
                asset_patrowl_name = f'[{aws_account_name}] {aws_asset[META[report_type]["Name"]]}'
                for asset in assets:
                    if asset['name'] == asset_patrowl_name:
                        new_asset = False
                        asset_id = asset['id']
                        continue
                if new_asset:
                    LOGGER.warning('Add a new asset: %s', asset_patrowl_name)
                    created_asset = add_asset(
                        PATROWL_API,
                        aws_asset[META[report_type]['Name']],
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
                for pattern in get_dangerous_pattern(aws_asset):
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
    main()
