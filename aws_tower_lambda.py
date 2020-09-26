#!/usr/bin/env python
"""
AWS Tower Lambda

Copyright 2020 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
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

# Own library
from libs.patrowl import add_asset, add_in_assetgroup, add_finding, get_assets
from libs.scan import ec2_scan, parse_report
from libs.session import get_session
from libs.slack import slack_alert

# Debug
# from pdb import set_trace as st

VERSION = '1.2.1'

PATROWL = dict()
PATROWL['api_token'] = os.environ['PATROWL_APITOKEN']
PATROWL['assetgroup'] = int(os.environ['PATROWL_ASSETGROUP'])
PATROWL['private_endpoint'] = os.environ['PATROWL_PRIVATE_ENDPOINT']
PATROWL['public_endpoint'] = os.environ['PATROWL_PUBLIC_ENDPOINT']
SLACK = dict()
SLACK['channel'] = os.environ['SLACK_CHANNEL']
SLACK['icon_emoji'] = os.environ['SLACK_ICON_EMOJI']
SLACK['username'] = os.environ['SLACK_USERNAME']
SLACK['webhook'] = os.environ['SLACK_WEBHOOK']

LOGGER = logging.getLogger('aws-tower')

PATROWL_API = PatrowlManagerApi(
    url=PATROWL['private_endpoint'],
    auth_token=PATROWL['api_token']
)

SESSION = Session()

def main():
    with open('config', 'r') as aws_config:
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
            for ec2 in report['EC2']:
                new_asset = True
                for asset in assets:
                    if asset['name'] == ec2['Name']:
                        new_asset = False
                        continue
                if new_asset:
                    created_asset = add_asset(PATROWL_API, ec2['Name'], ec2['Name'])
                    is_ok = slack_alert(SESSION, SLACK, {'metadata': ec2, 'type': 'EC2', 'id': created_asset['id']}, {'account_name': aws_account_name}, PATROWL)
                    if not is_ok:
                        continue
                    add_in_assetgroup(PATROWL_API, PATROWL['assetgroup'], created_asset['id'])
                    add_finding(PATROWL_API, created_asset, 'Public EC2 has been found in {}'.format(aws_account_name), str(ec2), 'high')
            for elbv2 in report['ELBV2']:
                new_asset = True
                for asset in assets:
                    if asset['name'] == elbv2['DNSName']:
                        new_asset = False
                        continue
                if new_asset:
                    hostname = '.'.join(elbv2['DNSName'].split('.')[:-4])
                    created_asset = add_asset(PATROWL_API, hostname, elbv2['DNSName'])
                    is_ok = slack_alert(SESSION, SLACK, {'metadata': elbv2, 'type': 'ELBV2', 'id': created_asset['id']}, {'account_name': aws_account_name}, PATROWL)
                    if not is_ok:
                        continue
                    add_in_assetgroup(PATROWL_API, PATROWL['assetgroup'], created_asset['id'])
                    add_finding(PATROWL_API, created_asset, 'Public ELBV2 has been found in {}'.format(aws_account_name), str(elbv2), 'high')
            for rds in report['RDS']:
                new_asset = True
                for asset in assets:
                    if asset['name'] == rds['Name']:
                        new_asset = False
                        continue
                if new_asset:
                    hostname = '.'.join(rds['Name'].split('.')[:-4])
                    created_asset = add_asset(PATROWL_API, hostname, rds['Name'])
                    is_ok = slack_alert(SESSION, SLACK, {'metadata': rds, 'type': 'RDS', 'id': created_asset['id']}, {'account_name': aws_account_name}, PATROWL)
                    if not is_ok:
                        continue
                    add_in_assetgroup(PATROWL_API, PATROWL['assetgroup'], created_asset['id'])
                    add_finding(PATROWL_API, created_asset, 'Public RDS has been found in {}'.format(aws_account_name), str(rds), 'high')



def handler(event, context):
    main()
