#!/usr/bin/env python
"""
AWS Tower CLI

Copyright 2020 Nicolas BEGUIER
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
from argparse import ArgumentParser

# Third party library imports
import boto3

from libs.scan import ec2_scan, parse_report, print_subnet
from libs.slack import slack_alert

# Debug
# from pdb import set_trace as st

VERSION = '1.2.0'

def main(args):
    session = boto3.Session(profile_name=args.account)
    report = ec2_scan(session, public_only=not args.all)
    print_subnet(report)
    if not args.simulate:
        return True
    report = parse_report(report)
    for ec2 in report['EC2']:
        # st()
        slack_alert(
            None,
            {'channel': '', 'username': '', 'icon_emoji':'', '':''},
            {'metadata': ec2, 'type': 'EC2', 'id': 0},
            {'account_name': args.account},
            {'public_endpoint': ''},
            criticity='medium', simulate=True)
    for elbv2 in report['ELBV2']:
        slack_alert(
            None,
            {'channel': '', 'username': '', 'icon_emoji':'', '':''},
            {'metadata': elbv2, 'type': 'ELBV2', 'id': 0},
            {'account_name': args.account},
            {'public_endpoint': ''},
            criticity='medium', simulate=True)

if __name__ == '__main__':
    PARSER = ArgumentParser()

    PARSER.add_argument('--version', action='version', version=VERSION)
    PARSER.add_argument('-a', '--account', action='store',\
                        help='Account Name')
    PARSER.add_argument('--all', action='store_true',\
                        help='Display all assets')
    PARSER.add_argument('-s', '--simulate', action='store_true',\
                        help='Simulate slack')
    ARGS = PARSER.parse_args()
    main(ARGS)
