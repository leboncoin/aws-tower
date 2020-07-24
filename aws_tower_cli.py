#!/usr/bin/env python
"""
AWS Tower CLI

Copyright 2020 Leboncoin
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

VERSION = '1.3.0'

def main(args):
    """
    Main function
    """
    session = boto3.Session(profile_name=args.account)
    report = ec2_scan(
        session,
        public_only=not args.all,
        enable_ec2=args.ec2,
        enable_elbv2=args.elbv2,
        enable_rds=args.rds)
    print_subnet(report, names_only=args.names_only)
    if not args.simulate:
        return True
    report = parse_report(report)
    for ec2 in report['EC2']:
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
    for rds in report['RDS']:
        slack_alert(
            None,
            {'channel': '', 'username': '', 'icon_emoji':'', '':''},
            {'metadata': rds, 'type': 'RDS', 'id': 0},
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
    PARSER.add_argument('-n', '--names-only', action='store_true',\
                        help='Display only names')
    PARSER.add_argument('-s', '--simulate', action='store_true',\
                        help='Simulate slack')
    PARSER.add_argument('--ec2', action='store_true',\
                        help='Display EC2')
    PARSER.add_argument('--elbv2', action='store_true',\
                        help='Display ELBV2')
    PARSER.add_argument('--rds', action='store_true',\
                        help='Display RDS')
    ARGS = PARSER.parse_args()
    main(ARGS)
