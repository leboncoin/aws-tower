#!/usr/bin/env python
"""
AWS Tower CLI

Copyright 2020 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""

# Standard library imports
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

# Third party library imports
import boto3
import botocore

from libs.scan import aws_scan, print_subnet
from config import variables
# Debug
# from pdb import set_trace as st

VERSION = '1.7.0'

def main(args):
    """
    Main function
    """
    try:
        session = boto3.Session(profile_name=args.account)
    except botocore.exceptions.ProfileNotFound:
        print('The profile "{}" can\'t be found...'.format(args.account))
        return False
    report = aws_scan(
        session,
        public_only=not args.even_private,
        enable_ec2=args.ec2,
        enable_elbv2=args.elbv2,
        enable_rds=args.rds)
    security = None
    if args.security:
        min_severity = list(variables.SEVERITY_LEVELS.keys())[0]
        max_severity = list(variables.SEVERITY_LEVELS.keys())[-1]
        if args.min_severity in variables.SEVERITY_LEVELS:
            min_severity = args.min_severity
        if args.max_severity in variables.SEVERITY_LEVELS:
            max_severity = args.max_severity
        security = {
            'findings_rules_path': variables.FINDING_RULES_PATH,
            'severity_levels': variables.SEVERITY_LEVELS,
            'min_severity': min_severity,
            'max_severity': max_severity
        }
    print_subnet(
        report,
        variables.META_TYPES,
        names_only=args.names_only,
        hide_sg=args.hide_sg,
        security=security
    )

if __name__ == '__main__':
    PARSER = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter
    )

    PARSER.add_argument('--version', action='version', version=VERSION)
    PARSER.add_argument('-a', '--account', action='store',\
                        help='Account Name')
    PARSER.add_argument('--even-private', action='store_true',\
                        help='Display public and private assets')
    PARSER.add_argument('-n', '--names-only', action='store_true',\
                        help='Display only names')
    PARSER.add_argument('--ec2', action='store_true',\
                        help='Display EC2')
    PARSER.add_argument('--elbv2', action='store_true',\
                        help='Display ELBV2')
    PARSER.add_argument('--rds', action='store_true',\
                        help='Display RDS')
    PARSER.add_argument('--hide-sg', action='store_true',\
                        help='Hide Security Groups')
    PARSER.add_argument('-s', '--security', action='store_true',
                        help='Check security issues on your services')
    PARSER.add_argument('--min_severity', default=f'{list(variables.SEVERITY_LEVELS.keys())[0]}',
                        help=f'min severity level to report when security is enabled ({list(variables.SEVERITY_LEVELS.keys())})')
    PARSER.add_argument('--max_severity', default=f'{list(variables.SEVERITY_LEVELS.keys())[-1]}',
                        help=f'max severity level to report when security is enabled ({list(variables.SEVERITY_LEVELS.keys())})')
    ARGS = PARSER.parse_args()
    main(ARGS)
