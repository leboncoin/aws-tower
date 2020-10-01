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
import botocore

from libs.scan import aws_scan, print_subnet

# Debug
# from pdb import set_trace as st

VERSION = '1.4.1'

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
        public_only=not args.all,
        enable_ec2=args.ec2,
        enable_elbv2=args.elbv2,
        enable_rds=args.rds)
    print_subnet(report, names_only=args.names_only)

if __name__ == '__main__':
    PARSER = ArgumentParser()

    PARSER.add_argument('--version', action='version', version=VERSION)
    PARSER.add_argument('-a', '--account', action='store',\
                        help='Account Name')
    PARSER.add_argument('--all', action='store_true',\
                        help='Display all assets')
    PARSER.add_argument('-n', '--names-only', action='store_true',\
                        help='Display only names')
    PARSER.add_argument('--ec2', action='store_true',\
                        help='Display EC2')
    PARSER.add_argument('--elbv2', action='store_true',\
                        help='Display ELBV2')
    PARSER.add_argument('--rds', action='store_true',\
                        help='Display RDS')
    ARGS = PARSER.parse_args()
    main(ARGS)
