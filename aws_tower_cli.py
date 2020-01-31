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

from libs.scan import ec2_scan, print_subnet

# Debug
# from pdb import set_trace as st

VERSION = '1.1.0'

def main(args):
    session = boto3.Session(profile_name=args.account)
    report = ec2_scan(session, public_only=not args.all)
    print_subnet(report)

if __name__ == '__main__':
    PARSER = ArgumentParser()

    PARSER.add_argument('--version', action='version', version=VERSION)
    PARSER.add_argument('-a', '--account', action='store',\
                        help='Account Name')
    PARSER.add_argument('--all', action='store_true',\
                        help='Display all assets')
    ARGS = PARSER.parse_args()
    main(ARGS)
