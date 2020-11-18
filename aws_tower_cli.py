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
import sys

# Third party library imports
import boto3
import botocore

from libs.scan import aws_scan, print_subnet
from config import variables

# Debug
# from pdb import set_trace as st

VERSION = '2.0.0'

def main(verb, args):
    """
    Main function
    """
    try:
        session = boto3.Session(profile_name=args.account)
    except botocore.exceptions.ProfileNotFound:
        print('The profile "{}" can\'t be found...'.format(args.account))
        sys.exit(1)
    meta_types = list()
    if args.type is None:
        meta_types = variables.META_TYPES.keys()
    else:
        for meta_type in args.type:
            if meta_type.upper() not in variables.META_TYPES:
                print(f'Unable to find meta type "{meta_type}" in {variables.META_TYPES.keys()}')
                sys.exit(1)
            if meta_type.upper() not in meta_types:
                meta_types.append(meta_type.upper())

    if verb == 'discover':
        report = aws_scan(
            session,
            public_only=not args.even_private,
            meta_types=meta_types
        )
        print_subnet(
            report,
            variables.META_TYPES,
            names_only=args.names_only,
            hide_sg=args.hide_sg,
            security=None
        )
    elif verb == 'scan':
        report = aws_scan(
            session,
            public_only=False,
            meta_types=meta_types
        )
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
            names_only=False,
            hide_sg=False,
            security=security
        )
    else:
        sys.exit(1)
    sys.exit(0)

if __name__ == '__main__':
    PARSER = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter
    )
    PARSER = ArgumentParser()
    SUBPARSERS = PARSER.add_subparsers(help='commands')

    PARSER.add_argument('--version', action='version', version=VERSION)

    # DISCOVER Arguments
    DISCOVER_PARSER = SUBPARSERS.add_parser(
        'discover',
        help='Discover assets in an AWS account')
    DISCOVER_PARSER.add_argument(
        'account',
        action='store',
        help='Account Name')
    DISCOVER_PARSER.add_argument(
        '-t', '--type',
        action='append',
        choices=variables.META_TYPES,
        help='Types to display (default: display everything)')
    DISCOVER_PARSER.add_argument(
        '--even-private',
        action='store_true',
        help='Display public and private assets')
    DISCOVER_PARSER.add_argument(
        '--hide-sg',
        action='store_true',
        help='Hide Security Groups')
    DISCOVER_PARSER.add_argument(
        '-n', '--names-only',
        action='store_true',
        help='Display only names')

    # SCAN Arguments
    SCAN_PARSER = SUBPARSERS.add_parser(
        'scan',
        help='Scan AWS account to find security issues')
    SCAN_PARSER.add_argument(
        'account',
        action='store',\
        help='Account Name')
    SCAN_PARSER.add_argument(
        '-t', '--type',
        action='append',
        choices=variables.META_TYPES,
        help='Types to display (default: display everything)')
    SCAN_PARSER.add_argument(
        '--min_severity',
        default='low',
        choices=variables.SEVERITY_LEVELS,
        help='min severity level to report when security is enabled (default: low)')
    SCAN_PARSER.add_argument(
        '--max_severity',
        default='high',
        choices=variables.SEVERITY_LEVELS,
        help='max severity level to report when security is enabled (default: high)')

    ARGS = PARSER.parse_args()
    main(sys.argv[1], ARGS)
