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
import logging
import sys

# Third party library imports
import boto3
import botocore

from libs.scan import aws_scan, print_subnet
from config import variables

# Debug
# from pdb import set_trace as st

LOGGER = logging.getLogger('aws-tower')
VERSION = '2.2.0'

def main(verb, args):
    """
    Main function
    """
    try:
        session = boto3.Session(profile_name=args.profile)
    except botocore.exceptions.ProfileNotFound:
        LOGGER.critical(f'The profile "{args.profile}" can\'t be found...')
        LOGGER.critical('Take a look at the ~/.aws/config file.')
        sys.exit(1)
    meta_types = list()
    if args.type is None:
        meta_types = variables.META_TYPES.keys()
    else:
        for meta_type in args.type:
            if meta_type.upper() not in variables.META_TYPES:
                LOGGER.critical(f'Unable to find meta type "{meta_type}" in {variables.META_TYPES.keys()}')
                sys.exit(1)
            if meta_type.upper() not in meta_types:
                meta_types.append(meta_type.upper())

    if verb == 'discover':
        report = aws_scan(
            session,
            public_only=args.public_only,
            meta_types=meta_types
        )
        print_subnet(
            report,
            variables.META_TYPES,
            brief=args.brief,
            summary=args.summary,
            verbose=args.verbose,
            security=None
        )
    elif verb == 'scan':
        report = aws_scan(
            session,
            public_only=False,
            meta_types=meta_types
        )
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
            brief=args.brief,
            summary=args.summary,
            verbose=args.verbose,
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
        'profile',
        action='store',
        help='A valid profile name configured in the ~/.aws/config file')
    DISCOVER_PARSER.add_argument(
        '-t', '--type',
        action='append',
        choices=variables.META_TYPES,
        help='Types to display (default: display everything)')
    DISCOVER_PARSER.add_argument(
        '-p', '--public-only',
        action='store_true',
        help='Display public assets only')
    DISCOVER_PARSER.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output of the account assets')
    DISCOVER_PARSER.add_argument(
        '-b', '--brief',
        action='store_true',
        help='Brief output of the account assets')
    DISCOVER_PARSER.add_argument(
        '-s', '--summary',
        action='store_true',
        help='Summary of the account assets')

    # SCAN Arguments
    SCAN_PARSER = SUBPARSERS.add_parser(
        'scan',
        help='Scan AWS account to find security issues')
    SCAN_PARSER.add_argument(
        'profile',
        action='store',\
        help='A valid profile name configured in the ~/.aws/config file')
    SCAN_PARSER.add_argument(
        '-t', '--type',
        action='append',
        choices=variables.META_TYPES,
        help='Types to display (default: display everything)')
    SCAN_PARSER.add_argument(
        '-m', '--min-severity',
        default='low',
        choices=variables.SEVERITY_LEVELS,
        help='min severity level to report when security is enabled (default: low)')
    SCAN_PARSER.add_argument(
        '-M', '--max-severity',
        default='high',
        choices=variables.SEVERITY_LEVELS,
        help='max severity level to report when security is enabled (default: high)')
    SCAN_PARSER.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output of the account assets')
    SCAN_PARSER.add_argument(
        '-b', '--brief',
        action='store_true',
        help='Brief output of the account assets')
    SCAN_PARSER.add_argument(
        '-s', '--summary',
        action='store_true',
        help='Summary of the account assets')

    ARGS = PARSER.parse_args()
    if len(sys.argv) == 1:
        PARSER.print_help()
    main(sys.argv[1], ARGS)
