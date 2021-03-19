#!/usr/bin/env python
"""
AWS Tower CLI

Copyright 2020-2021 Leboncoin
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

from libs.display import print_report, print_summary
from libs.iam_scan import iam_display, iam_display_roles, iam_extract, iam_simulate
from libs.scan import aws_scan
from config import variables

# Debug
# from pdb import set_trace as st

# pylint: disable=logging-fstring-interpolation

LOGGER = logging.getLogger('aws-tower')
VERSION = '3.3.1'

def audit_handler(session, args, meta_types):
    """
    Handle audit argument
    """
    assets = aws_scan(
        session,
        public_only=False,
        meta_types=meta_types,
        name_filter=args.name
    )
    min_severity = list(variables.SEVERITY_LEVELS.keys())[0]
    max_severity = list(variables.SEVERITY_LEVELS.keys())[-1]
    if args.min_severity in variables.SEVERITY_LEVELS:
        min_severity = args.min_severity
    if args.max_severity in variables.SEVERITY_LEVELS:
        max_severity = args.max_severity
    security_config = {
        'findings_rules_path': variables.FINDING_RULES_PATH,
        'severity_levels': variables.SEVERITY_LEVELS,
        'min_severity': min_severity,
        'max_severity': max_severity
    }
    if args.summary:
        print_summary(
            assets,
            variables.META_TYPES,
            security_config
        )
    else:
        print_report(
            assets,
            variables.META_TYPES,
            brief=args.brief,
            security_config=security_config
        )

def discover_handler(session, args, meta_types):
    """
    Handle discover argument
    """
    assets = aws_scan(
        session,
        public_only=args.public_only,
        meta_types=meta_types,
        name_filter=args.name
    )
    if args.summary:
        print_summary(
            assets,
            variables.META_TYPES,
            None
        )
    else:
        print_report(
            assets,
            variables.META_TYPES,
            brief=args.brief,
            security_config=None
        )

def iam_handler(session, args):
    """
    Handle iam argument
    """
    client_iam = session.client('iam')
    res_iam = session.resource('iam')
    if args.display:
        iam_display(client_iam, res_iam, args.source, verbose=args.verbose)
    elif args.source and args.action:
        account_id = session.client('sts').get_caller_identity().get('Account')
        arn_list = iam_extract(args.source, account_id, verbose=args.verbose)
        for arn in arn_list:
            if iam_simulate(client_iam, res_iam, arn, args.action, verbose=args.verbose):
                print(f'{args.source} -> {args.action}: Access Granted')
                sys.exit(0)
        print(f'{args.source} -> {args.action}: Not Authorized')
    else:
        iam_display_roles(
            client_iam,
            res_iam,
            args.source,
            args.min_rights,
            args.service,
            verbose=args.verbose)

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
    if not hasattr(args, 'type') or args.type is None:
        meta_types = variables.META_TYPES
    else:
        for meta_type in args.type:
            if meta_type.upper() not in variables.META_TYPES:
                LOGGER.critical(f'Unable to find meta type "{meta_type}" in {variables.META_TYPES}')
                sys.exit(1)
            if meta_type.upper() not in meta_types:
                meta_types.append(meta_type.upper())

    if verb == 'audit':
        audit_handler(session, args, meta_types)
    elif verb == 'discover':
        discover_handler(session, args, meta_types)
    elif verb == 'iam':
        iam_handler(session, args)
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
        '-n', '--name',
        action='store',
        default='',
        help='Filter this asset name')
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

    # AUDIT Arguments
    AUDIT_PARSER = SUBPARSERS.add_parser(
        'audit',
        help='Audit AWS account to find security issues')
    AUDIT_PARSER.add_argument(
        'profile',
        action='store',\
        help='A valid profile name configured in the ~/.aws/config file')
    AUDIT_PARSER.add_argument(
        '-t', '--type',
        action='append',
        choices=variables.META_TYPES,
        help='Types to display (default: display everything)')
    AUDIT_PARSER.add_argument(
        '-m', '--min-severity',
        default='medium',
        choices=variables.SEVERITY_LEVELS,
        help='min severity level to report when security is enabled (default: medium)')
    AUDIT_PARSER.add_argument(
        '-M', '--max-severity',
        default='high',
        choices=variables.SEVERITY_LEVELS,
        help='max severity level to report when security is enabled (default: high)')
    AUDIT_PARSER.add_argument(
        '-n', '--name',
        action='store',
        default='',
        help='Filter this asset name')
    AUDIT_PARSER.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output of the account assets')
    AUDIT_PARSER.add_argument(
        '-b', '--brief',
        action='store_true',
        help='Brief output of the account assets')
    AUDIT_PARSER.add_argument(
        '-s', '--summary',
        action='store_true',
        help='Summary of the account assets')

    # IAM Arguments
    IAM_PARSER = SUBPARSERS.add_parser(
        'iam',
        help='Display IAM info for an AWS account')
    IAM_PARSER.add_argument(
        'profile',
        action='store',
        help='A valid profile name configured in the ~/.aws/config file')
    IAM_PARSER.add_argument(
        '-s', '--source',
        action='store',
        default='',
        help='Source arn')
    IAM_PARSER.add_argument(
        '-a', '--action',
        action='store',
        default='',
        help='Action to match')
    IAM_PARSER.add_argument(
        '--min-rights',
        action='store',
        choices=['admin', 'poweruser', 'reader'],
        default='',
        help='Minimum actions rights')
    IAM_PARSER.add_argument(
        '--service',
        action='store',
        default='',
        help='Action Category to match')
    IAM_PARSER.add_argument(
        '-d', '--display',
        action='store_true',
        help='Display informations about the source ARN')
    IAM_PARSER.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output of the account assets')

    ARGS = PARSER.parse_args()
    if len(sys.argv) == 1:
        PARSER.print_help()
    main(sys.argv[1], ARGS)
