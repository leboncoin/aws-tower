#!/usr/bin/env python
"""
AWS Tower CLI

Copyright 2020-2023 Leboncoin
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
from rich import console

from libs.display import audit_scan, draw_threats, draw_vpc_peering, \
    prepare_report, print_report, print_summary
from libs.iam_scan import complete_source_arn, iam_display, \
    iam_display_roles, iam_extract, iam_simulate
from libs.scan import aws_scan
from libs.tools import Cache, NoColor, generate_layer
from config import variables

# Debug
# from pdb import set_trace as st

CONSOLE = console.Console()
VERSION = '4.6.0'

def audit_handler(session, args, meta_types, cache):
    """
    Handle audit argument
    """
    assets = aws_scan(
        session,
        cache,
        iam_action_passlist=variables.IAM_ACTION_PASSLIST,
        iam_rolename_passlist=variables.IAM_ROLENAME_PASSLIST,
        public_only=False,
        meta_types=meta_types,
        name_filter=args.filter,
        console=CONSOLE
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
            CONSOLE,
            security_config
        )
    else:
        print_report(
            assets,
            variables.META_TYPES,
            CONSOLE,
            args.output,
            brief=args.brief,
            with_fpkey=args.false_positive_key,
            security_config=security_config
        )

def discover_handler(session, args, meta_types, cache):
    """
    Handle discover argument
    """
    assets = aws_scan(
        session,
        cache,
        iam_action_passlist=variables.IAM_ACTION_PASSLIST,
        iam_rolename_passlist=variables.IAM_ROLENAME_PASSLIST,
        public_only=args.public_only,
        meta_types=meta_types,
        name_filter=args.filter,
        console=CONSOLE
    )
    if args.summary:
        print_summary(
            assets,
            variables.META_TYPES,
            CONSOLE,
            None
        )
    else:
        print_report(
            assets,
            variables.META_TYPES,
            CONSOLE,
            args.output,
            brief=args.brief,
            security_config=None
        )

def draw_handler(session, args, meta_types, cache):
    """
    Handle draw argument
    """
    if args.vpc_peering_dot:
        meta_types = ['VPC']

    assets = aws_scan(
        session,
        cache,
        iam_action_passlist=variables.IAM_ACTION_PASSLIST,
        iam_rolename_passlist=variables.IAM_ROLENAME_PASSLIST,
        public_only=False,
        meta_types=meta_types,
        name_filter='',
        console=CONSOLE
    )

    min_severity = 'medium'
    max_severity = 'critical'
    security_config = {
        'findings_rules_path': variables.FINDING_RULES_PATH,
        'severity_levels': variables.SEVERITY_LEVELS,
        'min_severity': min_severity,
        'max_severity': max_severity
    }
    report = prepare_report(assets, meta_types, CONSOLE)
    audit_scan(assets, report, security_config, None, False, CONSOLE)
    if args.vpc_peering_dot:
        draw_vpc_peering(assets, args.vpc_peering_dot, args)
    else:
        draw_threats(f'AWS Tower: Threat map of {args.profile}', assets, CONSOLE, args)

def iam_handler(session, args, cache, csl):
    """
    Handle iam argument
    """
    args.source = complete_source_arn(session, args.source)
    client_iam = session.client('iam')
    res_iam = session.resource('iam')
    if args.display:
        iam_display(
            client_iam,
            res_iam,
            args.source,
            args.min_rights,
            cache,
            csl,
            iam_action_passlist=variables.IAM_ACTION_PASSLIST,
            iam_rolename_passlist=variables.IAM_ROLENAME_PASSLIST,
            only_dangerous_actions=args.only_dangerous_actions,
            verbose=args.verbose)
    elif args.source and args.action:
        account_id = session.client('sts').get_caller_identity().get('Account')
        arn_list = iam_extract(args.source, account_id, csl, verbose=args.verbose)
        for arn in arn_list:
            if iam_simulate(client_iam, res_iam, arn, args.action, csl, verbose=args.verbose):
                csl.print(f'{args.source} -> {args.action}: Access Granted')
                sys.exit(0)
        csl.print(f'{args.source} -> {args.action}: Not Authorized')
    else:
        iam_display_roles(
            client_iam,
            res_iam,
            args.source,
            args.min_rights,
            args.service,
            cache,
            csl,
            iam_action_passlist=variables.IAM_ACTION_PASSLIST,
            iam_rolename_passlist=variables.IAM_ROLENAME_PASSLIST,
            only_dangerous_actions=args.only_dangerous_actions,
            verbose=args.verbose)

def main(verb, args):
    """
    Main function
    """
    csl = CONSOLE
    if args.no_color:
        csl = NoColor()
    try:
        session = boto3.Session(profile_name=args.profile)
    except botocore.exceptions.ProfileNotFound:
        csl.print(f'[red]The profile [bold]{args.profile}[/bold] can\'t be found...')
        csl.print('[red]Take a look at the ~/.aws/config file.')
        sys.exit(1)
    meta_types = []
    if not hasattr(args, 'type') or args.type is None:
        meta_types = variables.META_TYPES
    else:
        for meta_type in args.type:
            if meta_type.upper() not in meta_types:
                meta_types.append(meta_type.upper())

    cache_dir = '/tmp/aws_tower_cache'
    cache_prefix = f'{cache_dir}/{args.profile}_{session.region_name}'
    if args.no_cache:
        cache_prefix = ''
    cache = Cache(cache_dir, cache_prefix, purge=args.clean_cache)

    identity = 'Unknown'
    try:
        identity = cache.get_caller_identity('id', session)['Arn']
    except (
        botocore.exceptions.UnauthorizedSSOTokenError,
        botocore.exceptions.EndpointConnectionError,
        botocore.exceptions.ClientError) as err_msg:
        CONSOLE.print(f'[red]{err_msg}')
        sys.exit(1)
    except:
        csl.print('[red]Can\'t get the caller identity...')
    if session.region_name is None:
        csl.print('[red]No region defined, take a look at the ~/.aws/config file')
        sys.exit(1)
    csl.print(f'[white]Welcome [bold]{identity}[/bold] !')
    csl.print(
        f'[white]Scan type: [bold]{verb}[/bold], '+
        f'Profile: [bold]{args.profile}[/bold], '+
        f'Region: [bold]{session.region_name}')

    if verb == 'audit':
        audit_handler(session, args, meta_types, cache)
    elif verb == 'discover':
        discover_handler(session, args, meta_types, cache)
    elif verb == 'draw':
        draw_handler(session, args, meta_types, cache)
    elif verb == 'iam':
        iam_handler(session, args, cache, csl)
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
    PARSER.add_argument('--no-color', action='store_true', help='Disable colors')
    PARSER.add_argument('--no-cache', action='store_true', help='Disable cache')
    PARSER.add_argument(
        '--clean-cache',
        action='store_true',
        help='Erase current cache by a new one')
    PARSER.add_argument(
        '-l', '--layer',
        action='store_true',
        help='[BETA] Generate a layer for the ATT&CK navigator')
    PARSER.add_argument(
        '-p', '--list-profiles',
        action='store_true',
        help='List available profiles')

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
        '-f', '--filter',
        action='store',
        default='',
        help='Filter by asset value (Ex: "something", "port:xxx", "engine:xxx", "version:xxx", "os:xxx"')
    AUDIT_PARSER.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output of the account assets')
    AUDIT_PARSER.add_argument(
        '-b', '--brief',
        action='store_true',
        help='Brief output of the account assets')
    AUDIT_PARSER.add_argument(
        '--false-positive-key',
        action='store_true',
        help='Display the unique "false-positive-key" label to consider those events as false-positive')
    AUDIT_PARSER.add_argument(
        '-s', '--summary',
        action='store_true',
        help='Summary of the account assets')
    AUDIT_PARSER.add_argument(
        '-o', '--output',
        action='store',
        default='',
        help='Save the JSON output inside the specified file')

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
        '-f', '--filter',
        action='store',
        default='',
        help='Filter by asset value (Ex: "something", "port:xxx", "engine:xxx", "version:xxx", "os:xxx"')
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
    DISCOVER_PARSER.add_argument(
        '-o', '--output',
        action='store',
        default='',
        help='Save the JSON output inside the specified file')

    # DRAW Arguments
    DRAW_PARSER = SUBPARSERS.add_parser(
        'draw',
        help='Draw a threat model of your AWS account')
    DRAW_PARSER.add_argument(
        'profile',
        action='store',
        help='A valid profile name configured in the ~/.aws/config file')
    DRAW_PARSER.add_argument(
        '-t', '--type',
        action='append',
        choices=variables.META_TYPES,
        help='Types to display (default: display everything)')
    DRAW_PARSER.add_argument(
        '--limit',
        action='store_true',
        help='Restrict to only interesting assets among vulnerable')
    DRAW_PARSER.add_argument(
        '--all',
        action='store_true',
        help='All assets, without lonely nodes')
    DRAW_PARSER.add_argument(
        '--vpc-peering-dot',
        action='store',
        help='Save VPC peering dot file')

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
        '--only-dangerous-actions',
        action='store_true',
        help='Display IAM dangerous actions only')
    IAM_PARSER.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output of the account assets')

    ARGS = PARSER.parse_args()
    if len(sys.argv) == 1:
        PARSER.print_help()
        sys.exit(0)
    if ARGS.layer:
        generate_layer(variables.FINDING_RULES_PATH)
        sys.exit(0)
    if ARGS.list_profiles:
        for profile in boto3.session.Session().available_profiles:
            print(profile)
        sys.exit(0)
    VERB = 'discover'
    if hasattr(ARGS, 'min_severity'):
        VERB = 'audit'
    elif hasattr(ARGS, 'min_rights'):
        VERB = 'iam'
    elif not hasattr(ARGS, 'filter'):
        VERB = 'draw'
    if ARGS.no_color:
        CONSOLE = None
    main(VERB, ARGS)
