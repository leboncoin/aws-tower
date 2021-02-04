#!/usr/bin/env python
"""
Display library

Copyright 2020 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""

# Standard library imports
import json
import logging

from .patterns import Patterns

# Debug
# from pdb import set_trace as st

VERSION = '2.2.1'

LOGGER = logging.getLogger('aws-tower')

def parse_report(report, meta_types):
    """
    Return anomalies from report
    """
    new_report = dict()
    for asset_type in meta_types:
        new_report[asset_type] = list()

    for region in report:
        for vpc in report[region]:
            if not vpc.startswith('vpc-'):
                asset_type = vpc
                if asset_type not in meta_types:
                    continue
                for asset in report[region][asset_type]:
                    report[region][asset_type][asset].update(
                        {'Region Name': region})
                    new_report[asset_type].append(report[region][asset_type][asset])
            else:
                for subnet in report[region][vpc]:
                    mini_name = report[region][vpc][subnet]['Name'].split(f'-{report[region][vpc][subnet]["AvailabilityZone"]}')[0]
                    for asset_type in report[region][vpc][subnet]:
                        if asset_type not in meta_types:
                            continue
                        for asset in report[region][vpc][subnet][asset_type]:
                            report[region][vpc][subnet][asset_type][asset].update(
                                {'Subnet Name': mini_name})
                            new_report[asset_type].append(report[region][vpc][subnet][asset_type][asset])

    return new_report

def remove_key_from_report(report, del_key, is_startswith=False):
    """
    Remove key from report
    """
    key_to_delete = list()
    for key in report:
        if is_startswith and key.startswith(del_key):
            key_to_delete.append(key)
        elif key == del_key:
            key_to_delete.append(key)
    for key in key_to_delete:
        del report[key]
    return report

def scan_mode(report, context):
    """
    This functions is returning an asset_report with security findings,
    it handles the brief mode output
    """
    try:
        patterns = Patterns(
            context['security']['findings_rules_path'],
            context['security']['severity_levels'],
            context['security']['min_severity'],
            context['security']['max_severity']
        )
    except Exception as err_msg:
        LOGGER.critical(err_msg)
        return []
    security_issues = patterns.extract_findings(report)
    if not security_issues:
        return []
    report['SecurityIssues'] = security_issues
    if context['brief']:
        is_public = ''
        if 'PubliclyAccessible' in report and report['PubliclyAccessible']:
            is_public = '[Public] '
        report = dict()
        report[f'{is_public}{context["asset_type"]}: {context["asset_name"]}'] = \
            [f['severity']+": "+f['title'] for f in security_issues]
    return report

def discover_mode(report, context):
    """
    This functions handles the brief mode output for discovery mode
    """
    if context['brief']:
        is_public = ''
        if 'PubliclyAccessible' in report and report['PubliclyAccessible']:
            is_public = '[Public] '
        return f'{is_public}{context["asset_type"]}: {context["asset_name"]}'
    return report

def update_asset_report(new_report, report, context):
    """
    This functions updates the new report by the given report,
    it handles the brief and verbose output
    """
    # Keep SecurityGroups only in verbose mode
    if not context['verbose'] and 'SecurityGroups' in report:
        del report['SecurityGroups']
    if context['brief']:
        new_report.append(report)
    else:
        # Put the asset_type between Subnet and Asset
        if context['asset_type'] not in new_report:
            new_report[context['asset_type']] = list()
        if 'Type' in report:
            del report['Type']
        new_report[context['asset_type']].append(report)
    return new_report

def update_asset_type_report(new_report, report, context):
    """
    This functions updates the current report by the given asset_report
    """
    if context['asset_type'] not in context['meta_types']:
        return new_report
    region = context['region']
    vpc = context['vpc']
    subnet = context['subnet']
    subnet_slug = context['subnet_slug']
    asset_type = context['asset_type']
    meta_types = context['meta_types']
    if context['vpc'] is None:
        for asset in report[region][asset_type]:
            asset_report = report[region][asset_type][asset]
            context['asset'] = asset
            context['asset_name'] = asset_report[meta_types[asset_type]['Name']]

            if context['security']:
                asset_report = scan_mode(
                    asset_report,
                    context)
                if not asset_report:
                    continue
            else:
                asset_report = discover_mode(
                    asset_report,
                    context)

            # Update the new report
            new_report[region][asset_type] = update_asset_report(
                new_report[region][asset_type],
                asset_report,
                context)
    else:
        for asset in report[region][vpc][subnet][asset_type]:
            asset_report = report[region][vpc][subnet][asset_type][asset]
            context['asset'] = asset
            context['asset_name'] = asset_report[meta_types[asset_type]['Name']]

            if context['security']:
                asset_report = scan_mode(
                    asset_report,
                    context)
                if not asset_report:
                    continue
            else:
                asset_report = discover_mode(
                    asset_report,
                    context)

            # Update the new report
            new_report[region][vpc][subnet_slug] = update_asset_report(
                new_report[region][vpc][subnet_slug],
                asset_report,
                context)
    return new_report

def print_subnet(report, meta_types, brief=False, verbose=False, security=None):
    """
    Print subnets
    """
    new_report = dict()
    context = {
        'region': None,
        'vpc': None,
        'subnet': None,
        'subnet_slug': None,
        'asset_type': None,
        'asset': None,
        'brief': brief,
        'verbose': verbose,
        'security': security,
        'meta_types': meta_types
        }
    for region in report:
        context['region'] = region
        new_report[region] = dict()
        for vpc in report[region]:
            if not vpc.startswith('vpc-'):
                context['vpc'] = None
                context['subnet'] = None
                context['subnet_slug'] = None
                context['asset_type'] = vpc
                if brief:
                    new_report[region][vpc] = list()
                new_report = update_asset_type_report(
                    new_report,
                    report,
                    context)
            else:
                context['vpc'] = vpc
                new_report[region][vpc] = dict()
                for subnet in report[region][vpc]:
                    context['subnet'] = subnet
                    context['subnet_slug'] = report[region][vpc][subnet]['Name'].split(
                        f'-{report[region][vpc][subnet]["AvailabilityZone"]}')[0]
                    if not context['subnet_slug'] in new_report[region][vpc]:
                        if brief:
                            new_report[region][vpc][context['subnet_slug']] = list()
                        else:
                            new_report[region][vpc][context['subnet_slug']] = dict()
                    for asset_type in report[region][vpc][subnet]:
                        context['asset_type'] = asset_type
                        new_report = update_asset_type_report(
                            new_report,
                            report,
                            context)
                    # Remove empty Subnet if brief mode
                    if brief and not new_report[region][vpc][context['subnet_slug']]:
                        del new_report[region][vpc][context['subnet_slug']]
                # Remove empty VPC if brief mode
                if brief and not new_report[region][vpc]:
                    del new_report[region][vpc]

    LOGGER.warning(json.dumps(new_report, sort_keys=True, indent=4))
    return True

def gen_init_report(security):
    """
    Generate an empty asset report summary
    """
    report = {
        'count': 0,
        'public': 0,
    }
    if security:
        report = {**report, **{
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }}
    return report

def update_severity(report, security):
    """
    Updates the severity in report for summary
    """
    if not security or 'severity_levels' not in security:
        return report
    for severity in security['severity_levels']:
        report[severity] += security['severity_levels'][severity]
    return report

def print_summary(report, meta_types, security):
    """
    Print summary
    """
    new_report = dict()
    for region in report:
        for vpc in report[region]:
            if not vpc.startswith('vpc-'):
                asset_type = vpc
                if asset_type not in meta_types:
                    continue
                if asset_type not in new_report:
                    new_report[asset_type] = gen_init_report(security)
                for asset in report[region][asset_type]:
                    new_report[asset_type]['count'] += 1
                    if report[region][asset_type][asset]['PubliclyAccessible']:
                        new_report[asset_type]['public'] += 1
                    new_report[asset_type] = update_severity(new_report[asset_type], security)
            else:
                for subnet in report[region][vpc]:
                    for asset_type in report[region][vpc][subnet]:
                        if asset_type not in meta_types:
                            continue
                        if asset_type not in new_report:
                            new_report[asset_type] = gen_init_report(security)
                        for asset in report[region][vpc][subnet][asset_type]:
                            new_report[asset_type]['count'] += 1
                            if report[region][vpc][subnet][asset_type][asset]['PubliclyAccessible']:
                                new_report[asset_type]['public'] += 1
                            new_report[asset_type] = update_severity(new_report[asset_type], security)
    LOGGER.warning(json.dumps(new_report, sort_keys=False, indent=4))
