#!/usr/bin/env python
"""
Display library

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""

# Standard library imports
import json
import logging

# Debug
# from pdb import set_trace as st

LOGGER = logging.getLogger('aws-tower')

def print_report(assets, meta_types, brief=False, security_config=None):
    """
    Print subnets
    """
    # Construct Region/VPC/subnet
    report = dict()
    for asset in assets:
        if type(asset).__name__ not in meta_types:
            continue
        if asset.location.region is None:
            continue
        if asset.location.region not in report:
            report[asset.location.region] = dict()
        if asset.location.vpc is None:
            continue
        if asset.location.vpc not in report[asset.location.region]:
            report[asset.location.region][asset.location.vpc] = dict()
        if asset.location.subnet is None:
            continue
        if asset.location.subnet not in report[asset.location.region][asset.location.vpc]:
            report[asset.location.region][asset.location.vpc][asset.location.subnet] = dict()

    # Add asset in report
    for asset in assets:
        if security_config:
            asset.audit(security_config)
            if not asset.security_issues:
                continue
        report = asset.report(report, brief=brief)

    LOGGER.warning(json.dumps(report, sort_keys=True, indent=4))
    return True

def print_summary(assets, meta_types, security_config):
    """
    Print summary
    """
    new_report = dict()
    for asset in assets:
        asset_type = asset.get_type()
        if asset_type not in meta_types:
            continue
        if asset_type not in new_report:
            new_report[asset_type] = {'count': 0, 'public': 0}
        new_report[asset_type]['count'] += 1
        if asset.public:
            new_report[asset_type]['public'] += 1
        if security_config:
            asset.audit(security_config)
        if asset.security_issues:
            for issue in asset.security_issues:
                if issue['severity'] not in new_report[asset_type]:
                    new_report[asset_type][issue['severity']] = 1
                else:
                    new_report[asset_type][issue['severity']] += 1
    LOGGER.warning(json.dumps(new_report, sort_keys=False, indent=4))
