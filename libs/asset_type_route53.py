#!/usr/bin/env python
"""
Asset types Route53 class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Third party library imports
import botocore

from .tools import log_me

@log_me('Getting Route53 raw data...')
def get_raw_data(raw_data, authorizations, boto_session, *_):
    """
    Get raw data from boto requests.
    Return any Route53 findings and add a 'False' in authorizations in case of errors
    """
    try:
        raw_data['route53_client'] = boto_session.client('route53')
    except botocore.exceptions.ClientError:
        authorizations['route53'] = False
    return raw_data, authorizations

def scan(assets, record_value, record):
    """
    Scan Route53
    """
    for i, asset in enumerate(assets):
        asset_type = asset.get_type()
        if asset_type == 'EC2' and record_value in (asset.public_ip, asset.private_ip):
            assets[i].dns_record = record['Name'].replace('\\052', '*')
        elif asset_type == 'ELB' and record_value == f'{asset.name}.':
            assets[i].dns_record = record['Name'].replace('\\052', '*')
    return assets

@log_me('Scanning Route53...')
def parse_raw_data(assets, authorizations, raw_data, cache, _):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    """
    try:
        for hosted_zone in cache.get(
            'r53_list_hosted_zones',
            raw_data['route53_client'],
            'list_hosted_zones')['HostedZones']:
            for record in cache.get_r53_list_resource_record_sets(
                f'r53_{hosted_zone["Name"]}',
                raw_data['route53_client'],
                hosted_zone['Id'])['ResourceRecordSets']:
                if 'ResourceRecords' in record:
                    for record_ in record['ResourceRecords']:
                        if 'Value' not in record_:
                            continue
                        scan(assets, record_['Value'], record)
                elif 'AliasTarget' in record:
                    scan(assets, record['AliasTarget']['DNSName'], record)
    except botocore.exceptions.ClientError:
        authorizations['route53'] = False
    return assets, authorizations
