#!/usr/bin/env python
"""
Asset types ELBv2 class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Third party library imports
import botocore

from .asset_type import AssetType
from .tools import draw_sg, get_network

# Debug
# from pdb import set_trace as st

class ELBV2(AssetType):
    """
    ELBv2 Asset Type
    """
    def __init__(self, name: str, scheme: str, public: bool=False):
        super().__init__('ELB', name, public=public)
        self.scheme = scheme
        self.security_groups = {}
        self.dns_record = None

    def report(self, report, brief=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {
                'Scheme': self.scheme
            }
            if self.public:
                asset_report['PubliclyAccessible'] = True
            if self.security_groups and not self.security_issues:
                asset_report['SecurityGroups'] = self.security_groups
            if self.dns_record:
                asset_report['DnsRecord'] = self.dns_record
            if self.security_issues:
                self.update_audit_report(asset_report)
        if 'ELBv2' not in report[self.location.region][self.location.vpc][self.location.subnet]:
            report[self.location.region][self.location.vpc][self.location.subnet]['ELBv2'] = \
                { self.name: asset_report }
            return report
        report[self.location.region][self.location.vpc][self.location.subnet]['ELBv2'].update(
            { self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        if self.public:
            return f'<Public> {self.display_brief_audit()}'
        return f'[{self.scheme}] {self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        if self.public:
            return f'<Public> {self.dns_record}'
        return f'<{self.scheme}> {self.dns_record}'

def get_raw_data(raw_data, authorizations, boto_session):
    """
    Get raw data from boto requests.
    Return any ELBv2 findings and add a 'False' in authorizations in case of errors
    """
    elbv2_client = boto_session.client('elbv2')
    try:
        raw_data['elbv2_raw'] = elbv2_client.describe_load_balancers()['LoadBalancers']
    except botocore.exceptions.ClientError:
        raw_data['elbv2_raw'] = []
        authorizations['elbv2'] = False
    return raw_data, authorizations

def scan(elbv2, sg_raw, subnets_raw, public_only):
    """
    Scan ELBv2
    """
    if public_only and elbv2['Scheme'] == 'internal':
        return None
    elbv2_asset = ELBV2(
        name=elbv2['DNSName'],
        scheme=elbv2['Scheme'],
        public=elbv2['Scheme'] != 'internal')
    region, vpc, subnet = get_network(elbv2['AvailabilityZones'][0]['SubnetId'], subnets_raw)
    elbv2_asset.location.region = region
    elbv2_asset.location.vpc = vpc
    elbv2_asset.location.subnet = subnet
    if 'SecurityGroups' in elbv2:
        for security_group in elbv2['SecurityGroups']:
            elbv2_asset.security_groups[security_group] = draw_sg(security_group, sg_raw)
    return elbv2_asset

def parse_raw_data(assets, authorizations, raw_data, name_filter, public_only):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    """
    for elbv2 in raw_data['elbv2_raw']:
        asset = scan(elbv2, raw_data['sg_raw'], raw_data['subnets_raw'], public_only)
        if asset is not None and name_filter.lower() in asset.name.lower():
            assets.append(asset)
    return assets, authorizations
