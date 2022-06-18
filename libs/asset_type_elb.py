#!/usr/bin/env python
"""
Asset types ELB class

Copyright 2020-2022 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Third party library imports
import botocore

from .asset_type import AssetType
from .tools import draw_sg, get_network, log_me, search_filter_in

# Debug
# from pdb import set_trace as st

class ELB(AssetType):
    """
    ELB Asset Type
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
                asset_report['PubliclyAccessible'] = '[red]True[/red]'
            if self.security_groups and not self.security_issues:
                asset_report['SecurityGroups'] = self.security_groups
            if self.dns_record:
                asset_report['DnsRecord'] = self.dns_record
            if self.security_issues:
                self.update_audit_report(asset_report)
        if 'ELB' not in report[self.location.region][self.location.vpc][self.location.subnet]:
            report[self.location.region][self.location.vpc][self.location.subnet]['ELB'] = \
                { self.name: asset_report }
            return report
        report[self.location.region][self.location.vpc][self.location.subnet]['ELB'].update(
            { self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        public = ''
        if self.public:
            public = '[red]<Public>[/red] '
        return f'{public}[{self.scheme}] {self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        if self.public:
            return f'<Public> {self.dns_record}'
        return f'<{self.scheme}> {self.dns_record}'

@log_me('Getting Elastic Load Balancer raw data...')
def get_raw_data(raw_data, authorizations, boto_session, cache, _):
    """
    Get raw data from boto requests.
    Return any ELB findings and add a 'False' in authorizations in case of errors
    """
    elb_client = boto_session.client('elbv2')
    try:
        raw_data['elb_raw'] = cache.get(
            'elb_describe_load_balancers',
            elb_client,
            'describe_load_balancers')['LoadBalancers']
    except botocore.exceptions.ClientError:
        raw_data['elb_raw'] = []
        authorizations['elb'] = False
    return raw_data, authorizations

def scan(elb, sg_raw, subnets_raw, public_only):
    """
    Scan ELB
    """
    if public_only and elb['Scheme'] == 'internal':
        return None
    elb_asset = ELB(
        name=elb['DNSName'],
        scheme=elb['Scheme'],
        public=elb['Scheme'] != 'internal')
    region, vpc, subnet = get_network(elb['AvailabilityZones'][0]['SubnetId'], subnets_raw)
    elb_asset.location.region = region
    elb_asset.location.vpc = vpc
    elb_asset.location.subnet = subnet
    if 'SecurityGroups' in elb:
        for security_group in elb['SecurityGroups']:
            elb_asset.security_groups[security_group] = draw_sg(security_group, sg_raw)
    return elb_asset

@log_me('Scanning Elastic Load Balancer...')
def parse_raw_data(assets, authorizations, raw_data, name_filter, public_only, cache, _):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    """
    for elb in raw_data['elb_raw']:
        asset = cache.get_asset(f'ELB_{elb["DNSName"]}')
        if asset is None:
            asset = scan(elb, raw_data['sg_raw'], raw_data['subnets_raw'], public_only)
            cache.save_asset(f'ELB_{elb["DNSName"]}', asset)
        if search_filter_in(asset, name_filter):
            assets.append(asset)
    return assets, authorizations
