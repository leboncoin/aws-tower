#!/usr/bin/env python
"""
Asset types EC2 class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Third party library imports
import botocore

from .asset_type import AssetType
from .tools import draw_sg, get_tag, get_network, log_me

# Debug
# from pdb import set_trace as st

class EC2(AssetType):
    """
    EC2 Asset Type
    """
    def __init__(self, name: str, private_ip: str, public: bool=False):
        super().__init__('EC2', name, public=public)
        self.os = 'unknown'
        self.private_ip = private_ip
        self.public_ip = ''
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
                'OS': self.os,
                'PrivateIP': self.private_ip
            }
            if self.public:
                asset_report['PubliclyAccessible'] = True
            if self.public_ip:
                asset_report['PublicIP'] = self.public_ip
            if self.security_groups and not self.security_issues:
                asset_report['SecurityGroups'] = self.security_groups
            if self.dns_record:
                asset_report['DnsRecord'] = self.dns_record
            if self.security_issues:
                self.update_audit_report(asset_report)
        if 'EC2' not in report[self.location.region][self.location.vpc][self.location.subnet]:
            report[self.location.region][self.location.vpc][self.location.subnet]['EC2'] = \
                { self.name: asset_report }
            return report
        report[self.location.region][self.location.vpc][self.location.subnet]['EC2'].update(
            { self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        if self.public:
            return f'<Public> {self.public_ip} {self.private_ip}{self.display_brief_audit()}'
        return f'{self.private_ip}{self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        if self.public:
            return f'<Public> {self.public_ip} {self.private_ip}'
        return f'<Private> {self.private_ip}'

@log_me('Getting EC2 raw data...')
def get_raw_data(raw_data, authorizations, boto_session, _):
    """
    Get raw data from boto requests.
    Return any EC2 findings and add a 'False' in authorizations in case of errors
    """
    ec2_client = boto_session.client('ec2')
    try:
        raw_data['ec2_raw'] = ec2_client.describe_instances()['Reservations']
    except botocore.exceptions.ClientError:
        raw_data['ec2_raw'] = []
        authorizations['ec2'] = False
    try:
        raw_data['subnets_raw'] = ec2_client.describe_subnets()['Subnets']
    except botocore.exceptions.ClientError:
        raw_data['subnets_raw'] = []
        authorizations['ec2'] = False
        authorizations['elb'] = False
        authorizations['rds'] = False
    try:
        raw_data['sg_raw'] = ec2_client.describe_security_groups()['SecurityGroups']
    except botocore.exceptions.ClientError:
        raw_data['sg_raw'] = []
        authorizations['ec2'] = False
        authorizations['elb'] = False
    return raw_data, authorizations

def scan(ec2, sg_raw, subnets_raw, boto_session, public_only):
    """
    Scan EC2
    """
    ec2_res = boto_session.resource('ec2')
    if 'VpcId' not in ec2 or 'SubnetId' not in ec2:
        return None
    if public_only and not 'PublicIpAddress' in ec2:
        return None
    ec2_asset = EC2(
        name=ec2['InstanceId'],
        private_ip=ec2['PrivateIpAddress'],
        public='PublicIpAddress' in ec2)
    region, vpc, subnet = get_network(ec2['SubnetId'], subnets_raw)
    ec2_asset.location.region = region
    ec2_asset.location.vpc = vpc
    ec2_asset.location.subnet = subnet
    if 'ImageId' in ec2:
        try:
            ec2_asset.os = ec2_res.Image(ec2['ImageId']).platform_details
        except:
            pass
    if 'Tags' in ec2:
        ec2_asset.name = get_tag(ec2['Tags'], 'Name')
    if 'PublicIpAddress' in ec2:
        ec2_asset.public_ip = ec2['PublicIpAddress']
    if 'SecurityGroups' in ec2:
        for security_group in ec2['SecurityGroups']:
            draw = draw_sg(security_group['GroupId'], sg_raw)
            if draw:
                ec2_asset.security_groups[security_group['GroupId']] = draw
    return ec2_asset

@log_me('Scanning EC2...')
def parse_raw_data(assets, authorizations, raw_data, name_filter, boto_session, public_only, _):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    """
    for ec2 in raw_data['ec2_raw']:
        for ec2_ in ec2['Instances']:
            asset = scan(
                ec2_,
                raw_data['sg_raw'],
                raw_data['subnets_raw'],
                boto_session,
                public_only)
            if asset is not None and name_filter.lower() in asset.name.lower():
                assets.append(asset)
    return assets, authorizations
