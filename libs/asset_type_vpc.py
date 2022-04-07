#!/usr/bin/env python
"""
Asset types VPC class

Copyright 2020-2022 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

from pathlib import Path

# Third party library imports
import botocore

from .asset_type import AssetType
from .tools import get_tag, log_me

# Debug
# from pdb import set_trace as st

class VPC(AssetType):
    """
    VPC Asset Type
    """
    def __init__(
        self,
        name: str,
        is_peering: bool=False,
        public: bool=False):
        super().__init__('VPC', name, public=public)
        self.is_peering = is_peering
        self.is_trusted_peering = False
        self.src_account_id = 'unknown'
        self.src_region_id = ''
        self.dst_account_id = 'unknown'
        self.dst_region_id = ''

    def report(self, report, brief=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {}
            if self.is_peering:
                asset_report['Link'] = \
                    f'{self.src_account_id}:{self.src_region_id} <-> {self.dst_account_id}:{self.dst_region_id}'
            if self.security_issues:
                self.update_audit_report(asset_report)
        if 'VPC' not in report:
            report['VPC'] = { self.name: asset_report }
            return report
        report['VPC'].update({ self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        return f'{self.src_account_id}:{self.src_region_id} <-> {self.dst_account_id}:{self.dst_region_id}{self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        return f'{self.src_account_id}:{self.src_region_id} <-> {self.dst_account_id}:{self.dst_region_id}'

@log_me('Getting VPC raw data...')
def get_raw_data(raw_data, authorizations, boto_session, cache, _):
    """
    Get raw data from boto requests.
    Return any VPC findings and add a 'False' in authorizations in case of errors
    """
    try:
        ec2 = boto_session.client('ec2')
        vpc_peering_describe = cache.get('vpc_peering_describe', ec2, 'describe_vpc_peering_connections')
        raw_data['vpc_peering_raw'] = vpc_peering_describe['VpcPeeringConnections']
    except botocore.exceptions.ClientError:
        authorizations['vpc'] = False
    return raw_data, authorizations

# @log_me('Scanning VPC...')
def parse_raw_data(assets, authorizations, raw_data, name_filter, public_only, cache, _):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    """
    trusted_accounts_list_path = Path('config/trusted_accounts_list.txt')
    if trusted_accounts_list_path.exists():
        trusted_accounts_list = trusted_accounts_list_path.read_text(
            encoding='ascii', errors='ignore').split('\n')

    for vpc_peering in raw_data['vpc_peering_raw']:
        asset = cache.get_asset(f'VPC_P_{vpc_peering["VpcPeeringConnectionId"]}')
        if asset is None:
            asset_name = f'peering:{get_tag(vpc_peering["Tags"], "Name")}'
            if asset_name == 'peering:':
                asset_name = vpc_peering['VpcPeeringConnectionId']
            asset = VPC(name=asset_name, is_peering=True)
            asset.src_account_id = vpc_peering['AccepterVpcInfo']['OwnerId']
            asset.src_region_id = vpc_peering['AccepterVpcInfo']['Region']
            asset.dst_account_id = vpc_peering['RequesterVpcInfo']['OwnerId']
            asset.dst_region_id = vpc_peering['RequesterVpcInfo']['Region']
            asset.is_trusted_peering = \
                asset.src_account_id in trusted_accounts_list and \
                asset.dst_account_id in trusted_accounts_list
            cache.save_asset(f'VPC_{vpc_peering["VpcPeeringConnectionId"]}', asset)
        if asset is not None and name_filter.lower() in asset.name.lower():
            assets.append(asset)
    return assets, authorizations
