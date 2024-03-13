#!/usr/bin/env python
"""
Asset types VPC class

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Third party library imports
import botocore

from config import variables
from .asset_type import AssetType
from .tools import get_account_in_arn, get_tag, log_me, search_filter_in

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
        is_endpoint_service: bool=False,
        is_vpn: bool=False,
        public: bool=False):
        super().__init__('VPC', name, public=public)
        # VPC Peering
        self.is_peering = is_peering
        self.is_trusted_peering = False
        self.src_account_id = 'unknown'
        self.src_region_id = ''
        self.dst_account_id = 'unknown'
        self.dst_region_id = ''
        # VPC Endpoint Services
        self.is_endpoint_service = is_endpoint_service
        self.has_untrusted_accounts = False
        self.untrusted_accounts = set()
        # VPC VPN Endpoints
        self.is_vpn = is_vpn
        self.endpoint = 'unknown'
        self.port = 'unknown'

    def report(self, report, brief=False, with_fpkey=False):
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
            elif self.is_endpoint_service and self.public:
                asset_report['Public'] = '[red]True[/red]'
            elif self.is_endpoint_service and self.has_untrusted_accounts:
                asset_report['Untrusted Accounts'] = f'[red]{list(self.untrusted_accounts)}[/red]'
            elif self.is_vpn:
                asset_report['Endpoint'] = self.endpoint
                asset_report['Port'] = self.port
            if self.security_issues:
                self.update_audit_report(asset_report, with_fpkey)
        if 'VPC' not in report:
            report['VPC'] = { self.name: asset_report }
            return report
        report['VPC'].update({ self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        message = ''
        if self.is_peering:
            message = f'{self.src_account_id}:{self.src_region_id} <-> {self.dst_account_id}:{self.dst_region_id}'
        elif self.is_endpoint_service:
            message = '<Private>'
            if self.public:
                message = '[red]<Public>[/red]'
            if self.has_untrusted_accounts:
                message += ' [red]Untrusted Accounts[/red]'
        elif self.is_vpn:
            message = f'{self.port} {self.endpoint}'
        return f'{message}{self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        message = ''
        if self.is_peering:
            message = f'{self.src_account_id}:{self.src_region_id} <-> {self.dst_account_id}:{self.dst_region_id}'
        elif self.is_endpoint_service:
            message = '<Private>'
            if self.public:
                message = '[red]<Public>[/red]'
        elif self.is_vpn:
            message = f'{self.port} {self.endpoint}'
        return message

@log_me('Getting VPC raw data...')
def get_raw_data(raw_data, authorizations, boto_session, cache, _):
    """
    Get raw data from boto requests.
    Return any VPC findings and add a 'False' in authorizations in case of errors
    """
    try:
        ec2 = boto_session.client('ec2')
        # VPC Peering
        vpc_peering_describe = cache.get(
            'vpc_peering_describe',
            ec2,
            'describe_vpc_peering_connections')
        raw_data['vpc_peering_raw'] = vpc_peering_describe['VpcPeeringConnections']
        # VPC Endpoint Services
        endpoint_services = cache.get(
            'vpc_endpoint_services_describe',
            ec2,
            'describe_vpc_endpoint_services')
        raw_data['vpc_endpoint_services_raw'] = [ i for i in endpoint_services['ServiceDetails'] if  i['Owner'] != 'amazon']
        raw_data['vpc_endpoint_services_perm_raw'] = {}
        for endpoint_service in raw_data['vpc_endpoint_services_raw']:
            raw_data['vpc_endpoint_services_perm_raw'][endpoint_service['ServiceId']] = \
                cache.get_vpc_endpoint_services_permission(
                f'vpc_es_perm_{endpoint_service["ServiceId"]}', ec2, endpoint_service['ServiceId'])
        # VPN Endpoints
        raw_data['vpc_vpn_endpoints'] = cache.get(
            'vpc_vpn_endpoints',
            ec2,
            'describe_client_vpn_endpoints')['ClientVpnEndpoints']
    except botocore.exceptions.ClientError:
        authorizations['vpc'] = False
    return raw_data, authorizations

@log_me('Scanning VPC...')
def parse_raw_data(assets, authorizations, raw_data, name_filter, public_only, cache, _):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    """
    trusted_accounts_list_path = variables.TRUSTED_ACCOUNTS_LIST_PATH
    trusted_accounts_list = []
    if trusted_accounts_list_path.exists():
        trusted_accounts_list = trusted_accounts_list_path.read_text(
            encoding='ascii', errors='ignore').split('\n')
    # Remove account name comment
    trusted_accounts_list = [ i.split(':')[0] for i in trusted_accounts_list ]

    # VPC Peering
    if 'vpc_peering_raw' not in raw_data:
        authorizations['vpc'] = False
    else:
        for vpc_peering in raw_data['vpc_peering_raw']:
            asset = cache.get_asset(f'VPC_P_{vpc_peering["VpcPeeringConnectionId"]}')
            if asset is None:
                asset_name = f'peering:{get_tag(vpc_peering["Tags"], "Name")}'
                if asset_name == 'peering:':
                    asset_name = f'peering:{vpc_peering["VpcPeeringConnectionId"]}'
                asset = VPC(name=asset_name, is_peering=True)
                asset.src_account_id = vpc_peering['AccepterVpcInfo']['OwnerId']
                asset.src_region_id = vpc_peering['AccepterVpcInfo']['Region']
                asset.dst_account_id = vpc_peering['RequesterVpcInfo']['OwnerId']
                asset.dst_region_id = vpc_peering['RequesterVpcInfo']['Region']
                asset.is_trusted_peering = \
                    asset.src_account_id in trusted_accounts_list and \
                    asset.dst_account_id in trusted_accounts_list
                cache.save_asset(f'VPC_P_{vpc_peering["VpcPeeringConnectionId"]}', asset)
            if search_filter_in(asset, name_filter):
                assets.append(asset)
    # VPC Endpoint Services
    if 'vpc_endpoint_services_raw' not in raw_data:
        authorizations['vpc'] = False
    else:
        for vpc_endpoint_service in raw_data['vpc_endpoint_services_raw']:
            if vpc_endpoint_service['ServiceId'] not in raw_data['vpc_endpoint_services_perm_raw']:
                continue
            asset = cache.get_asset(f'VPC_ES_{vpc_endpoint_service["ServiceId"]}')
            if asset is None:
                asset_name = f'endpoint_service:{get_tag(vpc_endpoint_service["Tags"], "Name")}'
                if asset_name == 'endpoint_service:':
                    asset_name = f'endpoint_service:{vpc_endpoint_service["ServiceId"]}'
                asset = VPC(name=asset_name, is_endpoint_service=True)
                asset.public = True in [
                    '*' in i['Principal']
                    for i in raw_data['vpc_endpoint_services_perm_raw'][vpc_endpoint_service['ServiceId']]['AllowedPrincipals']
                ]
                for allowed_principal in raw_data['vpc_endpoint_services_perm_raw'][vpc_endpoint_service['ServiceId']]['AllowedPrincipals']:
                    aws_account_id = get_account_in_arn(allowed_principal['Principal'])
                    if aws_account_id not in trusted_accounts_list:
                        asset.untrusted_accounts.add(aws_account_id)
                asset.has_untrusted_accounts = asset.untrusted_accounts != set()
                cache.save_asset(f'VPC_ES_{vpc_endpoint_service["ServiceId"]}', asset)
                if public_only and not asset.public:
                    asset = None
            if search_filter_in(asset, name_filter):
                assets.append(asset)
    # VPC VPN Endpoints
    if 'vpc_vpn_endpoints' not in raw_data:
        authorizations['vpc'] = False
    else:
        for vpc_vpn in raw_data['vpc_vpn_endpoints']:
            asset = cache.get_asset(f'VPC_VPN_{vpc_vpn["ClientVpnEndpointId"]}')
            if asset is None:
                asset_name = f'vpn:{get_tag(vpc_vpn["Tags"], "Name")}'
                if asset_name == 'vpn:':
                    asset_name = f'vpn:{vpc_vpn["ClientVpnEndpointId"]}'
                asset = VPC(name=asset_name, is_vpn=True, public=True)
                asset.endpoint = vpc_vpn['DnsName'].replace('*.', '')
                asset.port = f'{vpc_vpn["TransportProtocol"].upper()}/{vpc_vpn["VpnPort"]}'
                cache.save_asset(f'VPC_VPN_{vpc_vpn["ClientVpnEndpointId"]}', asset)
                if public_only and not asset.public:
                    asset = None
            if search_filter_in(asset, name_filter):
                assets.append(asset)
    return assets, authorizations
