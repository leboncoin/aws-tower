#!/usr/bin/env python
"""
Asset types Lightsail class

Copyright 2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas_beguier@hotmail.com)
"""

# Standard imports
from datetime import datetime, timezone

# Third party library imports
import botocore

from .asset_type import AssetType
from .tools import log_me, search_filter_in

# Debug
# from pdb import set_trace as st

class LIGHTSAIL(AssetType):
    """
    LIGHTSAIL Asset Type
    """
    def __init__(self, name: str, private_ip: str, public: bool=False):
        super().__init__('LIGHTSAIL', name, public=public)
        self.operating_system = 'unknown'
        self.operating_system_name = 'unknown'
        self.private_ip = private_ip
        self.public_ip = ''
        self.security_groups = {}
        self.dns_record = None
        self.old_attached_ssh_key = False
        self.ssh_key_days = -1
        self.role_poweruser = ''
        self.role_admin = ''
        self.instance_id = ''

    def report(self, report, brief=False, with_fpkey=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {
                'OS': f'{self.operating_system} ({self.operating_system_name})',
                'PrivateIP': self.private_ip,
                'InstanceID': self.instance_id
            }
            if self.public:
                asset_report['PubliclyAccessible'] = '[red]True[/red]'
            if self.public_ip:
                asset_report['PublicIP'] = self.public_ip
            if self.security_groups and not self.security_issues:
                asset_report['SecurityGroups'] = self.security_groups
            if self.dns_record:
                asset_report['DnsRecord'] = self.dns_record
            if self.old_attached_ssh_key:
                asset_report['SSHKey age'] = f'[yellow]{self.ssh_key_days} days[/yellow]'
            if self.role_poweruser:
                asset_report['Roles PowerUser'] = f'[yellow]{self.role_poweruser}[/yellow]'
            if self.role_admin:
                asset_report['Roles Admin'] = f'[red]{self.role_admin}[/red]'
            if self.security_issues:
                self.update_audit_report(asset_report, with_fpkey)
        if 'LIGHTSAIL' not in report[self.location.region][self.location.vpc][self.location.subnet]:
            report[self.location.region][self.location.vpc][self.location.subnet]['LIGHTSAIL'] = \
                { self.name: asset_report }
            return report
        report[self.location.region][self.location.vpc][self.location.subnet]['LIGHTSAIL'].update(
            { self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        public = ''
        permissions = ''
        if self.public:
            public = f'[red]<Public>[/red] {self.public_ip} '
        if self.role_admin:
            permissions = ' [red]Admin[/red]'
        elif self.role_poweruser:
            permissions = ' [yellow]PowerUser[/yellow]'
        return f'{public}{self.private_ip}{permissions}{self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        if self.public:
            return f'<Public> {self.public_ip} {self.private_ip}'
        return f'<Private> {self.private_ip}'


@log_me('Getting Lightsail raw data...')
def get_raw_data(raw_data, authorizations, boto_session, cache, _):
    """
    Get raw data from boto requests.
    Return any LIGHTSAIL findings and add a 'False' in authorizations in case of errors
    """
    lightsail_client = boto_session.client('lightsail')
    try:
        raw_data['lightsail_raw'] = cache.get(
            'lightsail_get_instances',
            lightsail_client,
            'get_instances')['instances']
    except botocore.exceptions.ClientError:
        raw_data['lightsail_raw'] = []
        authorizations['lightsail'] = False
    return raw_data, authorizations

def scan(lightsail, public_only):
    """
    Scan Lightsail
    """
    if lightsail['state']['name'] != 'running':
        return None
    if public_only and not 'publicIpAddress' in lightsail:
        return None
    ls_asset = LIGHTSAIL(
        name=lightsail['name'],
        private_ip=lightsail['privateIpAddress'],
        public='publicIpAddress' in lightsail)
    ls_asset.instance_id = lightsail['supportCode'].split('/')[1]
    ls_asset.location.region = lightsail['location']['regionName']
    ls_asset.location.vpc = 'lightsail-vpc'
    ls_asset.location.subnet = 'lightsail-subnet'
    ls_asset.operating_system = lightsail['blueprintName']
    if 'publicIpAddress' in lightsail:
        ls_asset.public_ip = lightsail['publicIpAddress']
    if 'networking' in lightsail:
        security_groups = {}
        for port in lightsail['networking']['ports']:
            if port['fromPort'] == port['toPort']:
                security_groups[str(port['fromPort'])] = port['cidrs']
    ls_asset.security_groups['sg-lightsail'] = security_groups
    return ls_asset

@log_me('Scanning Lightsail...')
def parse_raw_data(assets, authorizations, raw_data, name_filter, public_only, cache, _):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    """
    for lightsail in raw_data['lightsail_raw']:
        asset = cache.get_asset(f'LS_{lightsail["supportCode"].replace("/", "_")}')
        if asset is None:
            asset = scan(
                lightsail,
                public_only)
            cache.save_asset(f'LS_{lightsail["supportCode"].replace("/", "_")}', asset)
        if search_filter_in(asset, name_filter):
            assets.append(asset)
    return assets, authorizations
