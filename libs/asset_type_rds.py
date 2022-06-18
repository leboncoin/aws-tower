#!/usr/bin/env python
"""
Asset types RDS class

Copyright 2020-2022 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Third party library imports
import botocore

from .asset_type import AssetType
from .tools import get_network, log_me, search_filter_in

# Debug
# from pdb import set_trace as st

class RDS(AssetType):
    """
    RDS Asset Type
    """
    def __init__(self, name: str, engine: str, url: str='', public: bool=False):
        super().__init__('RDS', name, public=public)
        self.engine = engine
        self.url = url

    def report(self, report, brief=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {
                'Engine': self.engine
            }
            if self.public:
                asset_report['PubliclyAccessible'] = '[red]True[/red]'
            if self.url:
                asset_report['URL'] = self.url
            if self.security_issues:
                self.update_audit_report(asset_report)
        if 'RDS' not in report[self.location.region][self.location.vpc][self.location.subnet]:
            report[self.location.region][self.location.vpc][self.location.subnet]['RDS'] = \
                { self.name: asset_report }
            return report
        report[self.location.region][self.location.vpc][self.location.subnet]['RDS'].update(
            { self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        public = ''
        if self.public:
            return f'[red]<Public>[/red] {self.url} '
        return f'{public}{self.engine}{self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        if self.public:
            return f'<Public> {self.url} {self.engine}'
        return f'<Private> {self.engine}'

@log_me('Getting RDS raw data...')
def get_raw_data(raw_data, authorizations, boto_session, cache, _):
    """
    Get raw data from boto requests.
    Return any RDS findings and add a 'False' in authorizations in case of errors
    """
    rds_client = boto_session.client('rds')
    try:
        # raw_data['rds_raw'] = rds_client.describe_db_instances()['DBInstances']
        raw_data['rds_raw'] = cache.get(
            'rds_describe_db_instances',
            rds_client,
            'describe_db_instances')['DBInstances']
    except botocore.exceptions.ClientError:
        raw_data['rds_raw'] = []
        authorizations['rds'] = False
    return raw_data, authorizations

def scan(rds, subnets_raw, public_only):
    """
    Scan RDS
    """
    if public_only and not rds['PubliclyAccessible']:
        return None
    rds_asset = RDS(
        name=rds['DBInstanceIdentifier'],
        engine=f'{rds["Engine"]}=={rds["EngineVersion"]}',
        public=rds['PubliclyAccessible'])
    region, vpc, _ = get_network(
        rds['DBSubnetGroup']['Subnets'][0]['SubnetIdentifier'],
        subnets_raw)
    rds_asset.location.region = region
    rds_asset.location.vpc = vpc
    rds_asset.location.subnet = rds['AvailabilityZone']
    if 'Endpoint' in rds and 'Address' in rds['Endpoint']:
        rds_asset.url = rds['Endpoint']['Address']
    return rds_asset

@log_me('Scanning RDS...')
def parse_raw_data(assets, authorizations, raw_data, name_filter, public_only, cache, _):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    """
    for rds in raw_data['rds_raw']:
        asset = cache.get_asset(f'RDS_{rds["DBInstanceIdentifier"]}')
        if asset is None:
            asset = scan(
                rds,
                raw_data['subnets_raw'],
                public_only)
            cache.save_asset(f'RDS_{rds["DBInstanceIdentifier"]}', asset)
        if search_filter_in(asset, name_filter):
            assets.append(asset)
    return assets, authorizations
