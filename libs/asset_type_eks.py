#!/usr/bin/env python
"""
Asset types EKS class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Third party library imports
import botocore

from .asset_type import AssetType
from .tools import get_network, log_me

# Debug
# from pdb imports set_trace as st

class EKS(AssetType):
    """
    EKS Asset Type
    """
    def __init__(
        self,
        name: str,
        endpoint: str,
        public: bool,
        version: str):
        super().__init__('EKS', name, public=public)
        self.endpoint = endpoint
        self.version = version

    def report(self, report, brief=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {
                'Endpoint': self.endpoint,
                'Version': self.version
            }
            if self.public:
                asset_report['PubliclyAccessible'] = True
            if self.security_issues:
                self.update_audit_report(asset_report)
        if 'EKS' not in report[self.location.region]:
            report[self.location.region]['EKS'] = { self.name: asset_report }
            return report
        report[self.location.region]['EKS'].update({ self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        if self.public:
            return f'<Public> {self.endpoint} Auth:{self.version}{self.display_brief_audit()}'
        return f'<Private> {self.endpoint} Auth:{self.version}{self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        if self.public:
            return f'<Public> {self.endpoint} Auth:{self.version}'
        return f'<Private> {self.endpoint} Auth:{self.version}'


@log_me('Getting EKS raw data...')
def get_raw_data(raw_data, authorizations, boto_session, _):
    """
    Get raw data from boto requests.
    Return any EKS findings and add a 'False' in authorizations in case of errors
    """
    eks_client = boto_session.client('eks')
    raw_data['eks_raw'] = {}
    try:
        clusters = eks_client.list_clusters()
        if 'clusters' not in clusters:
            authorizations['eks'] = False
            return raw_data, authorizations
        for cluster_name in clusters['clusters']:
            raw_data['eks_raw'][cluster_name] = {}
        for cluster_name in clusters['clusters']:
            raw_data['eks_raw'][cluster_name] = eks_client.describe_cluster(name=cluster_name)['cluster']
    except botocore.exceptions.ClientError:
        authorizations['eks'] = False
    return raw_data, authorizations

@log_me('Scanning EKS...')
def parse_raw_data(assets, authorizations, raw_data, name_filter, _):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    """
    for cluster_name in raw_data['eks_raw']:
        public = 'endpointPublicAccess' in raw_data['eks_raw'][cluster_name] and raw_data['eks_raw'][cluster_name]['endpointPublicAccess']
        endpoint = 'endpoint' in raw_data['eks_raw'][cluster_name] and raw_data['eks_raw'][cluster_name]['endpoint']
        version = 'version' in raw_data['eks_raw'][cluster_name] and raw_data['eks_raw'][cluster_name]['version']
        subnet = raw_data['eks_raw'][cluster_name]['resourcesVpcConfig']['subnetIds'][0]
        region, vpc, _ = get_network(subnet, raw_data['subnets_raw'])
        asset = EKS(name=cluster_name, public=public, endpoint=endpoint, version=version)
        if asset is not None and name_filter.lower() in asset.name.lower():
            asset.location.region = region
            asset.location.vpc = vpc
            assets.append(asset)
    return assets, authorizations
