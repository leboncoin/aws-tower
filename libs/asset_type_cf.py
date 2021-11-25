#!/usr/bin/env python
"""
Asset types CloudFront class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
from dataclasses import dataclass

# Third party library imports
import botocore

from .asset_type import AssetType
from .tools import log_me

# Debug
# from pdb import set_trace as st

@dataclass
class Authorization:
    """
    List of Authorization Types
    """
    types: str = ''
    has_no_auth_endpoint: bool = False

    def add_auth_type(self, auth_type):
        """
        Add an auth type to the list represented by a string
        """
        if self.types:
            types = list(set(self.types.split(',') + [auth_type]))
            types.sort()
            self.types = ','.join(types)
        else:
            self.types = auth_type
        if auth_type == 'NONE':
            self.has_no_auth_endpoint = True

class CloudFront(AssetType):
    """
    CloudFront Asset Type
    """
    def __init__(
        self,
        name: str,
        aliases: str,
        authorization_types: list,
        public: bool=False):
        super().__init__('CloudFront', name, public=public)
        self.aliases = aliases
        self.authorization = Authorization()
        for auth_type in authorization_types:
            self.authorization.add_auth_type(auth_type)
        self.location.region = 'global'

    def report(self, report, brief=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {
                'Aliases': self.aliases,
                'AuthorizationTypes': self.authorization.types
            }
            if self.public:
                asset_report['PubliclyAccessible'] = '[red]True[/red]'
            if self.security_issues:
                self.update_audit_report(asset_report)
        if 'CloudFront' not in report[self.location.region]:
            report[self.location.region]['CloudFront'] = { self.name: asset_report }
            return report
        report[self.location.region]['CloudFront'].update({ self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        if self.public:
            return f'<Public> {self.aliases} Auth:{self.authorization.types}{self.display_brief_audit()}'
        return f'{self.aliases} Auth:{self.authorization.types}{self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        if self.public:
            return f'<Public> {self.aliases} Auth:{self.authorization.types}'
        return f'<Private> {self.aliases} Auth:{self.authorization.types}'


@log_me('Getting Cloudfront raw data...')
def get_raw_data(raw_data, authorizations, boto_session, _):
    """
    Get raw data from boto requests.
    Return any Cloudfront findings and add a 'False' in authorizations in case of errors
    """
    cf_client = boto_session.client('cloudfront')
    try:
        raw_data['cf_raw'] = cf_client.list_distributions()['DistributionList']
    except botocore.exceptions.ClientError:
        raw_data['cf_raw'] = []
        authorizations['cloudfront'] = False
    return raw_data, authorizations

def scan(cf_dist):
    """
    Scan CloudFront
    """
    if not cf_dist['Enabled']:
        return None
    aliases = []
    if 'Aliases' in cf_dist and 'Items' in cf_dist['Aliases']:
        aliases = cf_dist['Aliases']['Items']
    authorization_types = []
    if 'WebACLId' in cf_dist and cf_dist['WebACLId']:
        authorization_types.append('WebACL')
    if 'DefaultCacheBehavior' in cf_dist and \
        'LambdaFunctionAssociations' in cf_dist['DefaultCacheBehavior'] and \
        'Items' in cf_dist['DefaultCacheBehavior']['LambdaFunctionAssociations']:
        for l_edge in cf_dist['DefaultCacheBehavior']['LambdaFunctionAssociations']['Items']:
            # Suppose that an authentication lambda has "auth" in its name...
            if 'auth' in l_edge['LambdaFunctionARN']:
                authorization_types.append('Lambda')
    if not authorization_types:
        authorization_types = ['NONE']
    return CloudFront(
        cf_dist['DomainName'],
        aliases,
        authorization_types,
        public=True)

@log_me('Scanning Cloudfront...')
def parse_raw_data(assets, authorizations, raw_data, name_filter, _):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    """
    if 'Items' in raw_data['cf_raw']:
        for cf_dist in raw_data['cf_raw']['Items']:
            asset = scan(cf_dist)
            if asset is not None and name_filter.lower() in asset.name.lower():
                assets.append(asset)
    return assets, authorizations
