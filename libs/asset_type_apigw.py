#!/usr/bin/env python
"""
Asset types APIGW class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
from dataclasses import dataclass

# Third party library imports
import botocore

from .asset_type import AssetType

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

class APIGW(AssetType):
    """
    APIGateway Asset Type
    """
    def __init__(
        self,
        name: str,
        api_id: str,
        region_name: str,
        authorization_types: list,
        public: bool=False):
        super().__init__('API Gateway', name, public=public)
        # Ex: https://{restapi-id}.execute-api.{region}.amazonaws.com/{stageName}
        self.api_endpoint = f'https://{api_id}.execute-api.{region_name}.amazonaws.com/'
        self.authorization = Authorization()
        for auth_type in authorization_types:
            self.authorization.add_auth_type(auth_type)
        self.location.region = region_name

    def report(self, report, brief=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {
                'ApiEndpoint': self.api_endpoint,
                'AuthorizationTypes': self.authorization.types
            }
            if self.public:
                asset_report['PubliclyAccessible'] = True
            if self.security_issues:
                self.update_audit_report(asset_report)
        if 'APIGW' not in report[self.location.region]:
            report[self.location.region]['APIGW'] = { self.name: asset_report }
            return report
        report[self.location.region]['APIGW'].update({ self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        if self.public:
            return f'<Public> {self.api_endpoint} Auth:{self.authorization.types}{self.display_brief_audit()}'
        return f'{self.api_endpoint} Auth:{self.authorization.types}{self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        if self.public:
            return f'<Public> {self.api_endpoint} Auth:{self.authorization.types}'
        return f'<Private> {self.api_endpoint} Auth:{self.authorization.types}'

def get_raw_data(raw_data, authorizations, boto_session):
    """
    Get raw data from boto requests.
    Return any API Gateway findings and add a 'False' in authorizations in case of errors
    """
    ag_client = boto_session.client('apigateway')
    try:
        raw_data['ag_raw'] = ag_client.get_rest_apis()['items']
    except botocore.exceptions.ClientError:
        raw_data['ag_raw'] = []
        authorizations['apigw'] = False

    agv2_client = boto_session.client('apigatewayv2')
    raw_data['agv2_client'] = agv2_client
    try:
        raw_data['agv2_raw'] = agv2_client.get_apis()['Items']
    except botocore.exceptions.ClientError:
        raw_data['agv2_raw'] = []
        authorizations['apigw'] = False
    return raw_data, authorizations

def parse_raw_data(assets, authorizations, raw_data, public_only, boto_session, name_filter):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    """
    for apigw in raw_data['ag_raw']:
        is_public = 'REGIONAL' in apigw['endpointConfiguration']['types']
        if public_only and not is_public:
            continue
        asset = APIGW(
            apigw['name'],
            apigw['id'],
            boto_session.region_name,
            [apigw['apiKeySource']],
            public=is_public)
        if asset is not None and name_filter.lower() in asset.name.lower():
            assets.append(asset)
    for apigw in raw_data['agv2_raw']:
        authorization_types = []
        try:
            for route in raw_data['agv2_client'].get_routes(ApiId=apigw['ApiId'])['Items']:
                authorization_types.append(route['AuthorizationType'])
        except botocore.exceptions.ClientError:
            authorizations['apigw'] = False
        asset = APIGW(
            apigw['Name'],
            apigw['ApiId'],
            boto_session.region_name,
            authorization_types,
            public=True)
        if asset is not None and name_filter.lower() in asset.name.lower():
            assets.append(asset)
    return assets, authorizations
