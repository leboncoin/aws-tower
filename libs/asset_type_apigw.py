#!/usr/bin/env python
"""
Asset types APIGW class

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
from dataclasses import dataclass

# Third party library imports
import botocore

from .asset_type import AssetType
from .asset_type_lambda import Lambda
from .tools import get_lambda_name, log_me, search_filter_in

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
        self.backend_endpoint = []
        self.domain_name = None

    def report(self, report, brief=False, with_fpkey=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {
                'ApiEndpoint': self.api_endpoint,
                'AuthorizationTypes': self.authorization.types,
                'Backend Endpoints': self.backend_endpoint
            }
            if self.domain_name:
                asset_report['Domain Name'] = self.domain_name
            if self.public:
                asset_report['PubliclyAccessible'] = '[red]True[/red]'
            if self.security_issues:
                self.update_audit_report(asset_report, with_fpkey)
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

    def dst_linked_assets(self, assets):
        """
        Among all asset, find assets linked to the APIGW in destination
        """
        result = set()
        for asset in assets:
            if asset.get_type() == 'Lambda' and f'lambda:{asset.name}' in self.backend_endpoint:
                result.add(asset)
        return result

@log_me('Getting API Gateway raw data...')
def get_raw_data(raw_data, authorizations, boto_session, cache, _):
    """
    Get raw data from boto requests.
    Return any API Gateway findings and add a 'False' in authorizations in case of errors
    """
    ag_client = boto_session.client('apigateway')
    try:
        raw_data['ag_raw'] = cache.get(
            'ag_get_rest_apis',
            ag_client,
            'get_rest_apis')['items']
        raw_data['ag_rest_api_raw'] = {}
        for rest_api in raw_data['ag_raw']:
            raw_data['ag_rest_api_raw'][rest_api['id']] = []
            resources = ag_client.get_resources(restApiId=rest_api['id'])['items']
            for resource in resources:
                if 'resourceMethods' not in resource or 'GET' not in resource['resourceMethods']:
                    continue
                raw_data['ag_rest_api_raw'][rest_api['id']].append(
                    ag_client.get_integration(
                        restApiId=rest_api['id'],
                        resourceId=resource['id'],
                        httpMethod='GET'))
    except botocore.exceptions.ClientError as err_msg:
        authorizations['apigw'] = False

    agv2_client = boto_session.client('apigatewayv2')
    raw_data['agv2_client'] = agv2_client
    try:
        raw_data['agv2_raw'] = cache.get(
            'agv2_get_apis',
            agv2_client,
            'get_apis')['Items']
        raw_data['agv2_rest_api_raw'] = {}
        for rest_api in raw_data['agv2_raw']:
            raw_data['agv2_rest_api_raw'][rest_api['ApiId']] = agv2_client.get_integrations(
                    ApiId=rest_api['ApiId'])['Items']
    except botocore.exceptions.ClientError:
        raw_data['agv2_raw'] = []
        authorizations['apigw'] = False

    lambda_client = boto_session.client('lambda')
    try:
        raw_data['lambda_raw'] = cache.get(
            'lambda_get_functions',
            lambda_client,
            'list_functions')['Functions']
    except botocore.exceptions.ClientError as err_msg:
        authorizations['apigw'] = False

    # Get domain API mapping
    all_domains = cache.get(
        'ag_get_domain_names',
        ag_client,
        'get_domain_names')['items']
    raw_data['ag_domain_raw'] = {}
    for domain in all_domains:
        raw_data['ag_domain_raw'][domain['domainName']] = \
            ag_client.get_base_path_mappings(domainName=domain['domainName'])

    return raw_data, authorizations

@log_me('Scanning API Gateway...')
def parse_raw_data(assets, authorizations, raw_data, public_only, boto_session, name_filter, cache, _):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    """
    if 'ag_raw' in raw_data:
        for apigw in raw_data['ag_raw']:
            asset = cache.get_asset(f'APIGW_{apigw["name"]}')
            if asset is None:
                is_public = 'REGIONAL' in apigw['endpointConfiguration']['types']
                if public_only and not is_public:
                    continue
                asset = APIGW(
                    apigw['name'],
                    apigw['id'],
                    boto_session.region_name,
                    [apigw['apiKeySource']],
                    public=is_public)
                for rest_api in raw_data['ag_rest_api_raw'][apigw['id']]:
                    if 'uri' not in rest_api:
                        rest_api['uri'] = 'unknown'
                    asset.backend_endpoint.append(
                        get_lambda_name(rest_api['uri']))
                for domain in raw_data['ag_domain_raw']:
                    if 'items' in raw_data['ag_domain_raw'][domain] and \
                        raw_data['ag_domain_raw'][domain]['items'][0] and \
                        raw_data['ag_domain_raw'][domain]['items'][0]['restApiId'] == apigw['id']:
                        asset.domain_name = domain
                cache.save_asset(f'APIGW_{apigw["name"]}', asset)
            if asset is not None and name_filter.lower() in asset.name.lower():
                assets.append(asset)
    if 'agv2_raw' in raw_data:
        for apigw in raw_data['agv2_raw']:
            asset = cache.get_asset(f'APIGW_{apigw["Name"]}')
            if asset is None:
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
                for rest_api in raw_data['agv2_rest_api_raw'][apigw['ApiId']]:
                    asset.backend_endpoint.append(
                        get_lambda_name(rest_api['IntegrationUri']))
                for domain in raw_data['ag_domain_raw']:
                    if 'items' in raw_data['ag_domain_raw'][domain] and \
                        raw_data['ag_domain_raw'][domain]['items'][0] and \
                        raw_data['ag_domain_raw'][domain]['items'][0]['restApiId'] == apigw['ApiId']:
                        asset.domain_name = domain
                cache.save_asset(f'APIGW_{apigw["Name"]}', asset)
            if search_filter_in(asset, name_filter):
                assets.append(asset)
    if 'lambda_raw' in raw_data:
        for lambda_fun in raw_data['lambda_raw']:
            asset = cache.get_asset(f'LAMBDA_{lambda_fun["FunctionName"]}')
            if asset is None:
                authorization_types = []
                asset = Lambda(lambda_fun['FunctionName'])
                cache.save_asset(f'LAMBDA_{lambda_fun["FunctionName"]}', asset)
            if search_filter_in(asset, name_filter):
                assets.append(asset)
    return assets, authorizations
