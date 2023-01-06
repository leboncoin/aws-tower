#!/usr/bin/env python
"""
Asset types S3 Group class

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Third party library imports
import botocore

from .asset_type import AssetType
from .asset_type_s3 import S3
from .tools import log_me, search_filter_in

# Debug
# from pdb import set_trace as st

class S3Group(AssetType):
    """
    S3Group Asset Type
    """
    def __init__(self, name: str):
        super().__init__('S3 buckets', name)
        self.list = []

    def audit(self, security_config):
        """
        Redefinition of audit
        """
        for asset in self.list:
            asset.console = self.console
            asset.audit(security_config)
            self.security_issues = [*self.security_issues, *asset.security_issues]

    def get_type(self):
        """
        Redefinition of get_type
        """
        return 'S3'

    def report(self, report, brief=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {}
            for asset in self.list:
                if asset.report_brief():
                    asset_report[asset.name] = asset.report_brief()
        report[self.name] = asset_report
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        result = ''
        for asset in self.list:
            asset.console = self.console
            result += f'[{asset.name}] {asset.report_brief()},'
        return result

    def finding_description(self, finding_title):
        """
        Return a description of the finding
        """
        name = finding_title.split('[')[1].split(']')[0]
        for iam in self.list:
            if iam.name == name:
                return iam.finding_description(name)
        return 'S3 bucket not found...'

    def remove_not_vulnerable_members(self):
        """
        Remove the non vulnerable members in the AssetGroup.
        """
        new_list = []
        for s3_bucket in self.list:
            if s3_bucket.security_issues:
                new_list.append(s3_bucket)
        self.list = new_list
        return True

@log_me('Getting S3 raw data...')
def get_raw_data(raw_data, authorizations, boto_session, cache, _):
    """
    Get raw data from boto requests.
    Return any S3 findings and add a 'False' in authorizations in case of errors
    """
    s3_client = boto_session.client('s3')
    raw_data['s3_client'] = s3_client
    try:
        raw_data['s3_list_buckets'] = cache.get(
            's3_list_buckets',
            s3_client,
            'list_buckets')['Buckets']
    except botocore.exceptions.ClientError:
        raw_data['s3_list_buckets'] = []
        authorizations['s3'] = False
    return raw_data, authorizations

def scan(s_three, configuration, region, acls, public_only):
    """
    Scan S3 Buckets
    """
    s3_asset = S3(
        name=f's3://{s_three}',
        url=f'https://{s_three}.s3.{region}.amazonaws.com/')
    if configuration is None or not configuration['BlockPublicAcls']:
        s3_asset.acls.block_public_acls = False
    if configuration is None or not configuration['IgnorePublicAcls']:
        s3_asset.acls.block_public_policy = False
    if configuration is None or not configuration['BlockPublicPolicy']:
        s3_asset.acls.ignore_public_acls = False
    if configuration is None or not configuration['RestrictPublicBuckets']:
        s3_asset.acls.restrict_public_buckets = False
    s3_asset.update_grants(acls)
    s3_asset.location.region = region
    if public_only and not s3_asset.public:
        return None
    return s3_asset

@log_me('Scanning S3...')
def parse_raw_data(assets, authorizations, raw_data, name_filter, public_only, cache, _):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    """
    s3group = S3Group(name='S3 buckets')
    for s_three in raw_data['s3_list_buckets']:
        s3bucket = cache.get_asset(f'S3_{s_three["Name"]}')
        if s3bucket is None:
            try:
                public_access_block_configuration = raw_data['s3_client'].get_public_access_block(
                    Bucket=s_three['Name'])['PublicAccessBlockConfiguration']
            except botocore.exceptions.ClientError:
                # Not really an error, the only way to know if it's a public bucket
                public_access_block_configuration = None
            try:
                region = raw_data['s3_client'].get_bucket_location(Bucket=s_three['Name'])['LocationConstraint']
            except botocore.exceptions.ClientError:
                region = None
                authorizations['s3'] = False
            # S3 default region is US East 1
            if region is None or region == 'unknown':
                region = 'us-east-1'
            try:
                acls = raw_data['s3_client'].get_bucket_acl(Bucket=s_three['Name'])['Grants']
            except botocore.exceptions.ClientError:
                acls = []
                authorizations['s3'] = False
            s3bucket = scan(
                s_three['Name'],
                public_access_block_configuration,
                region,
                acls,
                public_only)
            cache.save_asset(f'S3_{s_three["Name"]}', s3bucket)
        if search_filter_in(s3bucket, name_filter):
            s3group.list.append(s3bucket)
    assets.append(s3group)
    return assets, authorizations
