#!/usr/bin/env python
"""
Asset types MQ class

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Third party library imports
import botocore

from .asset_type import AssetType
from .tools import log_me, search_filter_in

# Debug
# from pdb import set_trace as st

class MQ(AssetType):
    """
    MQ Asset Type
    """
    def __init__(
        self,
        name: str,
        engine: str,
        url: str,
        public: bool=False):
        super().__init__('MQ', name, public=public)
        self.engine = engine
        self.url = url

    def report(self, report, brief=False, with_fpkey=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {
                'URL': self.url,
                'Engine': self.engine
            }
            if self.public:
                asset_report['PubliclyAccessible'] = '[red]True[/red]'
            if self.security_issues:
                self.update_audit_report(asset_report, with_fpkey)
        if 'MQ' not in report[self.location.region]:
            report[self.location.region]['MQ'] = { self.name: asset_report }
            return report
        report[self.location.region]['MQ'].update({ self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        if self.public:
            return f'<Public> {self.name}{self.display_brief_audit()}'
        return f'{self.name}{self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        if self.public:
            return f'<Public> {self.name}'
        return f'<Private> {self.name}'


@log_me('Getting MQ raw data...')
def get_raw_data(raw_data, authorizations, boto_session, cache, _):
    """
    Get raw data from boto requests.
    Return any MQ findings and add a 'False' in authorizations in case of errors
    """
    mq_client = boto_session.client('mq')
    raw_data['mq_brokers_raw'] = {}
    try:
        raw_data['mq_raw'] = cache.get(
            'mq_list_brokers',
            mq_client,
            'list_brokers')['BrokerSummaries']
        for mq_broker in raw_data['mq_raw']:
            raw_data['mq_brokers_raw'][mq_broker['BrokerId']] = mq_client.describe_broker(BrokerId=mq_broker['BrokerId'])
    except botocore.exceptions.ClientError:
        raw_data['mq_raw'] = []
        authorizations['mq'] = False
    return raw_data, authorizations

def scan(mq_broker, raw_data, public_only):
    """
    Scan MQ
    """
    asset = MQ(mq_broker['BrokerName'], '', '', False)
    if mq_broker['BrokerId'] not in raw_data['mq_brokers_raw']:
        return asset
    asset.public = raw_data['mq_brokers_raw'][mq_broker['BrokerId']]['PubliclyAccessible']
    asset.engine = f"{raw_data['mq_brokers_raw'][mq_broker['BrokerId']]['EngineType']}=={raw_data['mq_brokers_raw'][mq_broker['BrokerId']]['EngineVersion']}"
    if len(raw_data['mq_brokers_raw'][mq_broker['BrokerId']]['BrokerInstances']) > 0:
        asset.url = raw_data['mq_brokers_raw'][mq_broker['BrokerId']]['BrokerInstances'][0]['ConsoleURL']
    asset.location.region = raw_data['mq_brokers_raw'][mq_broker['BrokerId']]['BrokerArn'].split(':')[3]
    return asset

@log_me('Scanning MQ...')
def parse_raw_data(assets, authorizations, raw_data, name_filter, public_only, cache, _):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    """
    for mq_broker in raw_data['mq_raw']:
        asset = cache.get_asset(f'MQ_{mq_broker["BrokerName"]}')
        if asset is None:
            asset = scan(mq_broker, raw_data, public_only)
            cache.save_asset(f'MQ_{mq_broker["BrokerName"]}', asset)
        # If the MQ is disabled
        if asset is None:
            continue
        if search_filter_in(asset, name_filter) and not (public_only and not asset.public):
            assets.append(asset)
    return assets, authorizations
