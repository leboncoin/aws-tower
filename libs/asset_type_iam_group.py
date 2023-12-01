#!/usr/bin/env python
"""
Asset types IAM Group class

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Third party library imports
import botocore

from .asset_type import AssetType
from .iam_scan import iam_get_roles, iam_get_users
from .tools import log_me, search_filter_in

# Debug
# from pdb import set_trace as st

class IAMGroup(AssetType):
    """
    IAMGroup Asset Type
    """
    def __init__(self, name: str):
        super().__init__('IAM', name)
        self.list = []

    def audit(self, patterns):
        """
        Redefinition of audit
        """
        for asset in self.list:
            asset.console = self.console
            asset.audit(patterns)
            self.security_issues = [*self.security_issues, *asset.security_issues]

    def get_type(self):
        """
        Redefinition of get_type
        """
        return 'IAM'

    def report(self, report, brief=False, with_fpkey=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {}
            for asset in self.list:
                if asset.report_brief():
                    asset_report[asset.resource_id] = asset.report_brief()
        report[self.name] = asset_report
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        result = ''
        for asset in self.list:
            asset.console = self.console
            result += f'<{asset.resource_id}> {asset.report_brief()},'
        return result

    def finding_description(self, finding_title):
        """
        Return a description of the finding
        """
        resource_id = finding_title.split('[')[1].split(']')[0]
        for iam in self.list:
            if iam.resource_id == resource_id:
                return iam.finding_description(resource_id)
        return 'IAM identity not found...'

    def remove_not_vulnerable_members(self):
        """
        Remove the non vulnerable members in the AssetGroup.
        """
        new_list = []
        for iam in self.list:
            if iam.security_issues:
                new_list.append(iam)
        self.list = new_list
        return True

@log_me('Scanning IAM...')
def parse_raw_data(
    assets,
    authorizations,
    boto_session,
    iam_action_passlist,
    iam_rolename_passlist,
    name_filter,
    cache,
    _):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    Only display EC2 instance profile
    """
    iamgroup = IAMGroup(name='IAM')
    client_iam = boto_session.client('iam')
    resource_iam = boto_session.resource('iam')
    try:
        for role in iam_get_roles(
            client_iam, resource_iam, cache,
            iam_action_passlist=iam_action_passlist,
            iam_rolename_passlist=iam_rolename_passlist):
            if search_filter_in(role, name_filter) and role.is_instance_profile:
                iamgroup.list.append(role)
        for user in iam_get_users(client_iam, cache):
            iamgroup.list.append(user)
    except botocore.exceptions.ClientError:
        authorizations['iam'] = False
    assets.append(iamgroup)
    return assets, authorizations
