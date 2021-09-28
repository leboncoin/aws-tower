#!/usr/bin/env python
"""
Asset types IAM Group class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
import logging

from .asset_type import AssetType

# Debug
# from pdb import set_trace as st

LOGGER = logging.getLogger('aws-tower')

class IAMGroup(AssetType):
    """
    IAMGroup Asset Type
    """
    def __init__(self, name: str):
        super().__init__('IAM roles', name)
        self.list = []

    def audit(self, security_config):
        """
        Redefinition of audit
        """
        for asset in self.list:
            asset.audit(security_config)
            self.security_issues = [*self.security_issues, *asset.security_issues]

    def get_type(self):
        """
        Redefinition of get_type
        """
        return 'IAM'

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
                    asset_report[asset.resource_id] = asset.report_brief()
        report[self.name] = asset_report
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        result = ''
        for asset in self.list:
            result += f'[{asset.resource_id}] {asset.report_brief()},'
        return result

    def finding_description(self, finding_title):
        """
        Return a description of the finding
        """
        resource_id = finding_title.split('[')[1].split(']')[0]
        for iam in self.list:
            if iam.resource_id == resource_id:
                return iam.finding_description(resource_id)
        return 'IAM role not found...'
