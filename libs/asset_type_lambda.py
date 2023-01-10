#!/usr/bin/env python
"""
Asset types Lambda class

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

from .asset_type import AssetType

# Debug
# from pdb import set_trace as st

class Lambda(AssetType):
    """
    Lambda Asset Type
    """
    def __init__(self, name: str, public: bool=False):
        super().__init__('Lambda', name, public=public)

    def report(self, report, brief=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {}
            if self.security_issues:
                self.update_audit_report(asset_report)
        if 'Lambda' not in report[self.location.region]:
            report[self.location.region]['Lambda'] = \
                { self.name: asset_report }
            return report
        report[self.location.region]['Lambda'].update(
            { self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        return ''

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        return ''
