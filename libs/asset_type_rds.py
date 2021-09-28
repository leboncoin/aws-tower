#!/usr/bin/env python
"""
Asset types RDS class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

from .asset_type import AssetType

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
                asset_report['PubliclyAccessible'] = True
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
        if self.public:
            return f'[Public] {self.url} {self.engine}{self.display_brief_audit()}'
        return f'{self.engine}{self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        if self.public:
            return f'[Public] {self.url} {self.engine}'
        return f'[Private] {self.engine}'
