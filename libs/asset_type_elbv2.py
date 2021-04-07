#!/usr/bin/env python
"""
Asset types ELBv2 class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

from .asset_type import AssetType

# Debug
# from pdb import set_trace as st

class ELBV2(AssetType):
    """
    ELBv2 Asset Type
    """
    def __init__(self, name: str, scheme: str, public: bool=False):
        super().__init__(name, public=public)
        self.scheme = scheme
        self.security_groups = dict()
        self.dns_record = None

    def report(self, report, brief=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {
                'Scheme': self.scheme
            }
            if self.public:
                asset_report['PubliclyAccessible'] = True
            if self.security_groups and not self.security_issues:
                asset_report['SecurityGroups'] = self.security_groups
            if self.dns_record:
                asset_report['DnsRecord'] = self.dns_record
            if self.security_issues:
                self.update_audit_report(asset_report)
        if 'ELBv2' not in report[self.location.region][self.location.vpc][self.location.subnet]:
            report[self.location.region][self.location.vpc][self.location.subnet]['ELBv2'] = \
                { self.name: asset_report }
            return report
        report[self.location.region][self.location.vpc][self.location.subnet]['ELBv2'].update(
            { self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        if self.public:
            return f'[Public] {self.display_brief_audit()}'
        return f'[{self.scheme}] {self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        if self.public:
            return f'[Public] {self.dns_record}'
        return f'[{self.scheme}] {self.dns_record}'
