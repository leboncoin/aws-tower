#!/usr/bin/env python
"""
Asset types EC2 class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

from .asset_type import AssetType

# Debug
# from pdb import set_trace as st

class EC2(AssetType):
    """
    EC2 Asset Type
    """
    def __init__(self, name: str, private_ip: str, public: bool=False):
        super().__init__(name, public=public)
        self.private_ip = private_ip
        self.public_ip = ''
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
                'PrivateIP': self.private_ip
            }
            if self.public:
                asset_report['PubliclyAccessible'] = True
            if self.public_ip:
                asset_report['PublicIP'] = self.public_ip
            if self.security_groups and not self.security_issues:
                asset_report['SecurityGroups'] = self.security_groups
            if self.dns_record:
                asset_report['DnsRecord'] = self.dns_record
            if self.security_issues:
                self.update_audit_report(asset_report)
        if 'EC2' not in report[self.location.region][self.location.vpc][self.location.subnet]:
            report[self.location.region][self.location.vpc][self.location.subnet]['EC2'] = \
                { self.name: asset_report }
            return report
        report[self.location.region][self.location.vpc][self.location.subnet]['EC2'].update(
            { self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        if self.public:
            return f'[Public] {self.public_ip} {self.private_ip}{self.display_brief_audit()}'
        return f'{self.private_ip}{self.display_brief_audit()}'
