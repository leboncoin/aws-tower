#!/usr/bin/env python
"""
Asset types CloudFront class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

from dataclasses import dataclass

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

class CloudFront(AssetType):
    """
    CloudFront Asset Type
    """
    def __init__(
        self,
        name: str,
        aliases: str,
        authorization_types: list,
        public: bool=False):
        super().__init__('CloudFront', name, public=public)
        self.aliases = aliases
        self.authorization = Authorization()
        for auth_type in authorization_types:
            self.authorization.add_auth_type(auth_type)
        self.location.region = 'global'

    def report(self, report, brief=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {
                'Aliases': self.aliases,
                'AuthorizationTypes': self.authorization.types
            }
            if self.public:
                asset_report['PubliclyAccessible'] = True
            if self.security_issues:
                self.update_audit_report(asset_report)
        if 'CloudFront' not in report[self.location.region]:
            report[self.location.region]['CloudFront'] = { self.name: asset_report }
            return report
        report[self.location.region]['CloudFront'].update({ self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        if self.public:
            return f'[Public] {self.aliases} Auth:{self.authorization.types}{self.display_brief_audit()}'
        return f'{self.aliases} Auth:{self.authorization.types}{self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        if self.public:
            return f'[Public] {self.aliases} Auth:{self.authorization.types}'
        return f'[Private] {self.aliases} Auth:{self.authorization.types}'
