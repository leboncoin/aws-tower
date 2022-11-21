#!/usr/bin/env python
"""
Asset types class

Copyright 2020-2022 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
from dataclasses import dataclass

from .tools import color_severity

# Debug
# from pdb import set_trace as st

@dataclass
class Location:
    """
    Define the asset location
    """
    region: str = None
    vpc: str = None
    subnet: str = None

class AssetType:
    """
    Asset Type
    """
    def __init__(self, aws_service: str, name: str, public: bool=False):
        self.aws_service = aws_service
        self.name = name
        self.public = public
        self.location = Location()
        self.security_issues = []
        self.console = None

    def audit(self, patterns):
        """
        This function is returning an asset_report with security findings,
        it handles the brief mode output
        """
        self.security_issues = patterns.extract_findings(self)

    def update_audit_report(self, report):
        """
        Return an output of the audit
        """
        for issue in self.security_issues:
            if 'Audit' not in report:
                report['Audit'] = []
            report['Audit'].append(color_severity(issue["severity"], issue["title"], self.console))

    def display_brief_audit(self):
        """
        Return a brief output of the audit
        """
        if not self.security_issues:
            return ''
        output = ' '
        report = {}
        for issue in self.security_issues:
            if issue['severity'] not in report:
                report[issue['severity']] = 1
            else:
                report[issue['severity']] += 1
        for severity, message in report.items():
            output += f'<{color_severity(severity, message, self.console)}>'
        return output

    def get_type(self):
        """
        Return the asset type
        """
        return type(self).__name__

    def remove_not_vulnerable_members(self):
        """
        If it's an AssetGroup (IAMGroup or S3Group or else), remove the
        non vulnerable members.
        This is a nutshell, check the ASsetGroup override function.
        """
        return True

    def dst_linked_assets(self, _):
        """
        Among all asset, find assets linked in destination
        """
        return []

    def src_linked_assets(self, _):
        """
        Among all asset, find assets linked in source
        """
        return []

    def cluster_name(self):
        """
        Return nothing by default
        """
        return ''
