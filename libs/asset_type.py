#!/usr/bin/env python
"""
Asset types class

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
from dataclasses import dataclass
from pathlib import Path

from config import variables
from .tools import color_severity, get_false_positive_key

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

    def update_audit_report(self, report, with_fpkey):
        """
        Return an output of the audit
        """
        for issue in self.security_issues:
            if 'Audit' not in report:
                report['Audit'] = []
            message = issue['title']
            if with_fpkey:
                message = f'<false-positive-key={get_false_positive_key(message, self.get_type(), self.name)}> {message}'
            report['Audit'].append(color_severity(issue['severity'], message, self.console))

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

    def remove_false_positives(self):
        """
        Removes the findings from the false_positives_list.txt
        """
        fp_list_path = variables.FALSE_POSITIVES_LIST_PATH
        fp_list = []
        if fp_list_path.exists():
            fp_list = fp_list_path.read_text(
                encoding='ascii', errors='ignore').split('\n')

        security_issues = []

        for security_issue in self.security_issues:
            if get_false_positive_key(security_issue['title'], self.get_type(), self.name) not in fp_list:
                security_issues.append(security_issue)
        self.security_issues = security_issues

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
