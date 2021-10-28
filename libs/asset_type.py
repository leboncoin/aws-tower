#!/usr/bin/env python
"""
Asset types class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

from dataclasses import dataclass

from .tools import color_severity
from .patterns import Patterns

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

    def audit(self, security_config):
        """
        This function is returning an asset_report with security findings,
        it handles the brief mode output
        """
        try:
            patterns = Patterns(
                security_config['findings_rules_path'],
                security_config['severity_levels'],
                security_config['min_severity'],
                security_config['max_severity']
            )
        except Exception:
            return

        self.security_issues = patterns.extract_findings(self)

    def update_audit_report(self, report):
        """
        Return an output of the audit
        """
        for issue in self.security_issues:
            if 'Audit' not in report:
                report['Audit'] = []
            report['Audit'].append(color_severity(issue["severity"], issue["title"]))

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
            output += f'<{color_severity(severity, message)}>'
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
