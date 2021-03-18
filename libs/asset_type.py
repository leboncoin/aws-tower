#!/usr/bin/env python
"""
Asset types class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

from dataclasses import dataclass

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
    def __init__(self, name: str, public: bool=False):
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
                report['Audit'] = list()
            report['Audit'].append(f'[{issue["severity"]}] {issue["title"]}')

    def display_brief_audit(self):
        """
        Return a brief output of the audit
        """
        output = ''
        if self.security_issues:
            report = dict()
            for issue in self.security_issues:
                if issue['severity'] not in report:
                    report[issue['severity']] = 1
                else:
                    report[issue['severity']] += 1
            for issue_type in report:
                output += f' [{issue_type}: {report[issue_type]}]'
        return output

    def get_type(self):
        """
        Return the asset type
        """
        return type(self).__name__
