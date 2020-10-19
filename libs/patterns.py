#!/usr/bin/env python
"""
Patterns library

Copyright 2020 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""
from pathlib import Path
import json

VERSION = '2.1.0'

class Patterns:
    _patterns = list()

    def __init__(self, patterns_path):
        try:
            patterns = patterns_path.read_text()
        except Exception as e:
            raise Exception(f'Unable to read patterns from file {patterns_path.absolute()}: {e}')
        else:
            try:
                self._patterns = json.loads(patterns)
            except Exception as e:
                raise Exception(f'Unable to load json data: {e}')

    def _get_rules_from_type(self, type_name):
        '''
        Returns rules from patterns
        '''
        if not type_name in self._patterns['types']:
            return False
        return self._patterns['types'][type_name]

    def _check_rule_in(self, variable, value):
        '''
        Check rule "in" and return True or False
        '''
        return value in variable

    def _check_patterns_security_groups(self, sg_name, sg_line):
        sg_rules = self._get_rules_from_type('security_group')
        if sg_rules is False:
            return False
        report = list()
        for sg_rule in sg_rules:
            for pattern in sg_rule['patterns']:
                if 'type' in pattern and 'value' in pattern:
                    func_rule = f'_check_rule_{pattern["type"]}'
                    if hasattr(self, func_rule):
                        if getattr(self, func_rule)(sg_line, pattern['value']):
                            report.append({
                                'title': f'[{sg_name}] {sg_rule["message"]} ({sg_line})',
                                'severity': sg_rule['severity']
                            })
        return report

    def get_dangerous_patterns_from_security_groups(self, metadata):
        '''
        Try to find dangerous patterns from security groups
        '''
        if len(self._patterns) == 0 or len(metadata) == 0:
            return list()
        is_sg = False
        report = list()
        for sg_name in metadata:
            if sg_name.startswith('sg-'):
                is_sg = True
                for sg_rule in metadata[sg_name].split():
                    result = self._check_patterns_security_groups(sg_name, sg_rule)
                    if result is not False:
                        report += result
        if not is_sg:
            report.append({
                'title': 'No security group present',
                'severity': 'info'
            })

        if 'DnsRecord' in metadata:
            report.append({
                'title': f'DnsRecord: {metadata["DnsRecord"]}',
                'severity': 'medium'
            })
        return report

    def get_dangerous_patterns(self, metadata):
        '''
        Try to find dangerous patterns in differents settings like SG, ACL, ...
        '''
        report = list()
        report += self.get_dangerous_patterns_from_security_groups(metadata)
        return report