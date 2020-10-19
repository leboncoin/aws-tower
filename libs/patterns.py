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
    _regex_patterns = {
        'is_cidr': re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/(?:[1-2]?[0-9]|3[0-2])$'),
        'is_private_cidr': re.compile(r'^(?:127\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)')
    }
    _types_regex = {
        'port_range': re.compile(r'^(?:[1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[1-5])(?:-(?:[1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[1-5]))?$')
    }
    _severity_levels = dict()
    _min_severity = 0
    _max_severity = 0

    def __init__(self, patterns_path, severity_levels, min_severity, max_severity):
        """Constructor method
        Get patterns from the json file
        Set min_severity / max_severity to at least 0 if any issue
        """
        self._logger = logging.getLogger('aws-tower_patterns')
        try:
            patterns = patterns_path.read_text()
        except Exception as e:
            raise Exception(f'Unable to read patterns from file {patterns_path.absolute()}: {e}')
        else:
            try:
                self._patterns = json.loads(patterns)
            except Exception as e:
                raise Exception(f'Unable to load json data: {e}')
        self._severity_levels = severity_levels
        if min_severity not in self._severity_levels:
            raise Exception(f'Unable to found severity {min_severity} in {list(self._severity_levels.keys())}')
        if max_severity not in self._severity_levels:
            raise Exception(f'Unable to found severity {max_severity} in {list(self._severity_levels.keys())}')
        self._min_severity = self._severity_levels[min_severity]
        self._max_severity = self._severity_levels[max_severity]
        if self._min_severity < 0:
            self._min_severity = 0
        if self._max_severity < 0:
            self._max_severity = 0
        if self._max_severity < self._min_severity:
            raise Exception(f'Error: min severity ({min_severity}) higher than max severity ({max_severity})')

    def _get_findings_rules_from_type(self, type_name):
        '''
        Returns rules from patterns
        '''
        if not type_name in self._patterns['types']:
            return False
        return self._patterns['types'][type_name]

    def _check_rule_in(self, variable, value):
        """Check if value may be found in variable
        Check rule "in"

        :param variable: Variable where we want to find the value
        :type variable: mixed
        :param value: Value to find in variable
        :type value: str
        :return: True if we find it, else return False
        :rtype: bool
        """
        if type(variable) is str:
            return value.lower() in variable.lower()
        elif type(variable) is list:
            for element in variable:
                if value.lower() == element.lower():
                    return True
            return False
        return value in variable

    def _check_rule_not_in(self, variable, value):
        """Check if value is not in variable
        Check rule "not_in"

        :param variable: variable where we want to find the value
        :type variable: mixed
        :param value: value to find in variable
        :type value: str
        :return: True if we don't find it, else return False
        :rtype: bool
        """
        return not self._check_rule_in(variable, value)

    def _check_rule_is_cidr(self, source, is_cidr=True):
        """Check if source is a valid CIDR (example: 10.0.0.0/8)
        Check rule "is_cidr"
        If is_cidr is False, then it will return True if source
        is not a CIDR

        :param source: value we want to validate as a CIDR
        :type source: str
        :param is_cidr: If True then return source == cidr, else source != cidr
        :type is_cidr: bool, optional
        :return: Return True if source and cidr are validated
        :rtype: bool
        """
        result = self._regex_patterns['is_cidr'].match(source) is not None
        return result is is_cidr

    def _check_rule_is_private_cidr(self, source, is_private_cidr=True):
        """Check with a regex if source is a private CIDR or not
        Check rule "is_private_cidr"
        If is_private_cidr is False, then it will return True if
        source is not a private cidr

        :param source: Value we want to validate as a private CIDR
        :type source: str
        :param is_private_cidr: If True then return source == private, else source != private
        :type is_cidr: bool, optional
        :return: Return True if source and cidr are validated
        :rtype: bool
        """
        result = self._regex_patterns['is_private_cidr'].match(source) is not None
        return result is is_private_cidr

    def _check_rule_type_regex(self, ports, type_regex):
        """Check if ports if valid via regex
        Check rule "type_regex"
        It will check with self._types_regex

        :param ports: Ports to validate (examples: '80', '9000-9001')
        :type ports: str
        :param type_regex: Type we want to check (example: 'port_range')
        :type type_regex: str
        :return: True if we can find and validate the type of regex
        :rtype: bool
        """
        if type_regex in self._types_regex:
            return self._types_regex[type_regex].match(ports) is not None
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