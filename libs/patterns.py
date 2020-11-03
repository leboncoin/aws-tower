#!/usr/bin/env python
"""
Patterns library

Copyright 2020 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""

from distutils.version import LooseVersion
import ipaddress
import json
import logging
import re

VERSION = '2.4.0'

class Patterns:
    """Get findings from patterns

    :param patterns_path: Patterns' path
    :type patterns_path: pathlib.Path
    :param severity_levels: List of severities available
    :type severity_levels: dict
    :param min_severity: Minimum level of severity (info for example) to check
    :type min_severity: str
    :param max_severity: Maximum level of severity (critical for example) to check
    :type max_severity: str
    """
    _patterns = list()
    _types_regex = {
        'port_range': re.compile(r'^(?:[1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[1-5])(?:-(?:[1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[1-5]))?$')
    }
    _severity_levels = dict()
    _min_severity = 0
    _max_severity = 0
    _rules_definitions = {
        'in': {
            'variables': ['variable_in'],
            'values': ['value_in']
        }, 'not_in': {
            'variables': ['variable_in'],
            'values': ['value_in']
        }, 'is_cidr': {
            'variables': ['source'],
            'values': ['is_cidr']
        }, 'is_private_cidr': {
            'variables': ['source'],
            'values': ['is_private_cidr']
        }, 'is_in_networks': {
            'variables': ['source'],
            'values': ['networks']
        }, 'is_ports': {
            'variables': ['source'],
            'values': ['is_ports']
        }, 'engine_deprecated_version': {
            'variables': ['engine'],
            'values': ['engine_name', 'versions']
        }
    }

    def __init__(self, patterns_path, severity_levels={'info': 0, 'critical': 1}, min_severity='info', max_severity='critical'):
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

    def _prepare_arguments(self, arguments, kwargs):
        """Prepare arguments to use them in rule methods

        :param arguments: arguments to prepare
        :type arguments: list
        :return: Arguments prepared or False if any error
        :rtype: dict, bool
        """
        self._logger.debug(f'Preparing arguments: {arguments}')
        prepared_arguments = dict()
        for argument in arguments:
            if argument['type'] == 'value':
                prepared_arguments[argument['name']] = argument['value']
            elif argument['type'] == 'var':
                if argument['value'] in kwargs:
                    prepared_arguments[argument['name']] = kwargs[argument['value']]
                else:
                    self._logger.error(f'Unable to find {argument["value"]} in {list(kwargs.keys())}')
                    return False
            elif argument['type'] == 'dict':
                if argument['value'] in kwargs:
                    if isinstance(kwargs[argument['value']], dict) and argument['key'] in kwargs[argument['value']]:
                        prepared_arguments[argument['name']] = kwargs[argument['value']][argument['key']]
                    else:
                        self._logger.error(f'Unable to find {argument["key"]} in {kwargs[argument["value"]]}')
                        return False
                else:
                    self._logger.error(f'Unable to find {argument["value"]} in {list(kwargs.keys())}')
                    return False
            else:
                self._logger.error(f'Bad type ({argument["type"]} for {argument["value"]}')
                return False
        return prepared_arguments

    def _check_definition(self, rule, variables, values):
        """Check rule definition to use it

        :param rule: Rule name, like "is_ports"
        :type rule: str
        :param variables: variables used to check
        :type variables: dict
        :param values: values used to check
        :type values: dict
        :return: True if all values / variables found
        :rtype: bool
        """
        self._logger.debug(f'Checking definition of {rule}')
        if not rule in self._rules_definitions:
            self._logger.error(f'Unable to find definition for {rule}')
            return False
        variables_name = [variable['name'] for variable in variables]
        values_name = [value['name'] for value in values]
        for variable in self._rules_definitions[rule]['variables']:
            if not variable in variables_name:
                self._logger.error(f'Unable to find {variable} in {list(variables_name)}')
                return False
        for value in self._rules_definitions[rule]['values']:
            if not value in values_name:
                self._logger.error(f'Unable to find {value} in {list(values_name)}')
                return False
        return True

    def _get_findings_rules_from_type(self, type_name):
        """Get findings rules from _patterns

        :param type_name: Type of findings we want to get (like metadata, security_groups, ...)
        :type type_name: str
        :return: Return findings rules
        :rtype: dict
        """
        if not type_name in self._patterns['types'] or \
            'findings' not in self._patterns['types'][type_name]:
            return False
        return self._patterns['types'][type_name]['findings']

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
        if isinstance(variable, str):
            return value.lower() in variable.lower()
        if isinstance(variable, list):
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
        self._logger.debug(f'Check rule is_cidr. Source: {source} | is_cidr: {is_cidr}')
        try:
            ipaddress.ip_network(source)
        except ValueError:
            return not is_cidr
        except Exception as e:
            self._logger.warning(f'Error in creating ip_network from {source}: {e}')
            return False
        else:
            return is_cidr

    def _check_rule_is_private_cidr(self, source, is_private_cidr=True):
        """Check if source is a private CIDR or not
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
        self._logger.debug(f'Check rule is_private_cidr. Source: {source} | is_private_cidr: {is_private_cidr}')
        try:
            ip_network = ipaddress.ip_network(source)
        except ValueError:
            self._logger.warning(f'Unable to create ip_network from {source}: Bad format!')
            return False
        except Exception as e:
            self._logger.warning(f'Error in creating ip_network from {source}: {e}')
            return False
        is_private = True
        if source.startswith('0.0.0.0'):
            is_private = False
        else:
            is_private = ip_network.is_private
        return is_private ==  is_private_cidr

    def _check_rule_is_in_networks(self, source, networks):
        """Check if source is in one of the networks
        Check rule "is_in_specific_networks"

        :param source: Value we want to validate as a private CIDR
        :type source: str
        :param networks: List of networks we want to check check
        :type networks: list
        """
        self._logger.debug(f'Check rule is_in_networks. Source: {source} | networks: {networks}')
        if not isinstance(networks, list):
            self._logger.warnig(f'Bad format for networks. Got {type(networks)} instead of list')
            return False
        try:
            ip_network = ipaddress.ip_network(source)
        except ValueError:
            self._logger.warning(f'Unable to create ip_network from {source}: Bad format!')
            return False
        except Exception as e:
            self._logger.warning(f'Error in creating ip_network from {source}: {e}')
            return False
        for network_str in networks:
            try:
                network = ipaddress.ip_network(network_str)
            except ValueError:
                self._logger.warning(f'Unable to create ip_network from {source}: Bad format!')
                continue
            except Exception as e:
                self._logger.warning(f'Error in creating ip_network from {source}: {e}')
                continue
            if network.supernet_of(ip_network):
                return True
        return False

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

    def _check_rule_engine_deprecated_version(self, metadata, list_min_version_allowed):
        """Check if the engine version is not deprecated.
        Compare the engine version if it's smaller than the minimum version allowed in list
        If there is multiple versions,
        it only checks the major version for the other listed versions
        Check rule "engine_deprecated_version"

        :param metadata: RDS metadata
        :type metadata: dict
        :param min_version_allowed: Minimum DBMS version allowed
        :type list_min_version_allowed: string representation of list
        :return: True if the engine version is deprecated
        :rtype: bool
        """
        if 'Engine' not in metadata:
            return False
        if len(metadata['Engine'].split('==')) < 2:
            self._logger.warning(f'Wrong format for {metadata["Engine"]}')
            return False
        current_version = LooseVersion(metadata['Engine'].split('==')[1])
        min_version = LooseVersion('0.0.1')
        versions = list()
        for min_version_allowed in json.loads(list_min_version_allowed):
            if len(min_version_allowed.split('==')) < 2:
                self._logger.warning(f'Wrong format for {min_version_allowed}')
                return False
            version = LooseVersion(min_version_allowed.split('==')[1])
            if version < min_version:
                min_version = version
            else:
                versions.append(version)
        # Compare only if major version match
        for version in versions:
            if str(version).split('.')[0] == str(current_version).split('.')[0]:
                return current_version < version
        return current_version < min_version

    def _generate_report_message(self, message, severity, **kwargs):
        """Generate a message for the report

        :param message: Message data from the finding (may be a string or dictionary)
        :type message: mixed
        :param severity: Severity of the message (examples: 'info', 'high', ..)
        :type severity: str
        :param kwargs: Variables we may need to generate the message (like metadata, name, source, ...)
        :return: Message generated
        :rtype: dict
        """
        report_message = dict()
        if isinstance(message, str):
            report_message = {
                'title': f'{message}',
                'severity': f'{severity}'
            }
        else:
            try:
                args = dict()
                for key, value in message['args'].items():
                    if value['type'] == 'dict':
                        if value['variable'] in kwargs:
                            if value['key'] in kwargs[value['variable']]:
                                args[key] = kwargs[value['variable']][value['key']]
                            else:
                                self._logger.error(f'Unable to find variable {value["key"]} in {list(kwargs[value["variable"]].keys())}')
                                return False
                        else:
                            self._logger.error(f'Unable to find variable {value["type"]} in {list(kwargs.keys())}')
                            return False
                    elif value['type'] == 'var':
                        if value['variable'] in kwargs:
                            args[key] = kwargs[value['variable']]
                        else:
                            self._logger.error(f'Unable to find variable {value["type"]} in {list(kwargs.keys())}')
                            return False
            except Exception as e:
                self._logger.error(f'Unable to prepare variables for the report message: {e}', exc_info=True)
                return False
            else:
                try:
                    report_message = {
                        'title': message['text'].format(**args),
                        'severity': f'{severity}'
                    }
                except Exception as e:
                    self._logger.error(f'Unable to generate report message: {e}')
                    return False
        return report_message

    def _check_findings_by_type(self, findings_type, loop=True, **kwargs):
        """Check every finding rule on kwargs
        Example: Try to check if a source is a valid CIDR and is a private CIDR

        :param findings_type: Findings to use like metadata, security_groups, ...
        :type findings_type: str
        :param loop: If True then we don't stop after the first finding found
        :type loop: bool, optional
        :return: Report generated from the findings
        :rtype: list
        """
        self._logger.debug(f'Kwargs in check_findings_by_type: {kwargs}')
        findings_rules = self._get_findings_rules_from_type(findings_type)
        if findings_rules is False:
            self._logger.warning(f'Unable to find findings rules for {findings_type}')
            return False
        report = list()
        for finding in findings_rules:
            finding_found = False
            if finding['severity'] in self._severity_levels and \
                (self._severity_levels[finding['severity']] >= self._min_severity and \
                    self._severity_levels[finding['severity']] <= self._max_severity):
                finding_found = True
                for rule in finding['rules']:
                    if 'type' in rule and 'value' in rule and 'variable' in rule:
                        func_rule = f'_check_rule_{rule["type"]}'
                        if hasattr(self, func_rule) and rule['variable'] in kwargs:
                            if not getattr(self, func_rule)(kwargs[rule['variable']], rule['value']):
                                finding_found = False
                                break
                        else:
                            self._logger.error(f'Uanble to find function {func_rule} or {rule["variable"]} in {kwargs}')
                            finding_found = False
                    else:
                        self._logger.error(f'Unable to find "type", "value" or "variable" in {rule}')
                        finding_found = False
                        break
            if finding_found:
                report_message = self._generate_report_message(
                    finding['message'],
                    finding['severity'],
                    **kwargs
                )
                if report_message is not False:
                    report.append(report_message)
                    if loop is False:
                        break
        return report

    def extract_findings_from_security_groups(self, metadata):
        """Try to extract findings from security groups

        :param metadata: Metadata from aws asset
        :type metadata: dict
        :return: Report generated from the findings
        :rtype: list
        """
        if len(self._patterns) == 0 or len(metadata) == 0:
            return list()
        report = list()
        if 'SecurityGroups' in metadata:
            for sg_name, sg_rules in metadata['SecurityGroups'].items():
                for ports, sources in sg_rules.items():
                    for source in sources:
                        result = self._check_findings_by_type(
                            'security_group',
                            loop=False,
                            sg_name=sg_name,
                            ports=ports,
                            source=source
                        )
                        if result is not False:
                            report += result
        report_metadata = self._check_findings_by_type('metadata', metadata=metadata)
        if report_metadata is not False:
            report += report_metadata
        return report

    def extract_findings(self, metadata):
        """Try to extract findings from metadata

        :param metadata: Metadata from aws asset
        :type metadata: dict
        :return: Report generated
        :rtype: list()
        """
        report = list()
        report += self.extract_findings_from_security_groups(metadata)
        return report
