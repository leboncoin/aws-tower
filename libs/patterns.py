#!/usr/bin/env python
"""
Patterns library

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""

from collections.abc import Mapping, Sequence
from collections import OrderedDict
from distutils.version import LooseVersion
import ipaddress
import json
import logging
from pathlib import Path
import re

# ThirdParty
import ruamel.yaml
from ruamel.yaml.error import YAMLError

# Debug
# from pdb import set_trace as st

# pylint: disable=logging-fstring-interpolation,no-self-use

yaml = ruamel.yaml.YAML()

class OrderlyJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Mapping):
            return OrderedDict(o)
        if isinstance(o, Sequence):
            return list(o)
        return json.JSONEncoder.default(self, o)


def yaml_2_json(patterns_content):
    """
    Transform a Yaml into JSON
    """
    try:
        datamap = yaml.load(patterns_content)
    except YAMLError:
        return None
    return OrderlyJSONEncoder(indent=2).encode(datamap)


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
    _patterns = []
    _ports_range = re.compile(r'^(?:[1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[1-5])(?:-(?:[1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[1-5]))?$')
    _severity_levels = {}
    _min_severity = 0
    _max_severity = 0
    _rules_definitions = {
        'in': {
            'data_sources': ['data_list'],
            'conditions': ['data_element']
        },
        'not_in': {
            'data_sources': ['data_list'],
            'conditions': ['data_element']
        },
        'has_attribute': {
            'data_sources': ['asset'],
            'conditions': ['attribute']
        },
        'has_not_attribute': {
            'data_sources': ['asset'],
            'conditions': ['attribute']
        },
        'has_attribute_equal': {
            'data_sources': ['attribute_value'],
            'conditions': ['attribute_value']
        },
        'has_attribute_not_equal': {
            'data_sources': ['attribute_value'],
            'conditions': ['attribute_value']
        },
        'is_cidr': {
            'data_sources': ['source'],
            'conditions': ['is_cidr']
        },
        'is_private_cidr': {
            'data_sources': ['source'],
            'conditions': ['is_private_cidr']
        },
        'is_in_networks': {
            'data_sources': ['source'],
            'conditions': ['networks']
        },
        'is_ports': {
            'data_sources': ['source'],
            'conditions': ['is_ports']
        },
        'engine_deprecated_version': {
            'data_sources': ['attribute_value'],
            'conditions': ['engine_name', 'versions']
        }
    }

    def __init__(
        self,
        patterns_path,
        severity_levels={'info': 0, 'critical': 1},
        min_severity='info',
        max_severity='critical'):
        """Constructor method
        Get patterns from the json file
        Set min_severity / max_severity to at least 0 if any issue
        """
        self._logger = logging.getLogger('aws-tower_patterns')
        # self._logger.setLevel(logging.DEBUG)
        try:
            patterns = patterns_path.read_text()
        except Exception as err_msg:
            raise Exception(f'Unable to read patterns from file {patterns_path.absolute()}: {err_msg}')
        else:
            try:
                self._patterns = json.loads(yaml_2_json(patterns))
            except Exception as err_msg:
                raise Exception(f'Unable to load yaml data: {err_msg}')
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
        self.subnet_allow_list = []
        allow_list_path = Path('config/subnet_allow_list.txt')
        if allow_list_path.exists():
            with allow_list_path.open() as allow_list:
                for line in allow_list.readlines():
                    cidr = line.split('\n')[0].split(':')[0]
                    try:
                        self.subnet_allow_list.append(ipaddress.ip_network(cidr))
                    except ValueError:
                        pass

    def _prepare_arguments(self, arguments, kwargs):
        """Prepare arguments to use them in rule methods

        :param arguments: arguments to prepare
        :type arguments: list
        :return: Arguments prepared or False if any error
        :rtype: dict, bool
        """
        self._logger.debug(f'Preparing arguments: {arguments}')
        prepared_arguments = {}
        for argument in arguments:
            if argument['type'] == 'constant':
                prepared_arguments[argument['name']] = argument['value']
            elif argument['type'] == 'variable':
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
            elif argument['type'] == 'attribute':
                try:
                    if hasattr(kwargs['asset'], argument['value']):
                        prepared_arguments[argument['name']] = getattr(kwargs['asset'], argument['value'])
                    elif '.' in argument['value']:
                        # Allow "asset.subasset.value"
                        prepared_arguments[argument['name']] = getattr(
                            getattr(kwargs['asset'], argument['value'].split('.')[0]),
                            argument['value'].split('.')[1])
                    else:
                        self._logger.error(f'Unable to find {argument["value"]} in {kwargs["asset"].name}')
                        return False
                except Exception as err_msg:
                    self._logger.error(f'Unable to find {argument["value"]} in {kwargs["asset"].name} [{err_msg}]')
                    return False
            else:
                self._logger.error(f'Bad type ({argument["type"]} for {argument["value"]}')
                return False
        return prepared_arguments

    def _check_definition(self, rule, data_sources, conditions):
        """Check rule definition to use it

        :param rule: Rule name, like "is_ports"
        :type rule: str
        :param data_sources: data_sources used to check
        :type data_sources: dict
        :param conditions: conditions used to check
        :type conditions: dict
        :return: True if all conditions / data_sources found
        :rtype: bool
        """
        self._logger.debug(f'Checking definition of {rule}')
        if not rule in self._rules_definitions:
            self._logger.error(f'Unable to find definition for {rule}')
            return False
        data_sources_name = [variable['name'] for variable in data_sources]
        conditions_name = [value['name'] for value in conditions]
        for variable in self._rules_definitions[rule]['data_sources']:
            if not variable in data_sources_name:
                self._logger.error(f'Unable to find {variable} in {list(data_sources_name)}')
                return False
        for value in self._rules_definitions[rule]['conditions']:
            if not value in conditions_name:
                self._logger.error(f'Unable to find {value} in {list(conditions_name)}')
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


    def _check_rule_has_attribute(self, data_sources, conditions):
        """Check if data_sources['asset'] has the attribute conditions['attribute']
        Check rule "has_attribute"

        :param data_sources: Where we want to find the conditions
        :type data_sources: {"asset": AssetType}
        :param conditions: Attribute to find in the asset
        :type conditions: {"attribute": str}
        :return: True if we find it, else return False
        :rtype: bool
        """
        return hasattr(data_sources['asset'], conditions['attribute']) and \
            getattr(data_sources['asset'], conditions['attribute']) is not None

    def _check_rule_has_not_attribute(self, data_sources, conditions):
        """Check if data_sources['asset'] hasn't the attribute conditions['attribute']
        Check rule "has_not_attribute"

        :param data_sources: Where we want to find the conditions
        :type data_sources: {"asset": AssetType}
        :param conditions: Attribute not to find in the asset
        :type conditions: {"attribute": str}
        :return: False if we find it, else return True
        :rtype: bool
        """
        return not self._check_rule_has_attribute(data_sources, conditions)

    def _check_rule_has_attribute_equal(self, data_sources, conditions):
        """Check if data_sources['attribute_value'] has the attribute equal to conditions['attribute_value']
        Check rule "has_attribute_equal"

        :param data_sources: Where we want to find the conditions
        :type data_sources: {"attribute_value": mixed}
        :param conditions: Attribute value to be equal
        :type conditions: {"attribute_value": mixed}
        :return: True if it's equal
        :rtype: bool
        """
        return data_sources['attribute_value'] == conditions['attribute_value']

    def _check_rule_has_attribute_not_equal(self, data_sources, conditions):
        """Check if data_sources['attribute_value'] has the attribute not equal to conditions['attribute_value']
        Check rule "has_attribute_not_equal"

        :param data_sources: Where we want to find the conditions
        :type data_sources: {"attribute_value": mixed}
        :param conditions: Attribute value to be not equal
        :type conditions: {"attribute_value": mixed}
        :return: False if it's equal
        :rtype: bool
        """
        return not self._check_rule_has_attribute_equal(data_sources, conditions)

    def _check_rule_in(self, data_sources, conditions):
        """Check if conditions['data_element'] may be found in data_sources['data_list']
        Check rule "in"

        :param data_sources: Where we want to find the conditions
        :type data_sources: mixed
        :param conditions: Value to find in data_sources
        :type conditions: str
        :return: True if we find it, else return False
        :rtype: bool
        """
        if isinstance(data_sources['data_list'], str):
            return conditions['data_element'].lower() in data_sources['data_list'].lower()
        if isinstance(data_sources['data_list'], list):
            for element in data_sources['data_list']:
                if conditions['data_element'].lower() == element.lower():
                    return True
            return False
        return conditions['data_element'] in data_sources['data_list']

    def _check_rule_not_in(self, data_sources, conditions):
        """Check if conditions['data_element'] is not in data_sources['data_list']
        Check rule "not_in"

        :param data_sources: Where we want to find the conditions
        :type data_sources: mixed
        :param conditions: Value to find in data_sources
        :type conditions: str
        :return: True if we find it, else return False
        :rtype: bool
        """
        return not self._check_rule_in(data_sources, conditions)

    def _check_rule_is_cidr(self, data_sources, conditions):
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
        self._logger.debug(f'Check rule is_cidr. Source: {data_sources["source"]} | is_cidr: {conditions["is_cidr"]}')
        try:
            ipaddress.ip_network(data_sources["source"])
        except ValueError:
            return not conditions["is_cidr"]
        except Exception as err_msg:
            self._logger.debug(f'Error in creating ip_network from {data_sources["source"]}: {err_msg}')
            return False
        else:
            return conditions["is_cidr"]

    def _check_rule_is_private_cidr(self, data_sources, conditions):
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
        self._logger.debug(f'Check rule is_private_cidr. Source: {data_sources["source"]} | is_private_cidr: {conditions["is_private_cidr"]}')
        try:
            ip_network = ipaddress.ip_network(data_sources["source"])
        except ValueError:
            self._logger.debug(f'Unable to create ip_network from {data_sources["source"]}: Bad format!')
            return False
        except Exception as err_msg:
            self._logger.debug(f'Error in creating ip_network from {data_sources["source"]}: {err_msg}')
            return False
        is_private = True
        if data_sources["source"].startswith('0.0.0.0'):
            is_private = False
        else:
            is_private = ip_network.is_private
        in_allow_list = False
        for subnet in self.subnet_allow_list:
            if in_allow_list:
                continue
            in_allow_list = ipaddress.ip_network(data_sources["source"]).subnet_of(subnet)

        return (is_private or in_allow_list) == conditions["is_private_cidr"]

    def _check_rule_is_in_networks(self, data_sources, conditions):
        """Check if source is in one of the networks
        Check rule "is_in_specific_networks"

        :param source: Value we want to validate as a private CIDR
        :type source: str
        :param networks: List of networks we want to check check
        :type networks: list
        """
        self._logger.debug(f'Check rule is_in_networks. Source: {data_sources["source"]} | networks: {conditions["networks"]}')
        if not isinstance(conditions["networks"], list):
            self._logger.warnig(f'Bad format for networks. Got {type(conditions["networks"])} instead of list')
            return False
        try:
            ip_network = ipaddress.ip_network(data_sources["source"])
        except ValueError:
            self._logger.debug(f'Unable to create ip_network from {data_sources["source"]}: Bad format!')
            return False
        except Exception as err_msg:
            self._logger.debug(f'Error in creating ip_network from {data_sources["source"]}: {err_msg}')
            return False
        for network_str in conditions["networks"]:
            try:
                network = ipaddress.ip_network(network_str)
            except ValueError:
                self._logger.debug(f'Unable to create ip_network from {data_sources["source"]}: Bad format!')
                continue
            except Exception as err_msg:
                self._logger.debug(f'Error in creating ip_network from {data_sources["source"]}: {err_msg}')
                continue
            if network.supernet_of(ip_network):
                return True
        return False

    def _check_rule_is_ports(self, data_sources, conditions):
        """Check if ports is valid via regex
        Check rule "is_ports"
        It will check with self._ports_range

        :param ports: Ports to validate (examples: '80', '9000-9001')
        :type ports: str
        :param type_regex: Type we want to check (example: 'port_range')
        :type type_regex: str
        :return: True if we can find and validate the type of regex
        :rtype: bool
        """
        if self._ports_range.match(data_sources['source']) is not None:
            return conditions['is_ports']
        return False

    def _check_rule_engine_deprecated_version(self, data_sources, conditions):
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
        if len(data_sources['attribute_value'].split('==')) < 2:
            self._logger.debug(f'Wrong format for {data_sources["attribute_value"]}')
            return False
        engine_name, current_version = data_sources['attribute_value'].split('==')
        if conditions['engine_name'] != engine_name:
            return False
        current_version = LooseVersion(current_version)
        previous_version = LooseVersion('0')
        next_version = LooseVersion('999')
        # Get previous and next version
        for i in conditions['versions']:
            version = LooseVersion(i)
            # If this is the perfect match, it's not deprecated
            if version == current_version:
                return False
            if next_version > version > current_version:
                next_version = version
            elif previous_version < version < current_version:
                previous_version = version

        # There is no previous version, it's deprecated
        if previous_version == LooseVersion('0'):
            return True

        # Check how much sub version matches, longest is closest
        for i in range(min(len(previous_version.version), len(current_version.version), len(next_version.version))):
            # Undetermine, but the current version could be latest
            if previous_version.version[i] != current_version.version[i] != next_version.version[i]:
                if next_version == LooseVersion('999'):
                    return False
                self._logger.error(f'Unable to determine the version to compare...{previous_version=}{current_version=}{next_version=}')
                return False
            if previous_version.version[i] == current_version.version[i] == next_version.version[i]:
                continue
            # The only option, is to have a version that is closest to the current version
            # This case, the previous version can be compared,
            # and is below our current version, not deprecated
            if previous_version.version[i] == current_version.version[i]:
                return False
            # At the opposite, the next version is the closest, but the current version
            # is below, this is deprecated
            return True
        self._logger.error(f'Unable to determine the version to compare...{previous_version=}{current_version=}{next_version=}')
        return False

    def _generate_report_message(self, message, severity, kwargs):
        """Generate a message for the report

        :param message: Message data from the finding (may be a string or dictionary)
        :type message: mixed
        :param severity: Severity of the message (examples: 'info', 'high', ..)
        :type severity: str
        :param kwargs: data_sources we may need to generate the message (like attributes, name, source, ...)
        :return: Message generated
        :rtype: dict
        """
        report_message = {}
        if isinstance(message, str):
            report_message = {
                'title': f'{message}',
                'severity': f'{severity}'
            }
            return report_message
        try:
            args = {}
            for key, value in message['args'].items():
                if value['type'] == 'dict':
                    if value['variable'] in kwargs:
                        if value['key'] in kwargs[value['variable']]:
                            args[key] = kwargs[value['variable']][value['key']]
                        else:
                            self._logger.error(f'Unable to find variable {value["key"]} in {list(kwargs[value["variable"]].keys())}')
                            return False
                    else:
                        self._logger.error(f'Unable to find variable {value["type"]} in {", ".join(kwargs)}')
                        return False
                elif value['type'] == 'variable':
                    if value['variable'] in kwargs:
                        args[key] = kwargs[value['variable']]
                    else:
                        self._logger.error(f'Unable to find variable {value["type"]} in {", ".join(kwargs)}')
                        return False
                elif value['type'] == 'attribute':
                    if hasattr(kwargs['asset'], value['key']):
                        args[key] = getattr(kwargs['asset'], value['key'])
                    elif '.' in value['key']:
                        # Allow "asset.subasset.value"
                        args[key] = getattr(
                            getattr(kwargs['asset'], value['key'].split('.')[0]),
                            value['key'].split('.')[1])
                    else:
                        self._logger.error(f'Unable to find attribute {value["key"]} in {kwargs["asset"].name}')
                        return False
        except Exception as err_msg:
            self._logger.error(f'Unable to prepare data_sources for the report message: {err_msg}', exc_info=True)
            return False
        else:
            try:
                report_message = {
                    'title': message['text'].format(**args),
                    'severity': f'{severity}'
                }
            except Exception as err_msg:
                self._logger.error(f'Unable to generate report message: {err_msg}')
                return False
        return report_message

    def _check_findings_by_type(self, findings_type, loop=True, **kwargs):
        """Check every finding rule on kwargs
        Example: Try to check if a source is a valid CIDR and is a private CIDR

        :param findings_type: Findings to use like attributes, security_groups, ...
        :type findings_type: str
        :param loop: If True then we don't stop after the first finding found
        :type loop: bool, optional
        :return: Report generated from the findings
        :rtype: list
        """
        self._logger.debug(f'Kwargs in check_findings_by_type: {kwargs}')
        findings_rules = self._get_findings_rules_from_type(findings_type)
        if findings_rules is False:
            self._logger.debug(f'Unable to find findings rules for {findings_type}')
            return False
        report = []
        for finding in findings_rules:
            finding_found = False
            if finding['severity'] in self._severity_levels and \
                (self._severity_levels[finding['severity']] >= self._min_severity and \
                    self._severity_levels[finding['severity']] <= self._max_severity):
                finding_found = True
                for rule in finding['rules']:
                    if 'type' in rule and 'conditions' in rule and 'data_sources' in rule:
                        func_rule = f'_check_rule_{rule["type"]}'
                        if not self._check_definition(rule['type'], rule['data_sources'], rule['conditions']):
                            self._logger.error('Bad rule definition!')
                            finding_found = False
                            break
                        if hasattr(self, func_rule):
                            data_sources = self._prepare_arguments(rule['data_sources'], kwargs)
                            if not data_sources:
                                self._logger.error('Unable to prepare data_sources')
                                finding_found = False
                                break
                            conditions = self._prepare_arguments(rule['conditions'], kwargs)
                            if not conditions:
                                self._logger.error('Unable to prepare conditions')
                                finding_found = False
                                break
                            if not getattr(self, func_rule)(data_sources, conditions):
                                finding_found = False
                                break
                        else:
                            self._logger.error(f'Uanble to find function {func_rule}')
                            finding_found = False
                            break
                    else:
                        self._logger.error(f'Unable to find "type", "value" or "variable" in {rule}')
                        finding_found = False
                        break
            if finding_found:
                report_message = self._generate_report_message(
                    finding['message'],
                    finding['severity'],
                    kwargs
                )
                if report_message is not False:
                    report.append(report_message)
                    if loop is False:
                        break
        return report

    def extract_findings_from_security_groups(self, asset):
        """Try to extract findings from asset security groups

        :param asset: aws asset
        :type asset: AssetType
        :return: Report generated from the findings
        :rtype: list
        """
        if len(self._patterns) == 0:
            return list()
        report = []
        if hasattr(asset, 'security_groups'):
            for sg_name, sg_rules in asset.security_groups.items():
                for ports, sources in sg_rules.items():
                    for source in sources:
                        result = self._check_findings_by_type(
                            'security_group',
                            loop=False,
                            sg_name=sg_name,
                            ports=ports,
                            source=source,
                            asset=asset
                        )
                        if result is not False:
                            report += result
        report_attributes = self._check_findings_by_type('attributes', asset=asset)
        if report_attributes is not False:
            report += report_attributes
        return report

    def extract_findings(self, asset):
        """Try to extract findings from asset

        :param asset: aws asset
        :type asset: AssetType
        :return: Report generated
        :rtype: list()
        """
        report = []
        report += self.extract_findings_from_security_groups(asset)
        return report

    def _check_arguments_definitions(self, arguments, name):
        errors = {
            'critical': list(),
            'warning': list()
        }
        for argument in arguments:
            if 'name' not in argument or 'type' in argument or 'value' in argument:
                errors['critical'].append(f'{name} must have a "name", "type" and "value"')
            else:
                if argument['type'] not in ['dict',  'var', 'value']:
                    errors['critical'].append(f'{name} type must be dict, var, value. Found {argument["type"]}')
                else:
                    if argument['type'] == 'dict' and 'key' not in argument:
                        errors['critical'].append(f'{name} with type "dict" must have a "key"')
        return errors

    def _check_rules_definitions(self, rule):
        errors = {
            'critical': list(),
            'warning': list(),
        }
        bad_format = False
        if 'type' not in rule:
            errors['critical'].append('No "type"')
        else:
            if rule['type'] not in self._rules_definitions:
                errors['critical'].append(f'Rule type {rule["type"]} not found in rules definitions')
        if 'description' not in rule:
            errors['warning'].append('No "description"')
        if 'conditions' not in rule:
            errors['critical'].append('No "conditions')
            bad_format = True
        else:
            if not isinstance(rule['conditions'], list):
                errors['critical'].append(f'"conditions" must be list, found {type(rule["conditions"])}')
                bad_format = True
        if 'data_sources' not in rule:
            errors['critical'].append('No "data_sources"')
            bad_format = True
        else:
            if not isinstance(rule['data_sources'], list):
                errors['critical'].append(f'"data_sources" must be list, found {type(rule["data_sources"])}')
                bad_format = True
        if not bad_format and rule['type'] in self._rules_definitions:
            data_sources_errors = self._check_arguments_definitions(rule['data_sources'], 'Variable')
            errors['critical'] += data_sources_errors['critical']
            errors['warning'] += data_sources_errors['warning']
            data_sources_name = [variable['name'] for variable in rule['data_sources']]
            conditions_errors = self._check_arguments_definitions(rule['conditions'], 'Value')
            errors['critical'] += conditions_errors['critical']
            errors['warning'] += conditions_errors['warning']
            conditions_name = [value['name'] for value in rule['conditions']]
            for variable in self._rules_definitions[rule['type']]['data_sources']:
                if not variable in data_sources_name:
                    errors['critical'].append(f'Unable to find {variable} in {list(data_sources_name)}')
            for value in self._rules_definitions[rule['type']]['conditions']:
                if not value in conditions_name:
                    errors['critical'].append(f'Unable to find {value} in {list(conditions_name)}')
        return errors
