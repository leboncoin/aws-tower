#!/usr/bin/env python
"""
Asset types IAM class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
import logging
import re

from .asset_type import AssetType

# Debug
# from pdb import set_trace as st

LOGGER = logging.getLogger('aws-tower')

def allowed(response, action, resource):
    """
    Return True if the specified action is allowed on the specified resource
    """
    evaluation_results = response['EvaluationResults']
    for result in evaluation_results:
        if action == result['EvalActionName'] and resource == result['EvalResourceName']:
            return result['EvalDecision'] == 'allowed'
    return False

class IAM(AssetType):
    """
    IAM Asset Type
    """
    def __init__(self, arn: str):
        super().__init__('IAM role', arn, public=False)
        self.arn = arn
        self.actions = []
        self.admin_actions = None
        self.poweruser_actions = None
        self.reader_actions = None
        if self.is_valid():
            self.partition = arn.split(':')[1]
            self.service = arn.split(':')[2]
            self.region = arn.split(':')[3]
            self.account_id = arn.split(':')[4]
            self.resource_type = arn.split(':')[5].split('/')[0]
            self.resource_id = arn.split(':')[5].split('/')[1]

    def is_valid(self):
        """
        Return True if the arn is valid:
        arn:partition:service:region:account-id:resource-type/resource-id
        """
        return len(self.arn.split(':')) == 6 and \
            len(self.arn.split(':')[5].split('/')) >= 2

    def is_allowed_action(self, session, actions, verbose=False):
        """
        Return True is the actions are granted by this IAM arn
        """
        if isinstance(actions, str):
            actions = [actions]
        try:
            response = session.simulate_principal_policy(
                PolicySourceArn=self.arn,
                ActionNames=actions)
        except Exception as err_msg:
            print(err_msg)
            return False
        is_allowed = False
        for action in actions:
            is_allowed = is_allowed or allowed(response, action, '*')
        if verbose and is_allowed:
            LOGGER.warning(f'Match for {self.arn}')
        return is_allowed

    def simplify_actions(self):
        """
        Simplify the actions and regroupe in a way to understand actions
        admin > poweruser (write|delete|update) > reader > lister
        """
        types = {}
        poweruser_multi_verbs = ['GitPush']
        readers_verb = [
            'Batch', 'Check', 'Compare', 'Count', 'Describe', 'Detect', 'Discover',
            'Download', 'Estimate', 'Evaluate', 'Export', 'Filter', 'Get', 'Git',
            'Is', 'List', 'Lookup', 'Preview', 'Query', 'Read', 'Receive', 'Resolve',
            'Request', 'Retrieve', 'Sample', 'Scan', 'Search', 'Select', 'Simulate',
            'Synthesize', 'Test', 'Verify', 'View']
        for action in self.actions:
            if action == '*':
                self.admin_actions = ['*']
                return
            service = action.split(':')[0]
            if service not in types:
                types[service] = []
            types[service].append(action.split(':')[1])
        for service in types:
            if '*' in types[service]:
                if self.admin_actions is None:
                    self.admin_actions = []
                self.admin_actions.append(service)
            else:
                is_poweruser = False
                is_reader = False
                for action in types[service]:
                    verb = re.search('^[A-Z][a-z]+', action)
                    is_poweruser = is_poweruser or \
                        (verb and verb.group(0) not in readers_verb) or \
                        (action in poweruser_multi_verbs)
                    is_reader = is_reader or \
                        (verb and verb.group(0) in readers_verb and action not in poweruser_multi_verbs)
                if is_poweruser:
                    if self.poweruser_actions is None:
                        self.poweruser_actions = []
                    self.poweruser_actions.append(service)
                elif is_reader:
                    if self.reader_actions is None:
                        self.reader_actions = []
                    self.reader_actions.append(service)


    def print_actions(self, min_rights):
        """
        Display the actions right filtered by min_rights action category
        """
        action_category = {
            "admin": 0,
            "poweruser": 1,
            "reader": 2
        }
        action_id = {
            0: "admin",
            1: "poweruser",
            2: "reader"
        }
        if not self.actions:
            return False
        if min_rights is None or min_rights not in action_category:
            min_rights = 'reader'
        filtered_actions = {}
        for i in range(action_category[min_rights]+1):
            if getattr(self, f'{action_id[i]}_actions') is None:
                continue
            filtered_actions[action_id[i]] = getattr(self, f'{action_id[i]}_actions')
        LOGGER.warning(f'{self.arn}: {filtered_actions}')
        return True


    def report(self, report, brief=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {
                'Arn': self.arn
            }
            if self.admin_actions:
                asset_report['Admin actions'] = self.admin_actions
            if self.poweruser_actions:
                asset_report['Poweruser actions'] = self.poweruser_actions
            if self.security_issues:
                self.update_audit_report(asset_report)
        if 'IAM' not in report:
            report['IAM'] = { self.arn: asset_report }
            return report
        report['IAM'].update(
            { self.arn: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        actions = ''
        if self.admin_actions:
            actions += f'Admin actions: {self.admin_actions} '
        if self.poweruser_actions:
            actions += f'Poweruser actions: {self.poweruser_actions} '
        return f'{actions}{self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        return f'Actions: {self.actions}'
