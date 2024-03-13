#!/usr/bin/env python
"""
Asset types IAM class

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
import logging
import re
from dataclasses import dataclass

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

@dataclass
class Policy:
    """
    Policy nutshell
    """
    arn: str = ''
    default_version_id: str = ''
    policy_name: str = ''

class IAM(AssetType):
    """
    IAM Asset Type
    """
    def __init__(self, arn: str):
        super().__init__('IAM', arn, public=False)
        self.arn = arn
        self.actions = []
        self.admin_services = None # None instead of set(), for rules matching
        self.admin_actions = set()
        self.dangerous_actions = None # None instead of set(), for rules matching
        self.is_instance_profile = False
        self.poweruser_services = None # None instead of set(), for rules matching
        self.poweruser_actions = set()
        self.old_access_keys = []
        if self.is_valid():
            self.partition = arn.split(':')[1]
            self.service = arn.split(':')[2]
            self.region = arn.split(':')[3]
            self.account_id = arn.split(':')[4]
            self.resource_type = arn.split(':')[5].split('/')[0]
            self.resource_id = '/'.join(arn.split(':')[5].split('/')[1:])

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

    def add_dangerous_actions(self, service, action):
        """
        Append list of dangerous_actions if exists
        """
        dangerous_actions = [
            'iam:PassRole',
            # SSM everywhere
            'ssm:SendCommand',
            'ssm:StartSession',
            # https://sra.io/blog/aws-iam-exploitation/
            'iam:PutGroupPolicy',
            'iam:PutRolePolicy',
            'iam:PutUserPolicy',
            'iam:AttachGroupPolicy',
            'iam:AttachRolePolicy',
            'iam:AttachUserPolicy',
            'iam:CreatePolicyVersion',
            'iam:SetDefaultPolicyVersion',
            'iam:AddUserToGroup',
            'iam:CreateLoginProfile',
            'iam:UpdateLoginProfile',
            'iam:CreateAccessKey'
        ]
        for dangerous_action in dangerous_actions:
            if service == dangerous_action.split(':', maxsplit=1)[0] and \
                action in ['*', dangerous_action.split(':')[1]]:
                if self.dangerous_actions is None:
                    self.dangerous_actions = []
                if dangerous_action not in self.dangerous_actions:
                    self.dangerous_actions.append(dangerous_action)

    def get_type(self):
        """
        Redefinition of get_type
        """
        return f'IAM {self.resource_type}'

    def simplify_actions(self):
        """
        Simplify the actions and regroupe in a way to understand actions
        admin > poweruser (write|delete|update) > reader
        """
        types = {}
        readers_multi_verbs = [
            'AdminGet', 'AdminList', 'ESHttpGet', 'ESHttpHead', 'StartCostEstimation',
            # SSM
            'PutInventory', 'PutConfigurePackageResult', 'PutComplianceItems',
            'UpdateAssociationStatus', 'UpdateInstanceAssociationStatus',
            'UpdateInstanceInformation']
        poweruser_multi_verbs = ['GitPush']
        readers_verb = [
            'Batch', 'Check', 'Classify', 'Compare', 'Contains', 'Count',
            'Describe', 'Detect', 'Discover', 'Download', 'Estimate', 'Evaluate',
            'Export', 'Filter', 'Generate', 'Get', 'Git', 'Is', 'List', 'Lookup', 'Preview',
            'Query', 'Read', 'Receive', 'Resolve', 'Request', 'Retrieve',
            'Sample', 'Scan', 'Search', 'Select', 'Simulate',
            'Synthesize', 'Test', 'Validate', 'Verify', 'View']
        for action in self.actions:
            if action == '*':
                self.admin_services = ['*']
                self.admin_actions.add(action)
                return
            service = action.split(':')[0]
            if service not in types:
                types[service] = []
            types[service].append(action.split(':')[1])
        for service, actions in types.items():
            if '*' in actions:
                if self.admin_services is None:
                    self.admin_services = []
                self.admin_services.append(service)
                self.admin_actions.add(f'{service}:*')
            else:
                is_poweruser = False
                for action in actions:
                    self.add_dangerous_actions(service, action)
                    verb = re.search('^[A-Z][a-z]+', action)
                    if ((verb and verb.group(0) not in readers_verb) or \
                        (action in poweruser_multi_verbs)) and \
                        True not in [ action.startswith(i) for i in readers_multi_verbs ]:
                        is_poweruser = True
                        self.poweruser_actions.add(f'{service}:{action}')
                if is_poweruser:
                    if self.poweruser_services is None:
                        self.poweruser_services = set()
                    self.poweruser_services.add(service)
        # To avoid random order in output
        if self.admin_services:
            self.admin_services = list(self.admin_services)
            self.admin_services.sort()
        if self.poweruser_services:
            self.poweruser_services = list(self.poweruser_services)
            self.poweruser_services.sort()

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
            return ''
        if min_rights is None or min_rights not in action_category:
            min_rights = 'reader'
        filtered_actions = {}
        for i in range(action_category[min_rights]+1):
            if getattr(self, f'{action_id[i]}_services') is None:
                continue
            filtered_actions[action_id[i]] = getattr(self, f'{action_id[i]}_services')
        return f'{self.arn}: {filtered_actions}'


    def report(self, report, brief=False, with_fpkey=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {
                'Arn': self.arn
            }
            if self.admin_services:
                asset_report['Admin actions'] = f'[red]{self.admin_services}[/red]'
            if self.dangerous_actions:
                asset_report['Dangerous actions'] = f'[red]{self.dangerous_actions}[/red]'
            if self.poweruser_services:
                asset_report['Poweruser actions'] = f'[yellow]{self.poweruser_services}[/yellow]'
            if self.old_access_keys:
                asset_report['Old Access Keys'] += f'[yellow]{self.old_access_keys}[/yellow] '
            if self.security_issues:
                self.update_audit_report(asset_report, with_fpkey)
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
        if self.admin_services:
            actions += f'[red]Admin actions: {self.admin_services}[/red] '
        if self.dangerous_actions:
            actions += f'[red]Dangerous actions: {self.dangerous_actions}[/red] '
        if self.poweruser_services:
            actions += f'[yellow]Poweruser actions: {self.poweruser_services}[/yellow] '
        if self.old_access_keys:
            actions += f'[yellow]Old access keys: {self.old_access_keys}[/yellow] '
        if actions:
            actions += f'- AWS IAM {self.resource_type}'
        return f'{actions}{self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        return f'Admin actions: {self.admin_actions}\nPoweruser actions: {self.poweruser_actions}\nALL actions: {self.actions}'
