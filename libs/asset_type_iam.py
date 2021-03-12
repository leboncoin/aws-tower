#!/usr/bin/env python
"""
Asset types IAM class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
import logging

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
        super().__init__(arn, public=False)
        self.arn = arn
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
            len(self.arn.split(':')[5].split('/')) == 2

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

    def display(self, verbose=False):
        """
        Describe the object
        """
        return f'ARN: {self.arn}'
