#!/usr/bin/env python
"""
IAM Scan library

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
import logging
import re

# Third party library imports
import boto3

from .asset_type_iam import IAM

# Debug
# from pdb import set_trace as st

LOGGER = logging.getLogger('aws-tower')


def get_policy_from_rolepolicy(rolepolicy, account_id):
    """
    Return policies in a RolePolicy, in a specific accountId
    """
    arns = []
    statements = rolepolicy.policy_document['Statement']
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if statement['Action'] != 'sts:AssumeRole':
            continue
        role_arns = statement['Resource']
        if isinstance(role_arns, str):
            role_arns = [role_arns]
        for role_arn in role_arns:
            role = IAM(arn=role_arn)
            if role.account_id == account_id:
                arns.append(role_arn)
    return arns


def get_actions_from_rolepolicy(rolepolicy):
    """
    Return actions associated to a RolePolicy
    """
    actions = []
    statements = rolepolicy.policy_document['Statement']
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if isinstance(statement['Action'], str):
            actions.append(statement['Action'])
        else:
            actions = [*actions, *statement['Action']]
    return actions


def get_actions_from_policy(client, policy):
    """
    Return actions associated to a Policy
    """
    actions = []
    document = client.get_policy_version(
        PolicyArn=policy.arn,
        VersionId=policy.default_version_id)
    for statement in document['PolicyVersion']['Document']['Statement']:
        if 'Action' not in statement:
            continue
        if isinstance(statement['Action'], str):
            actions.append(statement['Action'])
        else:
            actions = [*actions, *statement['Action']]
    return actions


def get_role_from_policy(policy, limit=1):
    """
    Return the nth role attached to a policy
    """
    try:
        for role in policy.attached_roles.limit(count=limit):
            return role.arn
    except:
        return None


def get_role_from_arn(client, arn):
    """
    Return role informations from an ARN
    """
    paginator = client.get_paginator('list_roles')
    for response in paginator.paginate():
        for role in response['Roles']:
            if role['Arn'] == arn:
                return role
    return None


def iam_extract(arn, account_id, verbose=False):
    """
    This heavy function is extracting arn from the current profile
    """
    iam_obj = IAM(arn=arn)
    if not iam_obj.is_valid():
        return []
    if iam_obj.account_id == account_id:
        return [arn]
    root_session = boto3.Session()
    root_account_id = root_session.client('sts').get_caller_identity().get('Account')
    if iam_obj.account_id != root_account_id:
        return []
    # In that case, we are in the root account, we can enumerate groups and roles
    arns = []
    root_client_iam = root_session.client('iam')
    root_resource_iam = root_session.resource('iam')
    paginator = root_client_iam.get_paginator('list_users')
    for response in paginator.paginate():
        for user in response['Users']:
            if arn == user['Arn']:
                res_user = root_resource_iam.User(user['UserName'])
                for group in res_user.groups.all():
                    if verbose:
                        LOGGER.warning(f'Found group {group.name}: {group.arn}')
                    group_obj = IAM(arn=group.arn)
                    if group_obj.account_id == account_id:
                        arns.append(group.arn)
                    else:
                        for rolepolicy in group.policies.all():
                            arns = [*arns, *get_policy_from_rolepolicy(
                                rolepolicy,
                                account_id=account_id)]
                        for policy in group.attached_policies.all():
                            arns.append(policy.arn)
    return arns


def iam_scan(client, resource, source_arn, action, verbose=False):
    """
    Return True if the ARN can do the action
    """
    iam_obj = IAM(arn=source_arn)
    if not iam_obj.is_valid():
        return False

    if iam_obj.resource_type in ['role', 'user', 'group']:
        return iam_obj.is_allowed_action(client, action, verbose=verbose)

    if iam_obj.resource_type == 'policy':
        # Get the first role that contain this policy, at least one
        # If it doesn't exist, it's an exception
        policy = resource.Policy(arn=source_arn)
        role_arn = get_role_from_policy(policy)
        if role_arn is not None:
            return IAM(arn=role_arn).is_allowed_action(client, action, verbose=verbose)
        return False

    LOGGER.warning(f'Resource type not valid: {iam_obj.resource_type}')
    return False


def iam_display(client, resource, arn, verbose=False):
    """
    Display information about the ARN
    """
    iam_obj = IAM(arn=arn)
    print(f'ARN: {arn}')
    print(f'Resource type: {iam_obj.resource_type}')
    if iam_obj.resource_type == 'role':
        role_info = get_role_from_arn(client, arn)
        if role_info is not None:
            print(f'Role Name: {role_info["RoleName"]}')
            role = resource.Role(role_info['RoleName'])
            actions = []
            for policy in role.policies.all():
                if verbose:
                    LOGGER.warning(f'RolePolicy: {policy.name}')
                actions = [*actions, *get_actions_from_rolepolicy(policy)]
            for policy in role.attached_policies.all():
                if verbose:
                    LOGGER.warning(f'Policy: {policy.arn}')
                actions = [*actions, *get_actions_from_policy(client, policy)]
            print(f'Actions: {set(actions)}')


def format_print(arn, actions, action_category):
    if not actions:
        return False
    if action_category is not None:
        if action_category in actions:
            filtered_actions = {action_category: actions[action_category]}
            LOGGER.warning(f'{arn}: {filtered_actions}')
            return True
        return False
    LOGGER.warning(f'{arn}: {actions}')
    return True


def display_actions(arn, actions, action_category):
    """
    Display a regrouped way to understand actions
    admin > poweruser (write|delete|update) > reader > lister
    """
    result = dict()
    types = dict()
    poweruser_multi_verbs = ['GitPush']
    readers_verb = [
        'Batch', 'Check', 'Compare', 'Count', 'Describe', 'Detect', 'Discover',
        'Download', 'Estimate', 'Evaluate', 'Export', 'Filter', 'Get', 'Git',
        'Is', 'List', 'Lookup', 'Preview', 'Query', 'Read', 'Receive', 'Resolve',
        'Request', 'Retrieve', 'Sample', 'Scan', 'Search', 'Select', 'Simulate',
        'Synthesize', 'Test', 'Verify', 'View']
    for action in actions:
        if action == '*':
            return format_print(arn, {'admin': ['*']}, action_category)
        service = action.split(':')[0]
        if service not in types:
            types[service] = []
        types[service].append(action.split(':')[1])
    for service in types:
        if '*' in types[service]:
            if 'admin' not in result:
                result['admin'] = list()
            result['admin'].append(service)
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
                if 'poweruser' not in result:
                    result['poweruser'] = list()
                result['poweruser'].append(service)
            elif is_reader:
                if 'reader' not in result:
                    result['reader'] = list()
                result['reader'].append(service)
    return format_print(arn, result, action_category)


def get_role_services(role):
    """
    Return services associated to the role
    """
    services = []
    for statement in role['AssumeRolePolicyDocument']['Statement']:
        service = 'Unknown'
        if 'Service' in statement['Principal']:
            service = statement['Principal']['Service']
        elif 'AWS' in statement['Principal']:
            service = statement['Principal']['AWS']
        elif 'Federated' in statement['Principal']:
            service = statement['Principal']['Federated']
        services.append(service)
    return services


def iam_display_roles(client, resource, arn, action_category, service, verbose=False):
    """
    Display all roles actions
    """
    paginator = client.get_paginator('list_roles')
    for response in paginator.paginate():
        for role in response['Roles']:
            if arn and role['Arn'] != arn:
                continue
            if service and service not in get_role_services(role):
                continue
            actions = []
            for rolepolicy in resource.Role(role['RoleName']).policies.all():
                actions = [*actions, *get_actions_from_rolepolicy(rolepolicy)]
            for policy in resource.Role(role['RoleName']).attached_policies.all():
                actions = [*actions, *get_actions_from_policy(client, policy)]
            is_diplayed = display_actions(role['Arn'], actions, action_category)
            if verbose and is_diplayed:
                LOGGER.warning(f'Actions: {actions}')
                LOGGER.warning(f'AWS Services: {get_role_services(role)}')
