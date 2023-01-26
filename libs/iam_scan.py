#!/usr/bin/env python
"""
IAM Scan library

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Third party library imports
import boto3

from .asset_type_iam import IAM

# Debug
# from pdb import set_trace as st

def complete_source_arn(session, arn):
    """
    Return a complete ARN if this is just a simple string
    arn:partition:service:region:account-id:resource-type/resource-id
    """
    if IAM(arn=arn).is_valid():
        return arn
    account_id = session.client('sts').get_caller_identity().get('Account')
    return f'arn:aws:iam::{account_id}:role/{arn}'


def filter_actions(actions, passlist):
    """
    Return a filtered list of actions using the passlist
    """
    filtered_actions = []
    for action in actions:
        if ':' not in action or action.split(':')[0] not in passlist:
            filtered_actions.append(action)
    return filtered_actions


def get_policy_from_rolepolicy(rolepolicy, account_id):
    """
    Return policies in a RolePolicy, in a specific accountId
    Do not return:
        - Actions without 'sts:AssumeRole'
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
    Do not return:
        - Resource != '*'
        - NotResource
    """
    actions = []
    statements = rolepolicy.policy_document['Statement']
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if 'Action' not in statement:
            continue
        # Hide NotResource type
        if 'Resource' not in statement:
            continue
        # Hide non-global actions
        if statement['Resource'] != '*':
            continue
        if isinstance(statement['Action'], str):
            actions.append(statement['Action'])
        else:
            actions = [*actions, *statement['Action']]
    return actions


def get_actions_from_policy(client, policy, cache):
    """
    Return actions associated to a Policy
    """
    actions = []
    document = cache.get_iam_policy_version(
        f'iam_policy_version_{policy.policy_name}',
        client,
        policy.arn,
        policy.default_version_id)
    for statement in document['PolicyVersion']['Document']['Statement']:
        if 'Action' not in statement:
            continue
        # Hide non-global actions
        if 'Resource' not in statement or statement['Resource'] != '*':
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


def iam_extract(arn, account_id, console, verbose=False):
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
                        console.print(f'Found group {group.name}: {group.arn}')
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


def iam_simulate(client, resource, source_arn, action, console, verbose=False):
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

    console.print(f'Resource type not valid: {iam_obj.resource_type}')
    return False


def iam_display(
    client,
    resource,
    arn,
    min_rights,
    cache,
    console,
    iam_action_passlist=[],
    iam_rolename_passlist=[],
    verbose=False):
    """
    Display information about the ARN
    """
    iam_obj = IAM(arn=arn)
    console.print(f'ARN: {arn}')
    console.print(f'Resource type: {iam_obj.resource_type}')
    if iam_obj.resource_type != 'role':
        return
    role_info = get_role_from_arn(client, arn)
    if role_info is None or role_info['RoleName'] in iam_rolename_passlist:
        return
    console.print(f'Role Name: {role_info["RoleName"]}')
    role = resource.Role(role_info['RoleName'])

    # Get all actions
    actions = []
    for policy in role.policies.all():
        if verbose:
            console.print(f'RolePolicy: {policy.name}')
        actions = [*actions, *get_actions_from_rolepolicy(policy)]
    for policy in role.attached_policies.all():
        if verbose:
            console.print(f'Policy: {policy.arn}')
        actions = [*actions, *get_actions_from_policy(client, policy, cache)]
    actions = filter_actions(actions, iam_action_passlist)

    # Display actions
    iam_obj.actions = actions
    iam_obj.simplify_actions()
    if iam_obj.admin_actions:
        console.print(f'[red]Admin actions: {iam_obj.admin_actions}[/red]')
    if iam_obj.poweruser_actions and min_rights != 'admin':
        console.print(f'[yellow]Poweruser actions: {iam_obj.poweruser_actions}[/yellow]')
    console.print(f'ALL Actions: {set(actions)}')

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


def iam_get_roles(
    client,
    resource,
    cache,
    iam_action_passlist=[],
    iam_rolename_passlist=[],
    arn=None,
    service=None):
    """
    Return all roles, with associated actions
    Filter actions with the action_passlist
    """
    roles = []
    paginator = cache.get(
        'iam_paginator_list_roles',
        client,
        'get_paginator',
        args=('list_roles',),
        paginate=True)
    for response in paginator:
        for role in response['Roles']:
            role_obj = cache.get_asset(f'iam_{role["RoleName"]}')
            if role_obj is None:
                if arn and role['Arn'] != arn:
                    continue
                if service and service not in get_role_services(role):
                    continue
                role_obj = IAM(arn=role['Arn'])
                if role_obj.resource_id.startswith('aws-reserved') or \
                    role_obj.resource_id.startswith('aws-service-role') or \
                    role_obj.resource_id.startswith('service-role'):
                    continue
                role_obj.is_instance_profile = {'Service': 'ec2.amazonaws.com'} in [ x['Principal'] for x in role['AssumeRolePolicyDocument']['Statement'] if 'Principal' in x]
                if role['RoleName'] in iam_rolename_passlist:
                    continue
                actions = []
                for rolepolicy in resource.Role(role['RoleName']).policies.all():
                    actions = [*actions, *get_actions_from_rolepolicy(rolepolicy)]
                for policy in resource.Role(role['RoleName']).attached_policies.all():
                    actions = [*actions, *get_actions_from_policy(client, policy, cache)]
                role_obj.actions = filter_actions(actions, iam_action_passlist)
                role_obj.simplify_actions()
                cache.save_asset(f'iam_{role["RoleName"]}', role_obj)
            roles.append(role_obj)
    return roles


def iam_display_roles(
    client,
    resource,
    arn,
    min_rights,
    service,
    cache,
    console,
    iam_action_passlist=[],
    iam_rolename_passlist=[],
    verbose=False):
    """
    Display all roles actions
    """
    roles = iam_get_roles(
        client,
        resource,
        cache,
        iam_action_passlist=iam_action_passlist,
        iam_rolename_passlist=iam_rolename_passlist,
        arn=arn,
        service=service)
    for role in roles:
        actions = role.print_actions(min_rights)
        if actions:
            console.print(actions)
            if verbose:
                console.print(f'Actions: {role.actions}')
