#!/usr/bin/env python
"""
IAM Scan library

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard imports
from datetime import datetime, timedelta, timezone

# Third party library imports
import boto3

from .asset_type_iam import IAM, Policy

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
    only_dangerous_actions=False,
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
    if iam_obj.dangerous_actions:
        console.print(f'[red]Dangerous actions: {iam_obj.dangerous_actions}[/red]')
    if not only_dangerous_actions:
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

def iam_get_users(client, cache):
    """
    Retrieves a list of IAM users and their access key details using a given AWS IAM client.

    This function lists all users in the IAM and checks each user's access keys.
    It determines if any active access keys are vulnerable based on specific
    criteria: the key is older than 1 year or it was last used more than 6 months ago.
    It appends this information to an IAM user object and
    returns a list of these user objects.

    Parameters:
    client (boto3.client): An initialized boto3 IAM client object.

    Returns:
    list: A list of IAM user objects. Each IAM user object contains the user's ARN, access keys,
          and a flag indicating if the user has any vulnerable access keys.

    Note:
    The IAM user object is assumed to be defined with attributes 'arn', 'access_keys' (a list),
    and 'has_vulnerable_access_key' (a boolean). The function assumes 'IAM' is a predefined class.
    """
    users = client.list_users()
    current_date = datetime.now(timezone.utc)
    iam_users = []
    for user in users['Users']:
        iam_user = IAM(arn=user['Arn'])
        access_keys = client.list_access_keys(UserName=user['UserName'])
        for access_key in access_keys['AccessKeyMetadata']:
            if access_key['Status'] == 'Active':
                access_key_id = access_key['AccessKeyId']
                creation_date = access_key['CreateDate']

                # Get last used information of the access key
                last_used_info = client.get_access_key_last_used(AccessKeyId=access_key_id)
                last_used_date = last_used_info['AccessKeyLastUsed'].get('LastUsedDate', 'Never')

                if current_date - creation_date > timedelta(days=365) or \
                (last_used_date != 'Never' and current_date - last_used_date > timedelta(days=180)):
                    iam_user.old_access_keys.append(\
                        f'{access_key_id} ({(current_date - creation_date).days} days)')
        if iam_user.old_access_keys:
            policies = client.list_attached_user_policies(UserName=user['UserName'])
            for _p in policies['AttachedPolicies']:
                policy = Policy(arn=_p['PolicyArn'], policy_name=_p['PolicyName'])
                policy.default_version_id = \
                    client.get_policy(PolicyArn=policy.arn)['Policy']['DefaultVersionId']
                iam_user.actions = get_actions_from_policy(client, policy, cache)
        iam_user.simplify_actions()
        iam_users.append(iam_user)
    return iam_users

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
    only_dangerous_actions=False,
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
        if only_dangerous_actions:
            if role.dangerous_actions:
                print(f'{role.name}: {role.dangerous_actions}')
        else:
            actions = role.print_actions(min_rights)
            if actions:
                console.print(actions)
                if verbose:
                    console.print(f'Actions: {role.actions}')
