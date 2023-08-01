#!/usr/bin/env python
"""
Tools class

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
import json
import logging
from pathlib import Path
import pickle
import re

# ThirdParty
import ruamel.yaml
from ruamel.yaml.error import YAMLError

# Debug
# from pdb import set_trace as st

LOGGER = logging.getLogger('aws-tower')
COLOG_TAG_REGEX = '\[\/?[a-z ]+\]'

def get_tag(tags, key):
    """ Returns a specific value in aws tags, from specified key
    """
    names = [item['Value'] for item in tags if item['Key'] == key]
    if not names:
        return ''
    return names[0]

def draw_sg(security_group, sg_raw):
    """
    Returns a full definition of security groups
    Ex: {'80': ['0.0.0.0/0'], '9182': ['sg-e6337083'], '6379': ['sg-83b71de4', '34.1.1.1/32', '3.1.1.1/32'], '4520': ['0.0.0.0/0'], '3389': ['0.0.0.0/0'], '443': ['0.0.0.0/0']}
    """
    result = {}
    for _sg in sg_raw:
        if _sg['GroupId'] == security_group:
            for ip_perm in _sg['IpPermissions']:
                if ip_perm['IpProtocol'] in ['tcp', '-1']:
                    if ip_perm['IpProtocol'] == '-1':
                        if 'all' not in result:
                            result['all'] = []
                        value = None
                        for group in ip_perm['UserIdGroupPairs']:
                            value = f'{group["GroupId"]}'
                            if value not in result['all']:
                                result['all'].append(value)
                        for cidr in ip_perm['IpRanges']:
                            value = f'{cidr["CidrIp"]}'
                            if value not in result['all']:
                                result['all'].append(value)
                    else:
                        from_port = ip_perm['FromPort']
                        to_port = ip_perm['ToPort']
                        key_ports = f'{from_port}'
                        if from_port != to_port:
                            key_ports += f'-{to_port}'
                        if key_ports  not in result:
                            result[key_ports] = []
                        ip_range = ip_perm['IpRanges']
                        userid_group_pairs = ip_perm['UserIdGroupPairs']
                        value = None
                        for group in userid_group_pairs:
                            value = f'{group["GroupId"]}'
                            if value not in result[key_ports]:
                                result[key_ports].append(value)
                        for cidr in ip_range:
                            value = f'{cidr["CidrIp"]}'
                            if value not in result[key_ports]:
                                result[key_ports].append(value)
    return result

def generate_layer(rules_path):
    """
    Generate a layer for the ATT&CK navigator
    """
    yaml = ruamel.yaml.YAML()
    layer = {
        "name": "AWS Tower",
        "versions": {
            "attack": "11",
            "navigator": "4.6.4",
            "layer": "4.3"
        },
        "domain": "enterprise-attack",
        "description": "AWS Tower layer",
        "filters": {
            "platforms": [
                "PRE",
                "IaaS"
            ]
        },
        "sorting": 0,
        "layout": {
            "layout": "flat",
            "aggregateFunction": "average",
            "showID": False,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False
        },
        "hideDisabled": False,
        "techniques": [],
        "gradient": {
            "colors": [
                "#ffe766ff",
                "#8ec843ff"
            ],
            "minValue": 0,
            "maxValue": 3
        },
        "metadata": [],
        "links": [
            {
                "label": "AWS Tower GitHub",
                "url": "https://github.com/leboncoin/aws-tower"
            }
        ],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False
    }
    try:
        rules = yaml.load(rules_path)
    except YAMLError as err_msg:
        print(f'Cannot read rules.yml: {err_msg}')
        return
    for i in ['visibility', 'detection', 'protection']:
        tech_ids = set()
        for rule in [
            *rules['types']['security_group']['findings'],
            *rules['types']['attributes']['findings']]:
            if 'metadata' not in rule or i not in rule['metadata']:
                continue
            for tech_id in rule['metadata'][i]:
                tech_ids.add(tech_id)
        for tech_id in tech_ids:
            # Check if technique is not already in the layer
            if not sum([ t['techniqueID'] == tech_id for t in layer['techniques'] ]):
                layer['techniques'].append({
                    "techniqueID": tech_id,
                    "score": 1,
                    "color": "",
                    "comment": "",
                    "enabled": True,
                    "metadata": [],
                    "links": [],
                    "showSubtechniques": False
                })
            else:
                for t in layer['techniques']:
                    if t['techniqueID'] == tech_id:
                        t['score'] += 1
    print(json.dumps(layer))

def get_account_in_arn(arn):
    """
    Extracts the aws account id in the arn, if exists
    """
    if len(arn.split(':')) >= 5:
        return arn.split(':')[4]
    return '000000000000'

def get_lambda_name(apigw_arn):
    """
    Extracts the lambda name of the function in an APIGW integration
    """
    return 'lambda:' + apigw_arn.split(':')[-1].split('/')[0]

def get_network(subnet_id, subnets_raw):
    """
    Get simple name for vpc and subnet
    """
    region = 'unknown'
    vpc = 'unknown'
    subnet = 'unknown'
    for _subnet in subnets_raw:
        if _subnet['SubnetId'] == subnet_id:
            region = _subnet['AvailabilityZone'][:-1]
            vpc = _subnet['VpcId']
            subnet = _subnet['SubnetId']
    return region, vpc, subnet

def color_severity(severity, message, console):
    """
    For a given severity, return the severity with the message
    in the suitable color
    """
    color = 'bold red'
    if severity == 'info':
        color = 'blue'
    elif severity == 'low':
        color = 'bold blue'
    elif severity == 'medium':
        color = 'bold yellow'
    if isinstance(message, str):
        message = message.replace('[', '<').replace(']', '>')
    output = f'[{color}]{severity}: {message}[/{color}]'
    if console is None:
        output = re.sub(COLOG_TAG_REGEX, '', output)
    return output

def log_me(message):
    """
    This function with a decorator of logging
    """
    def decorator(func):
        def inner(*kwargs):
            console = kwargs[-1]
            if isinstance(console, type(None)):
                LOGGER.warning(message)
                return func(*kwargs)
            with console.status(f'[bold green]{message}'):
                return func(*kwargs)
        return inner
    return decorator

class NoColor:
    """
    Display log with LOGGER
    """
    def print(self, message):
        """
        Display message without console colors
        """
        message = re.sub(COLOG_TAG_REGEX, '', message)
        LOGGER.warning(message)

def rm_tree(pth):
    """
    This function is removing a directory with all files inside
    """
    pth = Path(pth)
    for child in pth.glob('*'):
        if child.is_file():
            child.unlink()
        else:
            rm_tree(child)
    pth.rmdir()

class Cache:
    """
    Cache is a class to store and get cached objects
    """
    def __init__(self, cache_dir, prefix, purge=False):
        self.prefix = prefix
        self.enabled = prefix != ''
        if self.enabled:
            cache_dir = Path(cache_dir)
            if purge:
                rm_tree(cache_dir)
            cache_dir.mkdir(parents=True, exist_ok=True)
    def save_file(self, result, cache_file):
        """
        This function is saving the file on disk
        """
        if self.enabled:
            try:
                pickle.dump(result, cache_file.open(mode='wb'))
            except:
                cache_file.unlink()
    def get(self, key, client, method, args=(), paginate=False):
        """
        Returns the value of the key, else do client.method() and save it
        """
        cache_file = Path(f'{self.prefix}_{key}')
        if cache_file.exists() and self.enabled:
            return pickle.load(cache_file.open(mode='rb'))
        if not hasattr(client, method):
            LOGGER.critical(f'Method {method} does not exists...')
            return None
        result = getattr(client, method)(*args)
        if paginate:
            paginator = result
            result = []
            for i in paginator.paginate():
                result.append(i)
        self.save_file(result, cache_file)
        return result
    def get_asset(self, key):
        """
        Get an asset from cache
        """
        cache_file = Path(f'{self.prefix}_{key}')
        if cache_file.exists() and self.enabled:
            return pickle.load(cache_file.open(mode='rb'))
        return None
    def save_asset(self, key, asset):
        """
        Save an asset in cache
        """
        cache_file = Path(f'{self.prefix}_{key}')
        self.save_file(asset, cache_file)
    def get_ec2_iam_raw(self, key, client, ip_name):
        """
        Custom cache method for ec2_iam_raw, piclkes not working with boto3.resources.factory.iam.*
        """
        cache_file = Path(f'{self.prefix}_{key}')
        if cache_file.exists() and self.enabled:
            return pickle.load(cache_file.open(mode='rb'))
        ec2_ip = client.InstanceProfile(ip_name)
        result = [role.name for role in ec2_ip.roles]
        self.save_file(result, cache_file)
        return result
    def get_iam_policy_version(self, key, client, policy_arn, version_id):
        """
        Custom cache method for iam.get_policy_version
        """
        cache_file = Path(f'{self.prefix}_{key}')
        if cache_file.exists() and self.enabled:
            return pickle.load(cache_file.open(mode='rb'))
        result = client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id)
        self.save_file(result, cache_file)
        return result
    def get_r53_list_resource_record_sets(self, key, client, hosted_zone_id):
        """
        Custom cache method for r53.list_resource_record_sets(HostedZoneId=hosted_zone_id)
        """
        cache_file = Path(f'{self.prefix}_{key}')
        if cache_file.exists() and self.enabled:
            return pickle.load(cache_file.open(mode='rb'))
        result = client.list_resource_record_sets(
            HostedZoneId=hosted_zone_id)
        self.save_file(result, cache_file)
        return result
    def get_eks_describe_cluster(self, key, client, cluster_name):
        """
        Custom cache method for eks.describe_cluster(name=cluster_name)
        """
        cache_file = Path(f'{self.prefix}_{key}')
        if cache_file.exists() and self.enabled:
            return pickle.load(cache_file.open(mode='rb'))
        result = client.describe_cluster(
            name=cluster_name)
        self.save_file(result, cache_file)
        return result
    def get_caller_identity(self, key, client):
        """
        Custom cache method for session.client('sts').get_caller_identity()
        """
        cache_file = Path(f'{self.prefix}_{key}')
        if cache_file.exists() and self.enabled:
            return pickle.load(cache_file.open(mode='rb'))
        result = client.client('sts').get_caller_identity()
        self.save_file(result, cache_file)
        return result
    def get_vpc_endpoint_services_permission(self, key, client, service_id):
        """
        Custom cache method for ec2.describe_vpc_endpoint_service_permissions(ServiceId=service_id)
        """
        cache_file = Path(f'{self.prefix}_{key}')
        if cache_file.exists() and self.enabled:
            return pickle.load(cache_file.open(mode='rb'))
        result = client.describe_vpc_endpoint_service_permissions(
            ServiceId=service_id)
        self.save_file(result, cache_file)
        return result
    def get_elb_describe_target_health(self, key, client, targetgrouparn):
        """
        Custom cache method for elb.describe_target_health(TargetGroupArn=targetgrouparn)
        """
        cache_file = Path(f'{self.prefix}_{key}')
        if cache_file.exists() and self.enabled:
            return pickle.load(cache_file.open(mode='rb'))
        result = client.describe_target_health(
            TargetGroupArn=targetgrouparn)
        self.save_file(result, cache_file)
        return result

def search_filter_in(asset, filter_str):
    """
    Return True if the filter_str is in the asset
    - by default -> asset.name and a lot of asset attributes
    - port:xxx -> asset.security_groups (ELB, EC2)
    - engine:xxx -> asset.engine (RDS)
    - version:xxx -> asset.version (EKS, RDS)
    - os:xxx -> asset.version (EC2)
    """
    filter_str = filter_str.lower()
    if asset is None:
        return False
    is_found = False
    if filter_str.startswith('port:') and hasattr(asset, 'security_groups'):
        port = filter_str.split(':')[1]
        for security_group in asset.security_groups:
            is_found |= port in asset.security_groups[security_group].keys()
    elif filter_str.startswith('engine:') and hasattr(asset, 'engine'):
        is_found = asset.engine.lower().startswith(filter_str.split(':')[1])
    elif filter_str.startswith('version:'):
        version = filter_str.split(':')[1]
        if asset.get_type() == 'EKS':
            is_found = asset.version.startswith(version)
        if asset.get_type() == 'RDS' and '==' in asset.engine:
            is_found = asset.engine.split('==')[1].startswith(version)
    elif filter_str.startswith('os:') and hasattr(asset, 'operating_system'):
        os_name = f'{asset.operating_system}+{asset.operating_system_name}'.lower()
        is_found = os_name in filter_str.split(':')[1] or filter_str.split(':')[1] in os_name
    else:
        if filter_str in asset.name.lower():
            return True
        for attribute in [
            'aliases', 'api_endpoint', 'arn',
            'dns_record', 'dst_account_id', 'endpoint',
            'engine', 'private_ip', 'public_ip', 'src_account_id', 'url',
            'role_poweruser', 'role_admin']:
            is_found |= hasattr(asset, attribute) and \
                isinstance(getattr(asset, attribute), str) and \
                filter_str in getattr(asset, attribute).lower()
    return is_found
