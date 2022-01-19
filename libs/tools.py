#!/usr/bin/env python
"""
Tools class

Copyright 2020-2022 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
import logging
from pathlib import Path
import pickle
import re

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
