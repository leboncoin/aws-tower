#!/usr/bin/env python
"""
Tools class

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
import logging
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
