#!/usr/bin/env python
"""
Scan library

Copyright 2020 Nicolas BEGUIER
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
import json
import logging

# Debug
# from pdb import set_trace as st

VERSION = '1.3.0'

LOGGER = logging.getLogger('aws-tower')

def get_tag(tags, key):
    names = [item['Value'] for item in tags if item['Key'] == key]
    if not names:
        return ''
    return names[0]

def draw_sg(security_group, sg_raw):
    result = ''
    for sg in sg_raw:
        if sg['GroupId'] != security_group:
            continue
        for ip_perm in sg['IpPermissions']:
            if ip_perm['IpProtocol'] not in ['tcp', '-1']:
                continue
            if ip_perm['IpProtocol'] == '-1':
                for group in ip_perm['UserIdGroupPairs']:
                    result += '{},'.format(group['GroupId'])
                for cidr in ip_perm['IpRanges']:
                    result += '{},'.format(cidr['CidrIp'])
                result = result[:-1] + '->All '
                continue
            from_port = ip_perm['FromPort']
            to_port = ip_perm['FromPort']
            ip_range = ip_perm['IpRanges']
            userid_group_pairs = ip_perm['UserIdGroupPairs']
            for group in userid_group_pairs:
                result += '{},'.format(group['GroupId'])
            for cidr in ip_range:
                result += '{},'.format(cidr['CidrIp'])
            result = result[:-1] + '=>{}'.format(from_port)
            if from_port != to_port:
                result += '-{}'.format(to_port)
            result += ' '
    return result[:-1]

def parse_report(report):
    """
    Return anomalies from report
    """
    new_report = dict()
    new_report['EC2'] = list()
    new_report['ELBV2'] = list()
    for vpc in report:
        for subnet in report[vpc]['Subnets']:
            mini_name = report[vpc]['Subnets'][subnet]['Name'].split('-{}'.format(
                report[vpc]['Subnets'][subnet]['AvailabilityZone']))[0]
            for ec2 in report[vpc]['Subnets'][subnet]['EC2']:
                report[vpc]['Subnets'][subnet]['EC2'][ec2].update({'Subnet Name': mini_name})
                new_report['EC2'].append(report[vpc]['Subnets'][subnet]['EC2'][ec2])
            for elbv2 in report[vpc]['Subnets'][subnet]['ELBV2']:
                report[vpc]['Subnets'][subnet]['ELBV2'][elbv2].update({'Subnet Name': mini_name})
                new_report['ELBV2'].append(report[vpc]['Subnets'][subnet]['ELBV2'][elbv2])

    return new_report

def print_subnet(report):
    """
    Print subnets
    """
    new_report = dict()
    for vpc in report:
        new_report[vpc] = dict()
        for subnet in report[vpc]['Subnets']:
            mini_name = report[vpc]['Subnets'][subnet]['Name'].split('-{}'.format(
                report[vpc]['Subnets'][subnet]['AvailabilityZone']))[0]
            if not mini_name in new_report[vpc]:
                new_report[vpc][mini_name] = list()
            for ec2 in report[vpc]['Subnets'][subnet]['EC2']:
                new_report[vpc][mini_name].append(report[vpc]['Subnets'][subnet]['EC2'][ec2])
            for elbv2 in report[vpc]['Subnets'][subnet]['ELBV2']:
                new_report[vpc][mini_name].append(report[vpc]['Subnets'][subnet]['ELBV2'][elbv2])

    LOGGER.warning(json.dumps(new_report, sort_keys=True, indent=4))

def ec2_scan(boto_session, public_only=False):
    """
    SCAN EC2
    """
    ec2_client = boto_session.client('ec2')
    vpcs_raw = ec2_client.describe_vpcs()['Vpcs']
    subnets_raw = ec2_client.describe_subnets()['Subnets']
    nacls_raw = ec2_client.describe_network_acls()['NetworkAcls']
    ec2_raw = ec2_client.describe_instances()['Reservations']
    sg_raw = ec2_client.describe_security_groups()['SecurityGroups']
    eclbv2_client = boto_session.client('elbv2')
    load_balancers_raw = eclbv2_client.describe_load_balancers()['LoadBalancers']

    report = dict()

    for vpc in vpcs_raw:
        report[vpc['VpcId']] = dict()
        report[vpc['VpcId']]['Subnets'] = dict()
        report[vpc['VpcId']]['NetworkAcls'] = dict()

    for subnet in subnets_raw:
        subnet_name = 'Unknown'
        if 'Tags' in subnet:
            subnet_name = get_tag(subnet['Tags'], 'Name')
        report[subnet['VpcId']]['Subnets'][subnet['SubnetId']] = {
            'Name': subnet_name,
            'AvailabilityZone': subnet['AvailabilityZone'],
            'CidrBlock': subnet['CidrBlock']}
        report[subnet['VpcId']]['Subnets'][subnet['SubnetId']]['NetworkAcls'] = dict()
        report[subnet['VpcId']]['Subnets'][subnet['SubnetId']]['EC2'] = dict()
        report[subnet['VpcId']]['Subnets'][subnet['SubnetId']]['ELBV2'] = dict()

    for nacl in nacls_raw:
        if not nacl['Associations']:
            report[nacl['VpcId']]['NetworkAcls'][nacl['NetworkAclId']] = nacl['Entries']
        for nacl_assoc in nacl['Associations']:
            report[nacl['VpcId']]['Subnets'][nacl_assoc['SubnetId']]['NetworkAcls'][nacl['NetworkAclId']] = nacl['Entries']

    for ec2 in ec2_raw:
        for ec2_ in ec2['Instances']:
            if 'VpcId' in ec2_ and 'SubnetId' in ec2_:
                if public_only and not 'PublicIpAddress' in ec2_:
                    continue
                report[ec2_['VpcId']]['Subnets'][ec2_['SubnetId']]['EC2'][ec2_['InstanceId']] = dict()
                if 'Tags' in ec2_:
                    report[ec2_['VpcId']]['Subnets'][ec2_['SubnetId']]['EC2'][ec2_['InstanceId']]['Name'] = get_tag(ec2_['Tags'], 'Name')
                else:
                    report[ec2_['VpcId']]['Subnets'][ec2_['SubnetId']]['EC2'][ec2_['InstanceId']]['Name'] = ec2_['InstanceId']
                if 'PrivateIpAddress' in ec2_:
                    report[ec2_['VpcId']]['Subnets'][ec2_['SubnetId']]['EC2'][ec2_['InstanceId']]['PrivateIpAddress'] = ec2_['PrivateIpAddress']
                if 'PublicIpAddress' in ec2_:
                    report[ec2_['VpcId']]['Subnets'][ec2_['SubnetId']]['EC2'][ec2_['InstanceId']]['PublicIpAddress'] = ec2_['PublicIpAddress']
                if 'SecurityGroups' in ec2_:
                    for sg in ec2_['SecurityGroups']:
                        draw = draw_sg(sg['GroupId'], sg_raw)
                        if not draw:
                            continue
                        report[ec2_['VpcId']]['Subnets'][ec2_['SubnetId']]['EC2'][ec2_['InstanceId']][sg['GroupId']] = draw
                # if 'ImageId' in ec2_:
                #     report[ec2_['VpcId']]['Subnets'][ec2_['SubnetId']]['EC2'][ec2_['InstanceId']]['ImageId'] = ec2_['ImageId']


    for elbv2 in load_balancers_raw:
        if public_only and elbv2['Scheme'] == 'internal':
            continue
        report[elbv2['VpcId']]['Subnets'][elbv2['AvailabilityZones'][0]['SubnetId']]['ELBV2'][elbv2['LoadBalancerName']] = dict()
        report[elbv2['VpcId']]['Subnets'][elbv2['AvailabilityZones'][0]['SubnetId']]['ELBV2'][elbv2['LoadBalancerName']]['Scheme'] = elbv2['Scheme']
        report[elbv2['VpcId']]['Subnets'][elbv2['AvailabilityZones'][0]['SubnetId']]['ELBV2'][elbv2['LoadBalancerName']]['DNSName'] = elbv2['DNSName']
        if 'SecurityGroups' in elbv2:
            for sg in elbv2['SecurityGroups']:
                report[elbv2['VpcId']]['Subnets'][elbv2['AvailabilityZones'][0]['SubnetId']]['ELBV2'][elbv2['LoadBalancerName']][sg] = draw_sg(sg, sg_raw)

    return report
