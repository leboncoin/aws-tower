#!/usr/bin/env python
"""
Scan library

Copyright 2020 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""

# Standard library imports
import json
import logging

from .patterns import Patterns

# Debug
# from pdb import set_trace as st

VERSION = '2.0.0'

LOGGER = logging.getLogger('aws-tower')

def get_tag(tags, key):
    """ Returns a specific value in aws tags, from specified key
    """
    names = [item['Value'] for item in tags if item['Key'] == key]
    if not names:
        return ''
    return names[0]

def draw_sg(security_group, sg_raw):
    """ Returns a full definition of security groups
    """
    result = dict()
    for _sg in sg_raw:
        if _sg['GroupId'] == security_group:
            for ip_perm in _sg['IpPermissions']:
                if ip_perm['IpProtocol'] in ['tcp', '-1']:
                    if ip_perm['IpProtocol'] == '-1':
                        if 'all' not in result:
                            result['all'] = list()
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
                            result[key_ports] = list()
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

def parse_report(report, meta_types):
    """
    Return anomalies from report
    """
    new_report = dict()
    for asset_type in meta_types:
        new_report[asset_type] = list()

    for vpc in report:
        for subnet in report[vpc]['Subnets']:
            mini_name = report[vpc]['Subnets'][subnet]['Name'].split(f'-{report[vpc]["Subnets"][subnet]["AvailabilityZone"]}')[0]
            for asset_type in report[vpc]['Subnets'][subnet]:
                if asset_type not in meta_types:
                    continue
                for asset in report[vpc]['Subnets'][subnet][asset_type]:
                    report[vpc]['Subnets'][subnet][asset_type][asset].update(
                        {'Subnet Name': mini_name})
                    new_report[asset_type].append(report[vpc]['Subnets'][subnet][asset_type][asset])

    return new_report

def remove_key_from_report(report, del_key, is_startswith=False):
    """
    Remove key from report
    """
    key_to_delete = list()
    for key in report:
        if is_startswith and key.startswith(del_key):
            key_to_delete.append(key)
        elif key == del_key:
            key_to_delete.append(key)
    for key in key_to_delete:
        del report[key]
    return report

def scan_mode(asset_report, asset_data, asset_name, asset_type, security, brief=False):
    """
    This functions is returning an asset_report with security findings,
    it handles the brief mode output
    """
    try:
        patterns = Patterns(
            security['findings_rules_path'],
            security['severity_levels'],
            security['min_severity'],
            security['max_severity']
        )
    except Exception as err_msg:
        LOGGER.critical(err_msg)
        return []
    security_issues = patterns.extract_findings(asset_data)
    if not security_issues:
        return []
    asset_report['SecurityIssues'] = security_issues
    if brief:
        asset_report = dict()
        asset_report[f'{asset_type}: {asset_name}'] = \
            [f['severity']+": "+f['title'] for f in security_issues]
    return asset_report

def discover_mode(asset_report, asset_name, asset_type, brief=False):
    """
    This functions handles the brief mode output for discovery mode
    """
    if brief:
        return f'{asset_type}: {asset_name}'
    return asset_report

def update_report(report, asset_report, asset_type, brief=False, verbose=False):
    """
    This functions updates the current report by the given asset_report,
    it handles the brief and verbose output
    """
    # Keep SecurityGroups only in verbose mode
    if not verbose and 'SecurityGroups' in asset_report:
        del asset_report['SecurityGroups']
    if brief:
        report.append(asset_report)
    else:
        # Put the asset_type between Subnet and Asset
        if asset_type not in report:
            report[asset_type] = list()
        if 'Type' in asset_report:
            del asset_report['Type']
        report[asset_type].append(asset_report)
    return report

def print_subnet(report, meta_types, brief=False, verbose=False, security=None):
    """
    Print subnets
    """
    new_report = dict()
    for vpc in report:
        new_report[vpc] = dict()
        for subnet in report[vpc]['Subnets']:
            mini_name = report[vpc]['Subnets'][subnet]['Name'].split(
                f'-{report[vpc]["Subnets"][subnet]["AvailabilityZone"]}')[0]
            if not mini_name in new_report[vpc]:
                if brief:
                    new_report[vpc][mini_name] = list()
                else:
                    new_report[vpc][mini_name] = dict()

            for asset_type in report[vpc]['Subnets'][subnet]:
                if asset_type not in meta_types:
                    continue
                for asset in report[vpc]['Subnets'][subnet][asset_type]:
                    asset_report = report[vpc]['Subnets'][subnet][asset_type][asset]

                    if security:
                        asset_report = scan_mode(
                            asset_report,
                            report[vpc]['Subnets'][subnet][asset_type][asset],
                            asset_report[meta_types[asset_type]['Name']],
                            asset_type,
                            security,
                            brief=brief)
                        if not asset_report:
                            continue
                    else:
                        asset_report = discover_mode(
                            asset_report,
                            asset_report[meta_types[asset_type]['Name']],
                            asset_type,
                            brief=brief)

                    # Update the new report
                    new_report[vpc][mini_name] = update_report(
                        new_report[vpc][mini_name],
                        asset_report,
                        asset_type,
                        brief=brief,
                        verbose=verbose)

            # Remove empty Subnet if brief mode
            if brief and not new_report[vpc][mini_name]:
                del new_report[vpc][mini_name]
        # Remove empty VPC if brief mode
        if brief and not new_report[vpc]:
            del new_report[vpc]

    LOGGER.warning(json.dumps(new_report, sort_keys=True, indent=4))
    return True

def ec2_scan(report, ec2, public_only, sg_raw):
    """
    Scan EC2
    """
    if 'VpcId' in ec2 and 'SubnetId' in ec2:
        if public_only and not 'PublicIpAddress' in ec2:
            return report
        report[ec2['VpcId']]['Subnets'][ec2['SubnetId']]['EC2'][ec2['InstanceId']] = dict()
        report[ec2['VpcId']]['Subnets'][ec2['SubnetId']]['EC2'][ec2['InstanceId']]['Type'] = 'EC2'
        if 'Tags' in ec2:
            report[ec2['VpcId']]['Subnets'][ec2['SubnetId']]['EC2'][ec2['InstanceId']]['Name'] = get_tag(ec2['Tags'], 'Name')
        else:
            report[ec2['VpcId']]['Subnets'][ec2['SubnetId']]['EC2'][ec2['InstanceId']]['Name'] = ec2['InstanceId']
        if 'PrivateIpAddress' in ec2:
            report[ec2['VpcId']]['Subnets'][ec2['SubnetId']]['EC2'][ec2['InstanceId']]['PrivateIpAddress'] = ec2['PrivateIpAddress']
        if 'PublicIpAddress' in ec2:
            report[ec2['VpcId']]['Subnets'][ec2['SubnetId']]['EC2'][ec2['InstanceId']]['PublicIpAddress'] = ec2['PublicIpAddress']
        if 'SecurityGroups' in ec2:
            report[ec2['VpcId']]['Subnets'][ec2['SubnetId']]['EC2'][ec2['InstanceId']]['SecurityGroups'] = dict()
            for security_group in ec2['SecurityGroups']:
                draw = draw_sg(security_group['GroupId'], sg_raw)
                if draw:
                    report[ec2['VpcId']]['Subnets'][ec2['SubnetId']]['EC2'][ec2['InstanceId']]['SecurityGroups'][security_group['GroupId']] = draw
        # if 'ImageId' in ec2:
        #     report[ec2['VpcId']]['Subnets'][ec2['SubnetId']]['EC2'][ec2['InstanceId']]['ImageId'] = ec2['ImageId']
    return report

def elbv2_scan(report, elbv2, public_only, sg_raw):
    """
    Scan ELBv2
    """
    if public_only and elbv2['Scheme'] == 'internal':
        return report
    report[elbv2['VpcId']]['Subnets'][elbv2['AvailabilityZones'][0]['SubnetId']]['ELBV2'][elbv2['LoadBalancerName']] = dict()
    report[elbv2['VpcId']]['Subnets'][elbv2['AvailabilityZones'][0]['SubnetId']]['ELBV2'][elbv2['LoadBalancerName']]['Type'] = 'ELBV2'
    report[elbv2['VpcId']]['Subnets'][elbv2['AvailabilityZones'][0]['SubnetId']]['ELBV2'][elbv2['LoadBalancerName']]['Scheme'] = elbv2['Scheme']
    report[elbv2['VpcId']]['Subnets'][elbv2['AvailabilityZones'][0]['SubnetId']]['ELBV2'][elbv2['LoadBalancerName']]['DNSName'] = elbv2['DNSName']
    if 'SecurityGroups' in elbv2:
        report[elbv2['VpcId']]['Subnets'][elbv2['AvailabilityZones'][0]['SubnetId']]['ELBV2'][elbv2['LoadBalancerName']]['SecurityGroups'] = dict()
        for security_group in elbv2['SecurityGroups']:
            report[elbv2['VpcId']]['Subnets'][elbv2['AvailabilityZones'][0]['SubnetId']]['ELBV2'][elbv2['LoadBalancerName']]['SecurityGroups'][security_group] = draw_sg(security_group, sg_raw)
    return report

def rds_scan(report, rds, public_only):
    """
    Scan RDS
    """
    if public_only and not rds['PubliclyAccessible']:
        return report
    report[rds['DBSubnetGroup']['VpcId']]['Subnets'][rds['DBSubnetGroup']['Subnets'][0]['SubnetIdentifier']]['RDS'][rds['DBInstanceIdentifier']] = dict()
    report[rds['DBSubnetGroup']['VpcId']]['Subnets'][rds['DBSubnetGroup']['Subnets'][0]['SubnetIdentifier']]['RDS'][rds['DBInstanceIdentifier']]['Type'] = 'RDS'
    report[rds['DBSubnetGroup']['VpcId']]['Subnets'][rds['DBSubnetGroup']['Subnets'][0]['SubnetIdentifier']]['RDS'][rds['DBInstanceIdentifier']]['Name'] = rds['DBInstanceIdentifier']
    report[rds['DBSubnetGroup']['VpcId']]['Subnets'][rds['DBSubnetGroup']['Subnets'][0]['SubnetIdentifier']]['RDS'][rds['DBInstanceIdentifier']]['Engine'] = f'{rds["Engine"]}=={rds["EngineVersion"]}'
    if 'Endpoint' in rds and 'Address' in rds['Endpoint']:
        report[rds['DBSubnetGroup']['VpcId']]['Subnets'][rds['DBSubnetGroup']['Subnets'][0]['SubnetIdentifier']]['RDS'][rds['DBInstanceIdentifier']]['Address'] = rds['Endpoint']['Address']
    return report

def route53_scan(report, record_value, record):
    """
    Scan Route53
    """
    # Look into report
    for vpc in report:
        for subnet in report[vpc]['Subnets']:
            for ec2 in report[vpc]['Subnets'][subnet]['EC2']:
                value = report[vpc]['Subnets'][subnet]['EC2'][ec2]
                if ('PrivateIpAddress' in value and record_value == value['PrivateIpAddress']) or \
                    ('Name' in value and record_value == value['Name']) or \
                    ('PublicIpAddress' in value and record_value == value['PublicIpAddress']):
                    report[vpc]['Subnets'][subnet]['EC2'][ec2]['DnsRecord'] = record['Name']
            for elbv2 in report[vpc]['Subnets'][subnet]['ELBV2']:
                value = report[vpc]['Subnets'][subnet]['ELBV2'][elbv2]
                if ('DNSName' in value and record_value == f'{value["DNSName"]}.'):
                    report[vpc]['Subnets'][subnet]['ELBV2'][elbv2]['DnsRecord'] = record['Name']

def aws_scan(
    boto_session,
    public_only=False,
    meta_types=list()):
    """
    SCAN AWS
    """
    ec2_client = boto_session.client('ec2')
    vpcs_raw = ec2_client.describe_vpcs()['Vpcs']
    subnets_raw = ec2_client.describe_subnets()['Subnets']
    nacls_raw = ec2_client.describe_network_acls()['NetworkAcls']
    ec2_raw = ec2_client.describe_instances()['Reservations']
    sg_raw = ec2_client.describe_security_groups()['SecurityGroups']
    elbv2_client = boto_session.client('elbv2')
    elbv2_raw = elbv2_client.describe_load_balancers()['LoadBalancers']
    rds_client = boto_session.client('rds')
    rds_raw = rds_client.describe_db_instances()['DBInstances']
    route53_client = boto_session.client('route53')

    report = dict()

    for vpc in vpcs_raw:
        report[vpc['VpcId']] = dict()
        report[vpc['VpcId']]['Subnets'] = dict()
        report[vpc['VpcId']]['NetworkAcls'] = dict()

    for subnet in subnets_raw:
        subnet_name = subnet['SubnetId']
        if 'Tags' in subnet:
            subnet_name = get_tag(subnet['Tags'], 'Name')
        report[subnet['VpcId']]['Subnets'][subnet['SubnetId']] = {
            'Name': subnet_name,
            'AvailabilityZone': subnet['AvailabilityZone'],
            'CidrBlock': subnet['CidrBlock']}
        report[subnet['VpcId']]['Subnets'][subnet['SubnetId']]['NetworkAcls'] = dict()
        report[subnet['VpcId']]['Subnets'][subnet['SubnetId']]['EC2'] = dict()
        report[subnet['VpcId']]['Subnets'][subnet['SubnetId']]['ELBV2'] = dict()
        report[subnet['VpcId']]['Subnets'][subnet['SubnetId']]['RDS'] = dict()

    for nacl in nacls_raw:
        if not nacl['Associations']:
            report[nacl['VpcId']]['NetworkAcls'][nacl['NetworkAclId']] = nacl['Entries']
        for nacl_assoc in nacl['Associations']:
            report[nacl['VpcId']]['Subnets'][nacl_assoc['SubnetId']]['NetworkAcls'][nacl['NetworkAclId']] = nacl['Entries']

    if 'EC2' in meta_types:
        for ec2 in ec2_raw:
            for ec2_ in ec2['Instances']:
                report = ec2_scan(report, ec2_, public_only, sg_raw)

    if 'ELBV2' in meta_types:
        for elbv2 in elbv2_raw:
            report = elbv2_scan(report, elbv2, public_only, sg_raw)

    if 'RDS' in meta_types:
        for rds in rds_raw:
            report = rds_scan(report, rds, public_only)

    for hosted_zone in route53_client.list_hosted_zones()['HostedZones']:
        for record in route53_client.list_resource_record_sets(HostedZoneId=hosted_zone['Id'])['ResourceRecordSets']:
            if 'ResourceRecords' in record:
                for record_ in record['ResourceRecords']:
                    if 'Value' not in record_:
                        continue
                    route53_scan(report, record_['Value'], record)
            elif 'AliasTarget' in record:
                route53_scan(report, record['AliasTarget']['DNSName'], record)
    return report
