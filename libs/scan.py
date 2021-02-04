#!/usr/bin/env python
"""
Scan library

Copyright 2020 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""

# Standard library imports
import logging

# Third party library imports
import botocore

# Debug
# from pdb import set_trace as st

VERSION = '2.2.1'

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
        if not public_only:
            report[ec2['VpcId']]['Subnets'][ec2['SubnetId']]['EC2'][ec2['InstanceId']]['PubliclyAccessible'] = 'PublicIpAddress' in ec2
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
    # report[elbv2['VpcId']]['Subnets'][elbv2['AvailabilityZones'][0]['SubnetId']]['ELBV2'][elbv2['LoadBalancerName']]['Scheme'] = elbv2['Scheme']
    report[elbv2['VpcId']]['Subnets'][elbv2['AvailabilityZones'][0]['SubnetId']]['ELBV2'][elbv2['LoadBalancerName']]['DNSName'] = elbv2['DNSName']
    if not public_only:
        report[elbv2['VpcId']]['Subnets'][elbv2['AvailabilityZones'][0]['SubnetId']]['ELBV2'][elbv2['LoadBalancerName']]['PubliclyAccessible'] = elbv2['Scheme'] != 'internal'
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
    if not public_only:
        report[rds['DBSubnetGroup']['VpcId']]['Subnets'][rds['DBSubnetGroup']['Subnets'][0]['SubnetIdentifier']]['RDS'][rds['DBInstanceIdentifier']]['PubliclyAccessible'] = rds['PubliclyAccessible']
    if 'Endpoint' in rds and 'Address' in rds['Endpoint']:
        report[rds['DBSubnetGroup']['VpcId']]['Subnets'][rds['DBSubnetGroup']['Subnets'][0]['SubnetIdentifier']]['RDS'][rds['DBInstanceIdentifier']]['Address'] = rds['Endpoint']['Address']
    return report

def route53_scan(report, record_value, record):
    """
    Scan Route53
    """
    # Look into report
    for vpc in report:
        # In case of a region, not a VPC
        if not 'Subnets' in report[vpc]:
            continue
        for subnet in report[vpc]['Subnets']:
            for ec2 in report[vpc]['Subnets'][subnet]['EC2']:
                value = report[vpc]['Subnets'][subnet]['EC2'][ec2]
                if ('PrivateIpAddress' in value and record_value == value['PrivateIpAddress']) or \
                    ('Name' in value and record_value == value['Name']) or \
                    ('PublicIpAddress' in value and record_value == value['PublicIpAddress']):
                    report[vpc]['Subnets'][subnet]['EC2'][ec2]['DnsRecord'] = record['Name'].replace('\\052', '*')
            for elbv2 in report[vpc]['Subnets'][subnet]['ELBV2']:
                value = report[vpc]['Subnets'][subnet]['ELBV2'][elbv2]
                if ('DNSName' in value and record_value == f'{value["DNSName"]}.'):
                    report[vpc]['Subnets'][subnet]['ELBV2'][elbv2]['DnsRecord'] = record['Name'].replace('\\052', '*')

def s3_scan_concat_permissions(s3_report, acls, permission, right, override=False):
    """
    Scan ACLS for S3 Buckets and appends the right
    """
    map_users_uri = {
        'http://acs.amazonaws.com/groups/global/AllUsers': 'ACL: All Users',
        'http://acs.amazonaws.com/groups/global/AuthenticatedUsers': 'ACL: Any Authenticated Users',
        'http://acs.amazonaws.com/groups/s3/LogDelivery': 'ACL: S3 Log Delivery'
    }
    for grant in acls:
        if isinstance(permission, list) and grant['Permission'] not in permission:
            continue
        if isinstance(permission, str) and grant['Permission'] != permission:
            continue
        if 'URI' in grant['Grantee'] and grant['Grantee']['URI'] in map_users_uri:
            if override or map_users_uri[grant['Grantee']['URI']] not in s3_report:
                s3_report[map_users_uri[grant['Grantee']['URI']]] = right
            else:
                s3_report[map_users_uri[grant['Grantee']['URI']]] = f'{s3_report[map_users_uri[grant["Grantee"]["URI"]]]},{right}'
            if map_users_uri[grant['Grantee']['URI']] in ['ACL: All Users', 'ACL: Any Authenticated Users']:
                s3_report['PubliclyAccessible'] = True
    return s3_report

def s3_scan_acls(s3_report, acls):
    """
    Scan ACLS for S3 Buckets
    """
    s3_report = s3_scan_concat_permissions(s3_report, acls, 'READ', 'LIST')
    s3_report = s3_scan_concat_permissions(s3_report, acls, 'READ_ACP', 'READ')
    s3_report = s3_scan_concat_permissions(s3_report, acls, ['WRITE', 'WRITE_ACP'], 'WRITE')
    s3_report = s3_scan_concat_permissions(
        s3_report,
        acls,
        'FULL_CONTROL',
        'LIST,READ,WRITE',
        override=True)
    return s3_report

def s3_scan(report, s_three, configuration, location, acls, public_only):
    """
    Scan S3 Buckets
    """
    is_private = False
    if configuration is not None:
        is_private = configuration['BlockPublicAcls'] and \
            configuration['IgnorePublicAcls'] and \
            configuration['BlockPublicPolicy'] and \
            configuration['RestrictPublicBuckets']
    if public_only and is_private:
        return report
    if location not in report:
        report[location] = dict()
        report[location]['S3'] = dict()
    report[location]['S3'][s_three] = dict()
    report[location]['S3'][s_three]['Type'] = 'S3'
    report[location]['S3'][s_three]['Name'] = f's3://{s_three}'
    report[location]['S3'][s_three]['URL'] = f'https://{s_three}.s3.{location}.amazonaws.com/'
    # Can be erased in 's3_scan_concat_permissions' function
    report[location]['S3'][s_three]['PubliclyAccessible'] = False
    if configuration is None or not configuration['BlockPublicAcls']:
        report[location]['S3'][s_three]['ACL: BlockPublicAcls'] = False
    if configuration is None or not configuration['IgnorePublicAcls']:
        report[location]['S3'][s_three]['ACL: IgnorePublicAcls'] = False
    if configuration is None or not configuration['BlockPublicPolicy']:
        report[location]['S3'][s_three]['ACL: BlockPublicPolicy'] = False
    if configuration is None or not configuration['RestrictPublicBuckets']:
        report[location]['S3'][s_three]['ACL: RestrictPublicBuckets'] = False
    report[location]['S3'][s_three] = s3_scan_acls(report[location]['S3'][s_three], acls)
    return report

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
        elbv2_client = boto_session.client('elbv2')
        elbv2_raw = elbv2_client.describe_load_balancers()['LoadBalancers']
        for elbv2 in elbv2_raw:
            report = elbv2_scan(report, elbv2, public_only, sg_raw)

    if 'RDS' in meta_types:
        rds_client = boto_session.client('rds')
        rds_raw = rds_client.describe_db_instances()['DBInstances']
        for rds in rds_raw:
            report = rds_scan(report, rds, public_only)

    if 'S3' in meta_types:
        s3_client = boto_session.client('s3')
        s3_list_buckets = s3_client.list_buckets()['Buckets']
        for s_three in s3_list_buckets:
            try:
                public_access_block_configuration = s3_client.get_public_access_block(
                    Bucket=s_three['Name'])['PublicAccessBlockConfiguration']
            except botocore.exceptions.ClientError:
                public_access_block_configuration = None
            location = s3_client.get_bucket_location(Bucket=s_three['Name'])['LocationConstraint']
            acls = s3_client.get_bucket_acl(Bucket=s_three['Name'])['Grants']
            report = s3_scan(
                report,
                s_three['Name'],
                public_access_block_configuration,
                location,
                acls,
                public_only)

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

def compute_report(report):
    """
    Compte report
    region -> vpc -> subnet -> asset_types
           -> asset_types
    """
    new_report = dict()
    for vpc in report:
        if not vpc.startswith('vpc-') or 'Subnets' not in report[vpc]:
            # vpc IS a region in that case
            if vpc not in new_report:
                new_report[vpc] = report[vpc]
            else:
                new_report[vpc] = {**new_report[vpc], **report[vpc]}
        else:
            # Take random subnet in vpc
            subnet = [ i for i in report[vpc]['Subnets']][0]
            region = report[vpc]['Subnets'][subnet]['AvailabilityZone'][:-1]
            if region not in new_report:
                new_report[region] = {vpc: report[vpc]['Subnets']}
            else:
                new_report[region] = {**new_report[region], **{vpc: report[vpc]['Subnets']}}
    return new_report
