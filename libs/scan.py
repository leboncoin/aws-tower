#!/usr/bin/env python
"""
Scan library

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""

# Standard library imports
import logging

# Third party library imports
import botocore

from .asset_type_apigw import APIGW
from .asset_type_cf import CloudFront
from .asset_type_ec2 import EC2
from .asset_type_elbv2 import ELBV2
from .asset_type_iam_group import IAMGroup
from .asset_type_rds import RDS
from .asset_type_s3 import S3
from .asset_type_s3_group import S3Group
from .iam_scan import iam_get_roles

# Debug
# from pdb import set_trace as st

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

def get_network(subnet_id, subnets_raw):
    """
    Get simple name for vpc and subnet
    """
    for _subnet in subnets_raw:
        if _subnet['SubnetId'] == subnet_id:
            region = _subnet['AvailabilityZone'][:-1]
            vpc = _subnet['VpcId']
            subnet = _subnet['SubnetId']
            if tag_name := get_tag(_subnet['Tags'], 'Name'):
                vpc = '-'.join(tag_name.split('-')[:-3])
                subnet = _subnet['AvailabilityZone']
    return region, vpc, subnet

def cloudfront_scan(cf_dist):
    """
    Scan CloudFront
    """
    if not cf_dist['Enabled']:
        return None
    aliases = []
    if 'Aliases' in cf_dist and 'Items' in cf_dist['Aliases']:
        aliases = cf_dist['Aliases']['Items']
    authorization_types = []
    if 'WebACLId' in cf_dist and cf_dist['WebACLId']:
        authorization_types.append('WebACL')
    if 'DefaultCacheBehavior' in cf_dist and \
        'LambdaFunctionAssociations' in cf_dist['DefaultCacheBehavior'] and \
        'Items' in cf_dist['DefaultCacheBehavior']['LambdaFunctionAssociations']:
        for l_edge in cf_dist['DefaultCacheBehavior']['LambdaFunctionAssociations']['Items']:
            # Suppose that an authentication lambda has "auth" in its name...
            if 'auth' in l_edge['LambdaFunctionARN']:
                authorization_types.append('Lambda')
    if not authorization_types:
        authorization_types = ['NONE']
    return CloudFront(
        cf_dist['DomainName'],
        aliases,
        authorization_types,
        public=True)

def ec2_scan(ec2, sg_raw, subnets_raw, public_only):
    """
    Scan EC2
    """
    if 'VpcId' not in ec2 or 'SubnetId' not in ec2:
        return None
    if public_only and not 'PublicIpAddress' in ec2:
        return None
    ec2_asset = EC2(
        name=ec2['InstanceId'],
        private_ip=ec2['PrivateIpAddress'],
        public='PublicIpAddress' in ec2)
    region, vpc, subnet = get_network(ec2['SubnetId'], subnets_raw)
    ec2_asset.location.region = region
    ec2_asset.location.vpc = vpc
    ec2_asset.location.subnet = subnet
    if 'Tags' in ec2:
        ec2_asset.name = get_tag(ec2['Tags'], 'Name')
    if 'PublicIpAddress' in ec2:
        ec2_asset.public_ip = ec2['PublicIpAddress']
    if 'SecurityGroups' in ec2:
        for security_group in ec2['SecurityGroups']:
            draw = draw_sg(security_group['GroupId'], sg_raw)
            if draw:
                ec2_asset.security_groups[security_group['GroupId']] = draw
    return ec2_asset

def elbv2_scan(elbv2, sg_raw, subnets_raw, public_only):
    """
    Scan ELBv2
    """
    if public_only and elbv2['Scheme'] == 'internal':
        return None
    elbv2_asset = ELBV2(
        name=elbv2['DNSName'],
        scheme=elbv2['Scheme'],
        public=elbv2['Scheme'] != 'internal')
    region, vpc, subnet = get_network(elbv2['AvailabilityZones'][0]['SubnetId'], subnets_raw)
    elbv2_asset.location.region = region
    elbv2_asset.location.vpc = vpc
    elbv2_asset.location.subnet = subnet
    if 'SecurityGroups' in elbv2:
        for security_group in elbv2['SecurityGroups']:
            elbv2_asset.security_groups[security_group] = draw_sg(security_group, sg_raw)
    return elbv2_asset

def rds_scan(rds, subnets_raw, public_only):
    """
    Scan RDS
    """
    if public_only and not rds['PubliclyAccessible']:
        return None
    rds_asset = RDS(
        name=rds['DBInstanceIdentifier'],
        engine=f'{rds["Engine"]}=={rds["EngineVersion"]}',
        public=rds['PubliclyAccessible'])
    region, vpc, _ = get_network(
        rds['DBSubnetGroup']['Subnets'][0]['SubnetIdentifier'],
        subnets_raw)
    rds_asset.location.region = region
    rds_asset.location.vpc = vpc
    rds_asset.location.subnet = rds['AvailabilityZone']
    if 'Endpoint' in rds and 'Address' in rds['Endpoint']:
        rds_asset.url = rds['Endpoint']['Address']
    return rds_asset

def route53_scan(assets, record_value, record):
    """
    Scan Route53
    """
    for i, asset in enumerate(assets):
        asset_type = asset.get_type()
        if asset_type == 'EC2' and record_value in (asset.public_ip, asset.private_ip):
            assets[i].dns_record = record['Name'].replace('\\052', '*')
        elif asset_type == 'ELBV2' and record_value == f'{asset.name}.':
            assets[i].dns_record = record['Name'].replace('\\052', '*')
    return assets

def s3_scan(s_three, configuration, region, acls, public_only):
    """
    Scan S3 Buckets
    """
    s3_asset = S3(
        name=f's3://{s_three}',
        url=f'https://{s_three}.s3.{region}.amazonaws.com/')
    if configuration is None or not configuration['BlockPublicAcls']:
        s3_asset.acls.block_public_acls = False
    if configuration is None or not configuration['IgnorePublicAcls']:
        s3_asset.acls.block_public_policy = False
    if configuration is None or not configuration['BlockPublicPolicy']:
        s3_asset.acls.ignore_public_acls = False
    if configuration is None or not configuration['RestrictPublicBuckets']:
        s3_asset.acls.restrict_public_buckets = False
    s3_asset.update_grants(acls)
    s3_asset.location.region = region
    if public_only and not s3_asset.public:
        return None
    return s3_asset

def get_raw_data(boto_session, meta_types):
    """
    Returned raw data and authorization failure for logging
    """
    authorizations = {'apigw': True, 'cloudfront': True, 'ec2': True, 'elbv2': True, 'iam': True, 'rds': True, 's3': True, 'route53': True}
    raw_data = dict()

    ec2_client = boto_session.client('ec2')
    try:
        raw_data['ec2_raw'] = ec2_client.describe_instances()['Reservations']
    except botocore.exceptions.ClientError:
        raw_data['ec2_raw'] = []
        authorizations['ec2'] = False
    try:
        raw_data['subnets_raw'] = ec2_client.describe_subnets()['Subnets']
    except botocore.exceptions.ClientError:
        raw_data['subnets_raw'] = list()
        authorizations['ec2'] = False
        authorizations['elbv2'] = False
        authorizations['rds'] = False
    try:
        raw_data['sg_raw'] = ec2_client.describe_security_groups()['SecurityGroups']
    except botocore.exceptions.ClientError:
        raw_data['sg_raw'] = []
        authorizations['ec2'] = False
        authorizations['elbv2'] = False

    if 'APIGW' in meta_types:
        ag_client = boto_session.client('apigateway')
        try:
            raw_data['ag_raw'] = ag_client.get_rest_apis()['items']
        except botocore.exceptions.ClientError:
            raw_data['ag_raw'] = []
            authorizations['apigw'] = False

        agv2_client = boto_session.client('apigatewayv2')
        raw_data['agv2_client'] = agv2_client
        try:
            raw_data['agv2_raw'] = agv2_client.get_apis()['Items']
        except botocore.exceptions.ClientError:
            raw_data['agv2_raw'] = []
            authorizations['apigw'] = False

    if 'CLOUDFRONT' in meta_types:
        cf_client = boto_session.client('cloudfront')
        try:
            raw_data['cf_raw'] = cf_client.list_distributions()['DistributionList']
        except botocore.exceptions.ClientError:
            raw_data['cf_raw'] = []
            authorizations['cloudfront'] = False

    if 'ELBV2' in meta_types:
        elbv2_client = boto_session.client('elbv2')
        try:
            raw_data['elbv2_raw'] = elbv2_client.describe_load_balancers()['LoadBalancers']
        except botocore.exceptions.ClientError:
            raw_data['elbv2_raw'] = []
            authorizations['elbv2'] = False

    if 'RDS' in meta_types:
        rds_client = boto_session.client('rds')
        try:
            raw_data['rds_raw'] = rds_client.describe_db_instances()['DBInstances']
        except botocore.exceptions.ClientError:
            raw_data['rds_raw'] = []
            authorizations['rds'] = False

    if 'S3' in meta_types:
        s3group = S3Group(name='S3 buckets')
        s3_client = boto_session.client('s3')
        raw_data['s3_client'] = s3_client
        try:
            raw_data['s3_list_buckets'] = s3_client.list_buckets()['Buckets']
        except botocore.exceptions.ClientError:
            raw_data['s3_list_buckets'] = []
            authorizations['s3'] = False

    raw_data['route53_client'] = boto_session.client('route53')

    return raw_data, authorizations

def log_authorization_errors(authorizations):
    """
    Print authorizations errors during scan
    """
    LOGGER.critical(f'A "False" suggest that something fail, too few authorizations?: {authorizations}')

def aws_scan(
    boto_session,
    action_passlist=list(),
    public_only=False,
    meta_types=list(),
    name_filter=''):
    """
    SCAN AWS
    """
    raw_data, authorizations = get_raw_data(boto_session, meta_types)

    assets = list()

    if 'APIGW' in meta_types:
        LOGGER.warning('Scanning API Gateway...')
        for apigw in raw_data['ag_raw']:
            is_public = 'REGIONAL' in apigw['endpointConfiguration']['types']
            if public_only and not is_public:
                continue
            asset = APIGW(
                apigw['name'],
                apigw['id'],
                boto_session.region_name,
                [apigw['apiKeySource']],
                public=is_public)
            if asset is not None and name_filter.lower() in asset.name.lower():
                assets.append(asset)
        for apigw in raw_data['agv2_raw']:
            authorization_types = []
            try:
                for route in raw_data['agv2_client'].get_routes(ApiId=apigw['ApiId'])['Items']:
                    authorization_types.append(route['AuthorizationType'])
            except botocore.exceptions.ClientError:
                authorizations['apigw'] = False
            asset = APIGW(
                apigw['Name'],
                apigw['ApiId'],
                boto_session.region_name,
                authorization_types,
                public=True)
            if asset is not None and name_filter.lower() in asset.name.lower():
                assets.append(asset)

    if 'CLOUDFRONT' in meta_types:
        LOGGER.warning('Scanning Cloudfront...')
        if 'Items' in raw_data['cf_raw']:
            for cf_dist in raw_data['cf_raw']['Items']:
                asset = cloudfront_scan(cf_dist)
                if asset is not None and name_filter.lower() in asset.name.lower():
                    assets.append(asset)

    if 'EC2' in meta_types:
        LOGGER.warning('Scanning EC2...')
        for ec2 in raw_data['ec2_raw']:
            for ec2_ in ec2['Instances']:
                asset = ec2_scan(
                    ec2_,
                    raw_data['sg_raw'],
                    raw_data['subnets_raw'],
                    public_only)
                if asset is not None and name_filter.lower() in asset.name.lower():
                    assets.append(asset)

    if 'ELBV2' in meta_types:
        LOGGER.warning('Scanning ELBv2...')
        for elbv2 in raw_data['elbv2_raw']:
            asset = elbv2_scan(elbv2, raw_data['sg_raw'], raw_data['subnets_raw'], public_only)
            if asset is not None and name_filter.lower() in asset.name.lower():
                assets.append(asset)

    if 'IAM' in meta_types:
        LOGGER.warning('Scanning IAM... (can be long)')
        iamgroup = IAMGroup(name='IAM roles')
        client_iam = boto_session.client('iam')
        resource_iam = boto_session.resource('iam')
        try:
            for role in iam_get_roles(client_iam, resource_iam, action_passlist=action_passlist):
                if name_filter.lower() in role.arn.lower():
                    iamgroup.list.append(role)
        except botocore.exceptions.ClientError:
            authorizations['iam'] = False
        assets.append(iamgroup)

    if 'RDS' in meta_types:
        LOGGER.warning('Scanning RDS...')
        for rds in raw_data['rds_raw']:
            asset = rds_scan(
                rds,
                raw_data['subnets_raw'],
                public_only)
            if asset is not None and name_filter.lower() in asset.name.lower():
                assets.append(asset)

    if 'S3' in meta_types:
        LOGGER.warning('Scanning S3...')
        s3group = S3Group(name='S3 buckets')
        for s_three in raw_data['s3_list_buckets']:
            try:
                public_access_block_configuration = raw_data['s3_client'].get_public_access_block(
                    Bucket=s_three['Name'])['PublicAccessBlockConfiguration']
            except botocore.exceptions.ClientError:
                public_access_block_configuration = None
            region = raw_data['s3_client'].get_bucket_location(Bucket=s_three['Name'])['LocationConstraint']
            acls = raw_data['s3_client'].get_bucket_acl(Bucket=s_three['Name'])['Grants']
            s3bucket = s3_scan(
                s_three['Name'],
                public_access_block_configuration,
                region,
                acls,
                public_only)
            if s3bucket is not None and name_filter.lower() in s3bucket.name.lower():
                s3group.list.append(s3bucket)
        assets.append(s3group)

    try:
        LOGGER.warning('Scanning Route53...')
        for hosted_zone in raw_data['route53_client'].list_hosted_zones()['HostedZones']:
            for record in raw_data['route53_client'].list_resource_record_sets(
                HostedZoneId=hosted_zone['Id'])['ResourceRecordSets']:
                if 'ResourceRecords' in record:
                    for record_ in record['ResourceRecords']:
                        if 'Value' not in record_:
                            continue
                        route53_scan(assets, record_['Value'], record)
                elif 'AliasTarget' in record:
                    route53_scan(assets, record['AliasTarget']['DNSName'], record)
    except botocore.exceptions.ClientError:
        authorizations['route53'] = False

    log_authorization_errors(authorizations)

    return assets
