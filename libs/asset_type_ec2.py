#!/usr/bin/env python
"""
Asset types EC2 class

Copyright 2020-2022 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard imports
from datetime import datetime, timezone

# Third party library imports
import botocore

from .asset_type import AssetType
from .tools import draw_sg, get_tag, get_network, log_me, search_filter_in

# Debug
# from pdb import set_trace as st

class EC2(AssetType):
    """
    EC2 Asset Type
    """
    def __init__(self, name: str, private_ip: str, public: bool=False):
        super().__init__('EC2', name, public=public)
        self.operating_system = 'unknown'
        self.private_ip = private_ip
        self.public_ip = ''
        self.security_groups = {}
        self.dns_record = None
        self.old_attached_ssh_key = False
        self.ssh_key_days = -1
        self.role_poweruser = ''
        self.role_admin = ''
        self.instance_id = ''
        self.eks_cluster = ''

    def report(self, report, brief=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {
                'OS': self.operating_system,
                'PrivateIP': self.private_ip
            }
            if self.public:
                asset_report['PubliclyAccessible'] = '[red]True[/red]'
            if self.public_ip:
                asset_report['PublicIP'] = self.public_ip
            if self.security_groups and not self.security_issues:
                asset_report['SecurityGroups'] = self.security_groups
            if self.dns_record:
                asset_report['DnsRecord'] = self.dns_record
            if self.old_attached_ssh_key:
                asset_report['SSHKey age'] = f'[yellow]{self.ssh_key_days} days[/yellow]'
            if self.role_poweruser:
                asset_report['Roles PowerUser'] = f'[yellow]{self.role_poweruser}[/yellow]'
            if self.role_admin:
                asset_report['Roles Admin'] = f'[red]{self.role_admin}[/red]'
            if self.security_issues:
                self.update_audit_report(asset_report)
        if 'EC2' not in report[self.location.region][self.location.vpc][self.location.subnet]:
            report[self.location.region][self.location.vpc][self.location.subnet]['EC2'] = \
                { self.name: asset_report }
            return report
        report[self.location.region][self.location.vpc][self.location.subnet]['EC2'].update(
            { self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        public = ''
        permissions = ''
        if self.public:
            public = f'[red]<Public>[/red] {self.public_ip} '
        if self.role_admin:
            permissions = ' [red]Admin[/red]'
        elif self.role_poweruser:
            permissions = ' [yellow]PowerUser[/yellow]'
        return f'{public}{self.private_ip}{permissions}{self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        if self.public:
            return f'<Public> {self.public_ip} {self.private_ip}'
        return f'<Private> {self.private_ip}'

    def src_linked_assets(self, assets):
        """
        Among all asset, find assets linked to the EC2 in source
        """
        result = set()
        ec2_sgs = set()
        for _, ec2_sg in self.security_groups.items():
            for _, port_allowed_ips in ec2_sg.items():
                for elb_sg_linked in port_allowed_ips:
                    if elb_sg_linked.startswith('sg-'):
                        ec2_sgs.add(elb_sg_linked)
        if not ec2_sgs:
            return result
        for elb in assets:
            if elb.get_type() != 'ELB':
                continue
            for elb_sg in elb.security_groups.keys():
                if elb_sg in ec2_sgs:
                    result.add(elb)
        return result

    def cluster_name(self):
        """
        Return the name of the belonging cluster
        """
        return self.eks_cluster


@log_me('Getting EC2 raw data...')
def get_raw_data(raw_data, authorizations, boto_session, cache, _):
    """
    Get raw data from boto requests.
    Return any EC2 findings and add a 'False' in authorizations in case of errors
    """
    ec2_client = boto_session.client('ec2')
    try:
        raw_data['ec2_raw'] = cache.get(
            'ec2_describe_instances',
            ec2_client,
            'describe_instances')['Reservations']
    except botocore.exceptions.ClientError:
        raw_data['ec2_raw'] = []
        authorizations['ec2'] = False
    try:
        raw_data['subnets_raw'] = cache.get(
            'ec2_describe_subnets',
            ec2_client,
            'describe_subnets')['Subnets']
    except botocore.exceptions.ClientError:
        raw_data['subnets_raw'] = []
        authorizations['ec2'] = False
        authorizations['elb'] = False
        authorizations['rds'] = False
    try:
        raw_data['sg_raw'] = cache.get(
            'ec2_describe_security_groups',
            ec2_client,
            'describe_security_groups')['SecurityGroups']
    except botocore.exceptions.ClientError:
        raw_data['sg_raw'] = []
        authorizations['ec2'] = False
        authorizations['elb'] = False
    try:
        raw_data['ec2_kp_raw'] = cache.get(
            'ec2_describe_key_pairs',
            ec2_client,
            'describe_key_pairs')['KeyPairs']
    except botocore.exceptions.ClientError:
        raw_data['ec2_kp_raw'] = []
        authorizations['ec2'] = False
    iam_res = boto_session.resource('iam')
    raw_data['ec2_iam_raw'] = {}
    try:
        raw_data['ec2_iam_assoc_raw'] = cache.get(
            'ec2_describe_iam_instance_profile_associations',
            ec2_client,
            'describe_iam_instance_profile_associations')['IamInstanceProfileAssociations']
    except botocore.exceptions.ClientError:
        raw_data['ec2_iam_assoc_raw'] = []
        authorizations['ec2'] = False
    for assoc in raw_data['ec2_iam_assoc_raw']:
        ip_name = assoc['IamInstanceProfile']['Arn'].split('/')[-1]
        try:
            raw_data['ec2_iam_raw'][ip_name] = cache.get_ec2_iam_raw(
                f'iam_InstanceProfile_{ip_name}',
                iam_res,
                ip_name)
        except botocore.exceptions.ClientError:
            raw_data['ec2_iam_raw'][ip_name] = []
            authorizations['ec2'] = False
    return raw_data, authorizations

def scan(ec2, sg_raw, subnets_raw, kp_raw, boto_session, public_only):
    """
    Scan EC2
    """
    if ec2['State']['Name'] != 'running':
        return None
    ec2_res = boto_session.resource('ec2')
    if 'VpcId' not in ec2 or 'SubnetId' not in ec2:
        return None
    if public_only and not 'PublicIpAddress' in ec2:
        return None
    ec2_asset = EC2(
        name=ec2['InstanceId'],
        private_ip=ec2['PrivateIpAddress'],
        public='PublicIpAddress' in ec2)
    ec2_asset.instance_id = ec2['InstanceId']
    region, vpc, subnet = get_network(ec2['SubnetId'], subnets_raw)
    ec2_asset.location.region = region
    ec2_asset.location.vpc = vpc
    ec2_asset.location.subnet = subnet
    if 'ImageId' in ec2:
        try:
            ec2_asset.operating_system = ec2_res.Image(ec2['ImageId']).platform_details
        except:
            pass
    if 'Tags' in ec2:
        ec2_asset.name = get_tag(ec2['Tags'], 'Name')
        eks_cluster_name =  [ i['Key'].split('/')[-1] for i in ec2['Tags'] if i['Key'].startswith('kubernetes.io/cluster/') ]
        if eks_cluster_name:
            ec2_asset.eks_cluster = eks_cluster_name[0]
    if 'PublicIpAddress' in ec2:
        ec2_asset.public_ip = ec2['PublicIpAddress']
    if 'SecurityGroups' in ec2:
        for security_group in ec2['SecurityGroups']:
            draw = draw_sg(security_group['GroupId'], sg_raw)
            if draw:
                ec2_asset.security_groups[security_group['GroupId']] = draw
    if 'KeyName' in ec2:
        for k in kp_raw:
            if k['KeyName'] == ec2['KeyName'] and 'CreateTime' in k:
                ec2_asset.ssh_key_days = (datetime.now(timezone.utc) - k['CreateTime']).days
    ec2_asset.old_attached_ssh_key = ec2_asset.ssh_key_days > 365/2
    return ec2_asset

@log_me('Scanning EC2...')
def parse_raw_data(assets, authorizations, raw_data, name_filter, boto_session, public_only, cache, _):
    """
    Parsing the raw data to extracts assets,
    enrich the assets list and add a 'False' in authorizations in case of errors
    """
    for ec2 in raw_data['ec2_raw']:
        for ec2_ in ec2['Instances']:
            asset = cache.get_asset(f'EC2_{ec2_["InstanceId"]}')
            if asset is None:
                asset = scan(
                    ec2_,
                    raw_data['sg_raw'],
                    raw_data['subnets_raw'],
                    raw_data['ec2_kp_raw'],
                    boto_session,
                    public_only)
                cache.save_asset(f'EC2_{ec2_["InstanceId"]}', asset)
            if search_filter_in(asset, name_filter):
                assets.append(asset)
    return assets, authorizations

@log_me('Scaning EC2 - IAM instance profile')
def parse_iam_instance_profile(assets, authorizations, raw_data, _):
    for ec2 in assets:
        if ec2.get_type() != 'EC2':
            continue
        # Loop on all EC2 <-> IAM instance profile association
        for assoc in raw_data['ec2_iam_assoc_raw']:
            if assoc['InstanceId'] != ec2.instance_id:
                continue
            if not ('IamInstanceProfile' in assoc and 'Arn' in assoc['IamInstanceProfile']):
                continue
            # Get the IAM Instance Profile of the EC2
            ip_name = assoc['IamInstanceProfile']['Arn'].split('/')[-1]
            if ip_name not in raw_data['ec2_iam_raw']:
                continue
            # Get the IAM Group
            iam_group = None
            for asset in assets:
                if asset.get_type() == 'IAM':
                    iam_group = asset
                    break
            # Loop on every IAM role associated to the IAM I.P.
            for role_name in raw_data['ec2_iam_raw'][ip_name]:
                # Loop on all IAM role of the AWS account
                for iam in iam_group.list:
                    if role_name != iam.arn.split('/')[-1]:
                        continue
                    if iam.poweruser_services is not None:
                        if ec2.role_poweruser != '':
                            ec2.role_poweruser = ' '
                        ec2.role_poweruser += f'{role_name}: {iam.poweruser_services}'
                    if iam.admin_services is not None:
                        if ec2.role_admin != '':
                            ec2.role_admin = ' '
                        ec2.role_admin += f'{role_name}: {iam.admin_services}'
    return assets, authorizations
