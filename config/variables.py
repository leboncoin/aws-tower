'''
AWS Tower variables

Copyright 2020-2023 Leboncoin
Licensed under the Apache License
Written by Fabien Martinez <fabien.martinez+github@adevinta.com>
'''
from pathlib import Path

SEVERITY_LEVELS = {
    'info': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
}

ALERTING_SEVERITIES = ['medium', 'high', 'critical']

# Paths
ROOT_PATH = Path(__file__).parent.parent
FINDING_RULES_PATH = ROOT_PATH / 'config' / 'rules.yaml'
SUBNET_ALLOW_LIST_PATH = ROOT_PATH / 'config' / 'subnet_allow_list.txt'
TRUSTED_ACCOUNTS_LIST_PATH = ROOT_PATH / 'config' / 'trusted_accounts_list.txt'

META_TYPES = ['APIGW', 'CLOUDFRONT', 'EC2', 'EKS', 'ELB', 'IAM', 'RDS', 'S3', 'VPC']

IAM_ACTION_PASSLIST = ['autoscaling', 'ec2messages', 'elasticloadbalancing', 'logs', 'ssmmessages', 'support', 'xray']

IAM_ROLENAME_PASSLIST = [
    'AccountManagementRole',
    'admin',
    'awx-baseami-lambda-role',
    'data-lifecycle-manager',
    'ebs-auto-tagging-lambda-role',
    'GovernanceExecutionRole',
    'govrnance-conrad-janitor-role',
    'GSN',
    'GSNRole',
    'lambda-scheduler-start-scheduler-lambda',
    'lambda-scheduler-stop-scheduler-lambda',
    'PayerAccountAccessRole',
    'poweruser',
    'readonly',
    'SchibstedSecurityAuditRole'
]

LAMBDA_SCAN_REGION_LIST = ['eu-west-1', 'eu-west-3']

AWS_ALL_REGION_LIST = [
    'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    'ap-south-1',
    'ap-southeast-1', 'ap-southeast-2',
    'ca-central-1', 'eu-central-1',
    'eu-north-1',
    'eu-west-1', 'eu-west-2', 'eu-west-3',
    'sa-east-1',
    'us-east-1', 'us-east-2',
    'us-west-1', 'us-west-2'
]
