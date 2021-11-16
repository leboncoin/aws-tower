'''
AWS Tower variables

Copyright 2020-2021 Leboncoin
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

META_TYPES = ['APIGW', 'CLOUDFRONT', 'EC2', 'EKS', 'ELBV2', 'IAM', 'RDS', 'S3']

IAM_ACTION_PASSLIST = ['ec2messages', 'logs', 'ssm', 'ssmmessages', 'support']

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
