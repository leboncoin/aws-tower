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

META_TYPES = ['EC2', 'ELBV2', 'IAM', 'RDS', 'S3']

ACTION_PASSLIST = ['ec2messages', 'logs', 'ssm', 'ssmmessages']
