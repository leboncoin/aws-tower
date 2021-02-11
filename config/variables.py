'''
AWS Tower variables

Copyright 2020-2021 Leboncoin
Licensed under the Apache License
Written by Fabien Martinez <fabien.martinez+github@adevinta.com>
'''
from pathlib import Path

VERSION = '1.1.0'

SEVERITY_LEVELS = {
    'info': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
}

MIN_SEVERITY = SEVERITY_LEVELS['info']
MAX_SEVERITY = SEVERITY_LEVELS['critical']

# Paths
ROOT_PATH = Path(__file__).parent.parent
FINDING_RULES_PATH = ROOT_PATH / 'config' / 'rules.json'

META_TYPES = {
    'EC2': {
        'Name': 'Name'
    },
    'ELBV2': {
        'Name': 'DNSName'
    },
    'RDS': {
        'Name': 'Name'
    },
    'S3': {
        'Name': 'Name'
    }
}
