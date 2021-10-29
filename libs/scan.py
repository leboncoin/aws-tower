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

from .asset_type_apigw import APIGW, get_raw_data as APIGW_get_raw_data, parse_raw_data as APIGW_parse_raw_data
from .asset_type_cf import CloudFront, get_raw_data as CF_get_raw_data, parse_raw_data as CF_parse_raw_data
from .asset_type_ec2 import EC2, get_raw_data as EC2_get_raw_data, parse_raw_data as EC2_parse_raw_data
from .asset_type_elbv2 import ELBV2, get_raw_data as ELBV2_get_raw_data, parse_raw_data as ELBV2_parse_raw_data
from .asset_type_iam_group import IAMGroup, parse_raw_data as IAM_parse_raw_data
from .asset_type_rds import RDS, get_raw_data as RDS_get_raw_data, parse_raw_data as RDS_parse_raw_data
from .asset_type_route53 import get_raw_data as R53_get_raw_data, parse_raw_data as R53_parse_raw_data
from .asset_type_s3_group import S3Group, get_raw_data as S3_get_raw_data, parse_raw_data as S3_parse_raw_data

# Debug
# from pdb import set_trace as st

LOGGER = logging.getLogger('aws-tower')

def get_raw_data(boto_session, meta_types, console):
    """
    Returned raw data and authorization failure for logging
    """
    authorizations = {
        'apigw': True,
        'cloudfront': True,
        'ec2': True,
        'elbv2': True,
        'iam': True,
        'rds': True,
        's3': True,
        'route53': True
    }
    raw_data = {}

    raw_data, authorizations = EC2_get_raw_data(
        raw_data,
        authorizations,
        boto_session,
        console)

    if 'APIGW' in meta_types:
        raw_data, authorizations = APIGW_get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            console)

    if 'CLOUDFRONT' in meta_types:
        raw_data, authorizations = CF_get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            console)

    if 'ELBV2' in meta_types:
        raw_data, authorizations = ELBV2_get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            console)

    if 'RDS' in meta_types:
        raw_data, authorizations = RDS_get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            console)

    if 'S3' in meta_types:
        raw_data, authorizations = S3_get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            console)

    if 'EC2' in meta_types or 'ELBV2' in meta_types:
        raw_data, authorizations = R53_get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            console)

    return raw_data, authorizations

def log_authorization_errors(authorizations, console):
    """
    Print authorizations errors during scan
    """
    if not console:
        LOGGER.critical(f'A "False" suggest that something fail, too few authorizations?: {authorizations}')
    else:
        for auth in authorizations:
            if not authorizations[auth]:
                console.print(f'[red]Error scannig [bold]{auth}[/bold], maybe not enough permissions...')

def aws_scan(
    boto_session,
    iam_action_passlist=[],
    iam_rolename_passlist=[],
    public_only=False,
    meta_types=[],
    name_filter='',
    console=None):
    """
    SCAN AWS
    """
    raw_data, authorizations = get_raw_data(boto_session, meta_types, console)

    assets = []

    if 'APIGW' in meta_types:
        assets, authorizations = APIGW_parse_raw_data(
            assets,
            authorizations,
            raw_data,
            public_only,
            boto_session,
            name_filter,
            console)

    if 'CLOUDFRONT' in meta_types:
        assets, authorizations = CF_parse_raw_data(
            assets,
            authorizations,
            raw_data,
            name_filter,
            console)

    if 'EC2' in meta_types:
        assets, authorizations = EC2_parse_raw_data(
            assets,
            authorizations,
            raw_data,
            name_filter,
            boto_session,
            public_only,
            console)

    if 'ELBV2' in meta_types:
        assets, authorizations = ELBV2_parse_raw_data(
            assets,
            authorizations,
            raw_data,
            name_filter,
            public_only,
            console)

    if 'IAM' in meta_types:
        assets, authorizations = IAM_parse_raw_data(
            assets,
            authorizations,
            boto_session,
            iam_action_passlist,
            iam_rolename_passlist,
            name_filter,
            console)

    if 'RDS' in meta_types:
        assets, authorizations = RDS_parse_raw_data(
            assets,
            authorizations,
            raw_data,
            name_filter,
            public_only,
            console)

    if 'S3' in meta_types:
        assets, authorizations = S3_parse_raw_data(
            assets,
            authorizations,
            raw_data,
            name_filter,
            public_only,
            console)

    if 'EC2' in meta_types or 'ELBV2' in meta_types:
        assets, authorizations = R53_parse_raw_data(
            assets,
            authorizations,
            raw_data,
            console)

    log_authorization_errors(authorizations, console)

    return assets
