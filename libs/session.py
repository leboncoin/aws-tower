#!/usr/bin/env python
"""
Session library

Copyright 2020 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Third party library imports
import boto3

PIVOTAL_ROLE = 'arn:aws:iam::xxxxxxxxxx:role/AWS-Tower'

def get_session(account_id):
    """
    Returns a session for the specified accountId
    """
    sts_connection = boto3.client('sts')
    acct_a = sts_connection.assume_role(
        RoleArn=PIVOTAL_ROLE,
        RoleSessionName='AWS-Tower'
    )

    access_key = acct_a['Credentials']['AccessKeyId']
    secret_key = acct_a['Credentials']['SecretAccessKey']
    session_token = acct_a['Credentials']['SessionToken']

    sts_connection_2 = boto3.client(
        'sts',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
    )

    acct_b = sts_connection_2.assume_role(
        RoleArn='arn:aws:iam::{}:role/readonly'.format(account_id),
        RoleSessionName='Readonly'
    )

    access_key = acct_b['Credentials']['AccessKeyId']
    secret_key = acct_b['Credentials']['SecretAccessKey']
    session_token = acct_b['Credentials']['SessionToken']

    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
    )
    return session
