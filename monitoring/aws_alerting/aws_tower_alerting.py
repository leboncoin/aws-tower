#!/usr/bin/env python
"""
AWS Tower Alerting S3-Slack

Copyright 2023 Nicolas BEGUIER
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas_beguier@hotmail.com)
"""

# Standard library imports
import json
import sys

# Third party library imports
import boto3
from botocore.exceptions import ClientError
sys.path.append('package')
from requests import Session

# Debug
# from pdb import set_trace as st

VERSION = '4.6.0'

SESSION = Session()

s3_client = boto3.client('s3')
BUCKET_NAME = 'aws-tower-findings'
SECRET_NAME = 'security_slack_alerts'
REGION_NAME = 'eu-west-3'
ENV = 'prod'
SLACK_ENV = {
    'dev': {
        'channel': '#security-alerts-test',
        'webhook_key': 'dev_security_alerts_slack_webhook'
    },
    'prod': {
        'channel': '#security-alerts',
        'webhook_key': 'security_alerts_slack_webhook'
    }
}

def get_finding_unique_name(event):
    return f"{event['id']}.json"


def is_valid_event(event):
    if not isinstance(event, dict):
        return False
    if 'id' in event:
        return True
    return False


def get_stored_event(key):
    """
    Returns the event in the AWS S3
    """
    try:
        response = s3_client.get_object(Bucket=BUCKET_NAME, Key=key)
        # Assuming the file contains JSON
        stored_event = json.loads(response['Body'].read().decode('utf-8'))
        return stored_event
    except ClientError:
        return None


def save_event(event):
    """
    Saves the event in the AWS S3
    """
    try:
        key = get_finding_unique_name(event)
        s3_client.put_object(
            Bucket=BUCKET_NAME,
            Key=key,
            Body=json.dumps(event),
            ContentType='application/json'
        )
        return True
    except ClientError as e:
        print(f"Failed to save the event to S3. Error: {e}")
        return False


def update_event(event):
    """
    Updates the object in S3 with the provided content.
    """
    key = get_finding_unique_name(event)
    s3_client.put_object(Bucket=BUCKET_NAME, Key=key, Body=json.dumps(event))


def create_slack_payload(title, description):
    """
    Create a Slack payload with title and description in Markdown format.

    :param title: The title of the message
    :param description: The description/content of the message
    :return: A payload ready to be sent to Slack
    """
    
    return {
        'blocks': [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{title}*"  # Making the title bold using Markdown
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": description  # This is your message content in Markdown
                }
            }
        ]
    }


def post_to_slack(webhook_url, payload, channel=None, username=None, icon_emoji=None):
    """
    Post a message to Slack channel.

    :param webhook_url: The Slack Incoming Webhook URL
    :param message: Message content to be sent to Slack
    :param channel: (Optional) Slack channel to post to.
    :param username: (Optional) Name of the sender.
    :param icon_emoji: (Optional) Emoji icon for the sender.
    :return: True if the message was sent successfully, False otherwise.
    """
    
    if channel:
        payload['channel'] = channel
    if username:
        payload['username'] = username
    if icon_emoji:
        payload['icon_emoji'] = icon_emoji
    
    headers = {
        'Content-Type': 'application/json'
    }
    
    response = SESSION.post(webhook_url, data=json.dumps(payload), headers=headers)
    
    return response.status_code == 200


def get_secret():
    """
    Return secrets
    """
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=REGION_NAME
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=SECRET_NAME
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    # Decrypts secret using the associated KMS key.
    return get_secret_value_response['SecretString']


def main(event):
    """
    Main function
    """
    if not is_valid_event(event):
        sys.exit(0)

    print(event)

    key = get_finding_unique_name(event)
    is_already_seen = get_stored_event(key)
    if is_already_seen:
        print('Event is already in s3. Ignoring event.')
        update_event(event)
    else:
        webhook_url = json.loads(get_secret())[SLACK_ENV[ENV]['webhook_key']]
        severity_logo = {
            'high': ':small_red_triangle:',
            'medium': ':small_orange_diamond:',
            'low': ':small_blue_diamond:'
        }
        description = f'*Description*: {event["title"]}\n*Account name*: {event["account_name"]}, *Region*: {event["region_name"]}'
        if event["asset_name"] not in description:
            description = f'*Description*: {event["title"]} on asset {event["asset_name"]} ({event["asset_type"]})\n*Account name*: {event["account_name"]}, *Region*: {event["region_name"]}'

        payload = create_slack_payload(
            f'{severity_logo[event["severity"]]} {event["severity"].capitalize()} severity alert',
            description)
            
        is_ok = post_to_slack(
            webhook_url,
            payload,
            channel=SLACK_ENV[ENV]['channel'],
            username='AWS Tower',
            icon_emoji=':aws:')
        if is_ok:
            print('Save event in s3')
            save_event(event)


def handler(event, _):
    """
    Specific entrypoint for lambda
    {
      "id": "test123",
      "asset_name": "asset_1",
      "asset_type": "EC2",
      "title": "public IP",
      "severity": "medium",
      "account_name": "my-irish-account",
      "region_name": "eu-west-1"
    }
    """
    main(event)
