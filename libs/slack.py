#!/usr/bin/env python
"""
Slack library

Copyright 2020 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
import json
import logging

# Debug
# from pdb import set_trace as st

BLACKLIST_KEY = ['Scheme']

COLOR_MAPPING = {
    'info': '#b4c2bf',
    'low': '#4287f5',
    'medium': '#f5a742',
    'high': '#b32b2b',
}

LOGGER = logging.getLogger('aws-tower')

def slack_alert(session, slack, asset, aws, patrowl, criticity='medium', simulate=False):
    """
    Post report on Slack
    """
    payload = dict()
    payload['channel'] = slack['channel']
    payload['link_names'] = 1
    payload['username'] = slack['username']
    payload['icon_emoji'] = slack['icon_emoji']

    attachments = dict()
    attachments['pretext'] = 'Public {} has been found on AWS'.format(asset['type'])
    attachments['fields'] = []
    attachments['color'] = COLOR_MAPPING[criticity]

    attachments['fields'].append({'title': 'AWS Account', 'value': aws['account_name']})
    for key in asset['metadata']:
        if key not in BLACKLIST_KEY:
            attachments['fields'].append({'title': key, 'value': asset['metadata'][key]})
    attachments['fields'].append({'title': 'Patrowl asset link', 'value': '{}/assets/details/{}'.format(patrowl['public_endpoint'], asset['id'])})

    payload['attachments'] = [attachments]

    if simulate:
        LOGGER.warning('#######################')
        LOGGER.warning(attachments['pretext'])
        for item in attachments['fields']:
            LOGGER.warning('# ' + item['title'])
            LOGGER.warning(item['value'])
        LOGGER.warning('#######################')
        return True

    response = session.post(slack['webhook'], data=json.dumps(payload))

    return response.ok
