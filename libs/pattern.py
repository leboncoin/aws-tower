#!/usr/bin/env python
"""
Pattern library

Copyright 2020 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

VERSION = '1.1.0'

def get_dangerous_pattern(metadata):
    """
    Returns a list of dangerous findings, from hardcoded pattern
    """
    report = list()
    is_sg = False
    for sg_name in metadata:
        if sg_name.startswith('sg-'):
            is_sg = True
            for sg_rule in metadata[sg_name].split():
                if '0.0.0.0/0' in sg_rule:
                    report.append({
                        'title': f'[{sg_name}] Too wide security group: {sg_rule}',
                        'severity': 'high'})
                if '->All' in sg_rule:
                    report.append({
                        'title': f'[{sg_name}] Allow connection to all port from same source',
                        'severity': 'medium'})

    if not is_sg:
        report.append({
            'title': 'No security group present',
            'severity': 'high'})

    return report
