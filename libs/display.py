#!/usr/bin/env python
"""
Display library

Copyright 2020-2022 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""

# Standard library imports
import json
import logging

from .patterns import Patterns
from .tools import NoColor, log_me

# Debug
# from pdb import set_trace as st

LOGGER = logging.getLogger('aws-tower')

@log_me('Preparing the report...')
def prepare_report(assets, meta_types, console):
    """
    Generate the inital report according to all assets
    """
    report = {}
    for asset in assets:
        # Attach the console to the asset, for colors
        asset.console = console
        if asset.get_type().upper() not in meta_types:
            continue
        if asset.location.region is None:
            continue
        if asset.location.region not in report:
            report[asset.location.region] = {}
        if asset.location.vpc is None:
            continue
        if asset.location.vpc not in report[asset.location.region]:
            report[asset.location.region][asset.location.vpc] = {}
        if asset.location.subnet is None:
            continue
        if asset.location.subnet not in report[asset.location.region][asset.location.vpc]:
            report[asset.location.region][asset.location.vpc][asset.location.subnet] = {}
    return report

@log_me('Auditing the scan...')
def audit_scan(assets, report, security_config, brief, console):
    """
    Add assets in report and audit them
    """
    if security_config:
        try:
            patterns = Patterns(
                security_config['findings_rules_path'],
                security_config['severity_levels'],
                security_config['min_severity'],
                security_config['max_severity']
            )
        except Exception as err_msg:
            LOGGER.critical(f'[CRITICAL] Auditing the scan: {err_msg}')
            return report
    for asset in assets:
        if security_config:
            asset.audit(patterns)
            if not asset.security_issues:
                continue
            asset.remove_not_vulnerable_members()
        report = asset.report(report, brief=brief)
    return report

def print_report(assets, meta_types, console, brief=False, security_config=None):
    """
    Print subnets
    """
    # Construct Region/VPC/subnet
    report = prepare_report(assets, meta_types, console)

    report = audit_scan(assets, report, security_config, brief, console)

    str_report = json.dumps(report, sort_keys=True, indent=4)

    if console is None:
        console = NoColor()
    console.print(str_report)
    return True

def print_summary(assets, meta_types, console, security_config):
    """
    Print summary
    """
    with console.status('[bold green]Auditing the scan...'):
        new_report = {}
        for asset in assets:
            asset_type = asset.get_type()
            if asset_type not in meta_types:
                continue
            if asset_type not in new_report:
                new_report[asset_type] = {'count': 0, 'public': 0}
            new_report[asset_type]['count'] += 1
            if asset.public:
                new_report[asset_type]['public'] += 1
            if security_config:
                asset.audit(security_config)
            if asset.security_issues:
                for issue in asset.security_issues:
                    if issue['severity'] not in new_report[asset_type]:
                        new_report[asset_type][issue['severity']] = 1
                    else:
                        new_report[asset_type][issue['severity']] += 1
    console.print(json.dumps(new_report, sort_keys=False, indent=4))

def draw_threats(title, assets, csl):
    # Third-party library imports
    from diagrams import Diagram, Cluster
    from diagrams.aws.compute import EC2, EKS
    from diagrams.aws.network import ELB, CloudFront, APIGateway as APIGW, VPC
    from diagrams.aws.database import RDS
    from diagrams.aws.storage import S3
    from diagrams.aws.general import InternetGateway
    from diagrams.aws.management import OrganizationsAccount

    def get_asset_risks(asset):
        report = set()
        if asset.get_type() in ['RDS', 'IAM']:
            return []
        for finding in asset.security_issues:
            if 'risks' not in finding['metadata']:
                continue
            for risk in finding['metadata']['risks']:
                report.add(risk)
        return report

    def get_asset_color(asset):
        color = '🟢'
        if asset.security_issues:
            color = '🟠'
        for finding in asset.security_issues:
            if finding['severity'] == 'high':
                color = '🔴'
        return color

    def tagged_name(asset):
        asset_name = f"\n{asset.name.split('.')[0]}"
        if 'WAN reachable asset' in get_asset_risks(asset):
            asset_name = '🌐 '+asset_name
        if 'Application vulnerability' in get_asset_risks(asset):
            if asset.get_type() != 'CloudFront': # CF are meant to be public
                asset_name = '🤢 '+asset_name
        if 'Powerful asset' in get_asset_risks(asset):
            asset_name = '💪 '+asset_name
        if 'Sensitive asset' in get_asset_risks(asset):
            asset_name = '👑 '+asset_name
        if 'Reconnaissance' in get_asset_risks(asset):
            asset_name = '👀 '+asset_name
        if 'Compromised asset' in get_asset_risks(asset):
            asset_name = '💀 '+asset_name
        if get_asset_color(asset) != '🟢' and 'WAN reachable asset' not in get_asset_risks(asset):
            asset_name = f'{get_asset_color(asset)} {asset_name}'
        if hasattr(asset, 'dns_record') and asset.dns_record:
            asset_name += f'\n{asset.dns_record}'
        return asset_name

    def get_obj(diag_objs, asset):
        # TODO: check le type
        asset_name = asset
        if not isinstance(asset, str):
            asset_name = tagged_name(asset)
        for obj in diag_objs:
            if asset_name == obj.label:
                return obj
        return None

    def is_present(diag_objs, asset):
        return get_obj(diag_objs, asset)

    csl.print('Vulnerable and Interesting assets')
    asset_names = set()
    vuln_assets = set()
    for asset in assets:
        if ('Application vulnerability' in get_asset_risks(asset) or \
            'Powerful asset' in get_asset_risks(asset) or \
            'Sensitive asset' in get_asset_risks(asset)) and \
            asset.name not in asset_names:
            asset_names.add(asset.name)
            vuln_assets.add(asset)
            csl.print(tagged_name(asset).replace('\n', ''))

    edge_attr = {
        "minlen": "5"
    }
    with Diagram(title, direction='LR', edge_attr=edge_attr, outformat="svg"):
        internet = InternetGateway('INTERNET')
        lan = InternetGateway('LAN')

        # Draw objects not in Cluster
        objects = []
        clusters = {}
        for asset in vuln_assets:
            if asset.cluster_name():
                if asset.cluster_name() not in clusters:
                    clusters[asset.cluster_name()] = []
                clusters[asset.cluster_name()].append(asset)
                continue
            if not is_present(objects, asset):
                objects.append(locals()[asset.get_type()](tagged_name(asset)))
            for linked_asset in asset.src_linked_assets(assets):
                if get_asset_color(linked_asset) == '🟢':
                    if not is_present(objects, f'Private {linked_asset.get_type()}'):
                        objects.append(locals()[linked_asset.get_type()](f'Private {linked_asset.get_type()}'))
                elif not is_present(objects, linked_asset):
                    objects.append(locals()[linked_asset.get_type()](tagged_name(linked_asset)))
        # Draw each Cluster
        for cluster_name, cluster_members in clusters.items():
            with Cluster(cluster_name):
                for asset in cluster_members:
                    if not is_present(objects, asset):
                        objects.append(locals()[asset.get_type()](tagged_name(asset)))
                    for linked_asset in asset.src_linked_assets(assets):
                        if get_asset_color(linked_asset) == '🟢':
                            if not is_present(objects, f'Private {linked_asset.get_type()}'):
                                objects.append(locals()[linked_asset.get_type()](f'Private {linked_asset.get_type()}'))
                        elif not is_present(objects, linked_asset):
                            objects.append(locals()[linked_asset.get_type()](tagged_name(linked_asset)))

        # Create link between objects
        links = []
        for asset in vuln_assets:
            if 'WAN reachable asset' in get_asset_risks(asset):
                if (internet, get_obj(objects, asset)) not in links:
                    links.append((internet, get_obj(objects, asset)))
                    internet >> get_obj(objects, asset)
            for linked_asset in asset.src_linked_assets(assets):
                if 'WAN reachable asset' in get_asset_risks(linked_asset):
                    if (internet, get_obj(objects, linked_asset)) not in links:
                        links.append((internet, get_obj(objects, linked_asset)))
                        internet >> get_obj(objects, linked_asset)
                if get_asset_color(linked_asset) == '🟢':
                    if (get_obj(objects, f'Private {linked_asset.get_type()}'), lan) not in links:
                        links.append((get_obj(objects, f'Private {linked_asset.get_type()}'), lan))
                        get_obj(objects, f'Private {linked_asset.get_type()}') << lan
                    if (get_obj(objects, asset), get_obj(objects, f'Private {linked_asset.get_type()}')) not in links:
                        links.append((get_obj(objects, asset), get_obj(objects, f'Private {linked_asset.get_type()}')))
                        get_obj(objects, asset) << get_obj(objects, f'Private {linked_asset.get_type()}')
                else:
                    if (get_obj(objects, linked_asset), get_obj(objects, asset)) not in links:
                        links.append((get_obj(objects, linked_asset), get_obj(objects, asset)))
                        get_obj(objects, linked_asset) >> get_obj(objects, asset)
