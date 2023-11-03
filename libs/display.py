#!/usr/bin/env python
"""
Display library

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
"""

# Standard library imports
import json
import logging
from pathlib import Path
import re

from config import variables
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
def audit_scan(assets, report, security_config, brief, with_fpkey, console):
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
            asset.remove_false_positives()
        if security_config and not asset.security_issues:
            continue
        report = asset.report(report, brief=brief, with_fpkey=with_fpkey)
    return report

def print_report(assets, meta_types, console, output_file, brief=False, with_fpkey=False, security_config=None):
    """
    Print subnets
    """
    # Construct Region/VPC/subnet
    report = prepare_report(assets, meta_types, console)

    report = audit_scan(assets, report, security_config, brief, with_fpkey, console)

    str_report = json.dumps(report, sort_keys=True, indent=4)

    if console is None:
        console = NoColor()
    if output_file:
        Path(output_file).write_text(str_report, encoding='utf-8')
        console.print(f'Output printed in {output_file}.')
    else:
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

def clean_dot_name(vpc_name, vpc_region):
    """
    Return a valid dot name
    """
    trusted_accounts_list_path = variables.TRUSTED_ACCOUNTS_LIST_PATH
    trusted_accounts_list = []
    if trusted_accounts_list_path.exists():
        trusted_accounts_list = trusted_accounts_list_path.read_text(
            encoding='ascii', errors='ignore').split('\n')

    for trust_account in trusted_accounts_list:
        if trust_account.startswith(f'{vpc_name}:'):
            name = trust_account.split(':')[1]

    if re.search('^[0-9]', name):
        name = '_' + name
    return (name+'_'+vpc_region).replace('-', '_').replace(' ', '_').replace(':', '_')

def draw_vpc_peering(assets, dot_filename, args):
    """
    Returns a dot file representing the VPC peering link.
    """
    dot_path = Path(dot_filename).open('w', encoding='utf-8')
    dot_path.write('graph {\n')
    for vpc in assets:
        if not vpc.is_peering:
            continue
        dot_path.write(f'{clean_dot_name(vpc.src_account_id, vpc.src_region_id)} -- {clean_dot_name(vpc.dst_account_id, vpc.dst_region_id)};\n')
    dot_path.write('}\n')

def draw_threats(title, assets, csl, args):
    # Diagrams imports
    from diagrams import Diagram, Cluster
    from diagrams.aws.compute import EC2, EKS, LambdaFunction as Lambda, Lightsail as LIGHTSAIL
    from diagrams.aws.network import ELB, CloudFront, APIGateway as APIGW, VPC
    from diagrams.aws.database import RDS
    from diagrams.aws.storage import S3
    from diagrams.aws.general import InternetGateway
    from diagrams.aws.management import OrganizationsAccount
    from diagrams.aws.integration import MQ

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
        # Ignore low
        if asset.security_issues:
            color = '🟢'
        for finding in asset.security_issues:
            if finding['severity'] == 'medium':
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

    # Generate "Vulnerable Assets", the base of the construction
    if args.limit:
        csl.print('Restrict to only interesting assets among vulnerable')
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
    elif args.all:
        csl.print('All assets, without lonely nodes')
        asset_names = set()
        vuln_assets = set()
        for asset in assets:
            if asset.get_type() in ['ELB', 'EC2', 'APIGW', 'CF'] and asset.name not in asset_names:
                asset_names.add(asset.name)
                vuln_assets.add(asset)
                csl.print(tagged_name(asset).replace('\n', ''))
    else:
        csl.print('All vulnerable assets')
        asset_names = set()
        vuln_assets = set()
        for asset in assets:
            if get_asset_risks(asset) and asset.name not in asset_names:
                asset_names.add(asset.name)
                vuln_assets.add(asset)
                csl.print(tagged_name(asset).replace('\n', ''))

    # Generate links between all assets
    links_lr = set()
    links_rl = set()
    for asset in vuln_assets:
        # internet >> public vulnerable asset
        if 'WAN reachable asset' in get_asset_risks(asset):
            links_lr.add(('INTERNET', asset))
        for linked_asset in asset.src_linked_assets(assets):
            if linked_asset.public:
                links_lr.add(('INTERNET', linked_asset))
                # linked asset >> asset
                links_lr.add((linked_asset, asset))
            else:
                links_rl.add((linked_asset, 'LAN'))
                # asset << linked asset
                links_rl.add((asset, linked_asset))
        for linked_asset in asset.dst_linked_assets(assets):
            if asset.public:
                links_lr.add(('INTERNET', asset))
                # asset >> linked_asset
                links_lr.add((asset, linked_asset))
            else:
                links_rl.add((asset, 'LAN'))
                # linked_asset << asset
                links_rl.add((linked_asset, asset))

    # Remove assets without any links
    to_remove = []
    for i in vuln_assets:
        asset_is_present = False
        for link in links_lr:
            asset_is_present = asset_is_present or i in link
        for link in links_rl:
            asset_is_present = asset_is_present or i in link
        if not asset_is_present:
            to_remove.append(i)
    for asset in to_remove:
        csl.print(f'Removing asset: {asset.name}')
        vuln_assets.remove(asset)

    edge_attr = {
        'minlen': '5'
    }
    with Diagram(title, direction='LR', edge_attr=edge_attr):
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
                if not is_present(objects, linked_asset):
                    objects.append(locals()[linked_asset.get_type()](tagged_name(linked_asset)))
            for linked_asset in asset.dst_linked_assets(assets):
                if not is_present(objects, linked_asset):
                    objects.append(locals()[linked_asset.get_type()](tagged_name(linked_asset)))
        # Draw each Cluster
        for cluster_name, cluster_members in clusters.items():
            with Cluster(cluster_name):
                for asset in cluster_members:
                    if not is_present(objects, asset):
                        objects.append(locals()[asset.get_type()](tagged_name(asset)))
                    for linked_asset in asset.src_linked_assets(assets):
                        if not is_present(objects, linked_asset):
                            objects.append(locals()[linked_asset.get_type()](tagged_name(linked_asset)))
                    for linked_asset in asset.dst_linked_assets(assets):
                        if not is_present(objects, linked_asset):
                            objects.append(locals()[linked_asset.get_type()](tagged_name(linked_asset)))

        # Create link between objects
        objects.append(internet)
        objects.append(lan)
        for link in links_lr:
            if get_obj(objects, link[0]) and get_obj(objects, link[1]):
                get_obj(objects, link[0]) >> get_obj(objects, link[1])
        for link in links_rl:
            if get_obj(objects, link[0]) and get_obj(objects, link[1]):
                get_obj(objects, link[0]) << get_obj(objects, link[1])
