#!/usr/bin/env python
"""
Patrowl library

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""
# Standard library imports
import logging
LOGGER = logging.getLogger('aws-tower')


def add_asset(patrowl_api, title, description):
    """
    Create an asset
    """
    try:
        return patrowl_api.add_asset(
            title,
            title,
            'domain',
            description,
            'medium',
            'external',
            tags=['All'])
    except Exception as err_msg:
        LOGGER.critical(f'{err_msg=}')
    return None


def get_assets(patrowl_api, assetgroup_id):
    """
    Get assets from AssetGroup
    """
    assets_list = []
    assets = []
    assetgroup = patrowl_api.get_assetgroup_by_id(assetgroup_id)
    assets += sorted(assetgroup['assets'], key=lambda k: k['id'], reverse=True)
    for asset in assets:
        assets_list.append(asset)

    return assets_list


def add_in_assetgroup(patrowl_api, assetgroup_id, asset_ids):
    """
    Add assets in AssetGroup
    """
    # If no new assets, do nothing
    if not asset_ids:
        return None

    new_assets_ids = asset_ids

    dst_assetgroup = patrowl_api.get_assetgroup_by_id(assetgroup_id)
    if len(dst_assetgroup) == 0:
        LOGGER.critical('Remote assetgroup empty, aborting...')
        return None
    for current_asset in dst_assetgroup['assets']:
        new_assets_ids.append(current_asset['id'])
    patrowl_api.edit_assetgroup(
        assetgroup_id,
        dst_assetgroup['name'],
        dst_assetgroup['description'],
        dst_assetgroup['criticity'],
        new_assets_ids)


def add_finding(patrowl_api, asset_id, title, description, criticity):
    """
    Add finding
    """
    try:
        patrowl_api.add_finding(
            title,
            description,
            'aws_tower',
            criticity,
            asset_id)
    except Exception as err_msg:
        LOGGER.critical(f'{err_msg=}')

def get_findings(patrowl_api, asset_id):
    """
    Get asset findings
    """
    try:
        return patrowl_api.get_asset_findings_by_id(asset_id)
    except Exception as err_msg:
        LOGGER.critical(f'{err_msg=}')
    return None

def update_finding(patrowl_api, finding_id):
    """
    Update the finding 'updated_at'
    """
    try:
        patrowl_api.update_finding(finding_id)
    except Exception as err_msg:
        LOGGER.critical(f'{err_msg=}')
