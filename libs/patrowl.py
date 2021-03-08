#!/usr/bin/env python
"""
Patrowl library

Copyright 2020-2021 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

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
    except:
        pass
    return None


def get_assets(patrowl_api, assetgroup_id):
    """
    Get assets from AssetGroup
    """
    assets_list = []
    assets = list()
    assetgroup = patrowl_api.get_assetgroup_by_id(assetgroup_id)
    assets += sorted(assetgroup['assets'], key=lambda k: k['id'], reverse=True)
    for asset in assets:
        assets_list.append(asset)

    return assets_list


def add_in_assetgroup(patrowl_api, assetgroup_id, asset_id):
    """
    Add asset in AssetGroup
    """
    new_assets_ids = list()
    new_assets_ids.append(asset_id)

    dst_assetgroup = patrowl_api.get_assetgroup_by_id(assetgroup_id)
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
    except:
        pass

def get_findings(patrowl_api, asset_id):
    """
    Get asset findings
    """
    try:
        return patrowl_api.get_asset_findings_by_id(asset_id)
    except:
        pass
    return list()
