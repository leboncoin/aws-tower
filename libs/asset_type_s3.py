#!/usr/bin/env python
"""
Asset types S3 class

Copyright 2020-2022 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
from dataclasses import dataclass

from .asset_type import AssetType

# Debug
# from pdb import set_trace as st

@dataclass
class S3Acl:
    """
    List of S3 Acls
    """
    block_public_acls: bool = True
    block_public_policy: bool = True
    ignore_public_acls: bool = True
    restrict_public_buckets: bool = True
    all_users_grants: str = ''
    any_authenticated_users_grants: str = ''
    s3_logs_delivery_grants: str = ''

    def add_right(self, user: str, right: str):
        """
        Add a right to the user permission
        """
        current_right = getattr(self, user).split()
        if right in current_right:
            return
        if right == 'LIST':
            new_right = ['LIST']+current_right
        elif right == 'WRITE':
            new_right = current_right+['WRITE']
        elif len(current_right) == 0:
            new_right = ['READ']
        elif current_right[0] == 'LIST':
            new_right = ['LIST', 'READ']
        else:
            new_right = ['READ', 'WRITE']
        setattr(self, user, ' '.join(new_right))
        return


class S3(AssetType):
    """
    S3 Asset Type
    """
    def __init__(self, name: str, url: str):
        super().__init__('S3 bucket', name)
        self.url = url
        self.acls = S3Acl()

    def update_grants(self, grants):
        """
        Updates the S3 ACL Grants
        """
        map_users_uri = {
            'http://acs.amazonaws.com/groups/global/AllUsers':
                'all_users_grants',
            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                'any_authenticated_users_grants',
            'http://acs.amazonaws.com/groups/s3/LogDelivery':
                's3_logs_delivery_grants'
        }
        map_permissions = {
            'READ': 'LIST',
            'READ_ACP': 'READ',
            'WRITE': 'WRITE',
            'WRITE_ACP': 'WRITE',
        }

        for grant in grants:
            if 'URI' not in grant['Grantee'] or grant['Grantee']['URI'] not in map_users_uri:
                continue

            if map_users_uri[grant['Grantee']['URI']] in [
                'any_authenticated_users_grants',
                'all_users_grants'
            ]:
                self.public = True

            if grant['Permission'] == 'FULL_CONTROL':
                self.acls.add_right(map_users_uri[grant['Grantee']['URI']], 'LIST')
                self.acls.add_right(map_users_uri[grant['Grantee']['URI']], 'READ')
                self.acls.add_right(map_users_uri[grant['Grantee']['URI']], 'WRITE')

            if grant['Permission'] not in map_permissions:
                continue

            self.acls.add_right(
                map_users_uri[grant['Grantee']['URI']],
                map_permissions[grant['Permission']])

    def report(self, report, brief=False):
        """
        Add an asset with only relevent informations
        """
        if brief:
            asset_report = self.report_brief()
        else:
            asset_report = {
                'URL': self.url
            }
            if self.public:
                asset_report['PubliclyAccessible'] = '[red]True[/red]'
            if self.security_issues:
                self.update_audit_report(asset_report)
            else:
                if not self.acls.block_public_acls:
                    asset_report['ACL: BlockPublicAcls'] = False
                if not self.acls.block_public_policy:
                    asset_report['ACL: BlockPublicPolicy'] = False
                if not self.acls.ignore_public_acls:
                    asset_report['ACL: IgnorePublicAcls'] = '[yellow]False[/yellow]'
                if not self.acls.restrict_public_buckets:
                    asset_report['ACL: RestrictPublicBuckets'] = False
                if self.acls.all_users_grants:
                    asset_report['ACL: All Users'] = f'[red]{self.acls.all_users_grants}[/red]'
                if self.acls.any_authenticated_users_grants:
                    asset_report['ACL: Any Authenticated Users'] = \
                        f'[red]{self.acls.any_authenticated_users_grants}[/red]'
        if 'S3' not in report[self.location.region]:
            report[self.location.region]['S3'] = { self.name: asset_report }
            return report
        report[self.location.region]['S3'].update({ self.name: asset_report })
        return report

    def report_brief(self):
        """
        Return the report in one line
        """
        important_acls = []
        if self.acls.all_users_grants:
            important_acls.append(f'[red]<ALL {self.acls.all_users_grants}>[/red]')
        if self.acls.any_authenticated_users_grants:
            important_acls.append(f'[red]<AWS Auth {self.acls.any_authenticated_users_grants}>[/red]')
        is_public = ''
        if self.public:
            is_public = '[red]<Public>[/red] '
        return f'{is_public}{self.url} {" ".join(important_acls)}{self.display_brief_audit()}'

    def finding_description(self, _):
        """
        Return a description of the finding
        """
        return self.report_brief()
