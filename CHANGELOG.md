CHANGELOG
=========

AWS-TOWER
-----

4.6.0
-----

2024/03/06

### New feature
  - Add IAM user scan/audit, add 'global' region for lambda montoring
  - [Lambda] Add remove_false_positives function in aws_tower_auditor
  - Display domain name in API Gateway if exists

### Updates
  - update RDS version rules

### Fixtures
  - Fix VPC bug
  - Fix AWS S3 public bucket detection
  - Fix audit rule 'old_access_keys'

4.5.0
-----

2023/11/03

### New feature
  - Add 'LIGHTSAIL' asset type
  - Add `--false-positive-key` in audit mode
  - Add `config/false_positives_list.txt` file, list of finding keys to ignore in audit report
  - Add lambda monitoring and documentation

### Fixtures
  - Audit: Consider ports 0-65535 as "all"

4.4.5
-----
2023/07/28

### Fixtures
  - Small fix in API Gateway

4.4.4
-----

2023/03/10

### New feature
  - Add `--vpc-peering-dot` to save vpc peering in a dot file

4.4.3
-----

2023/03/10

### New feature
  - Display EC2 OS info and improve filter
  - Pattern: add rule has_attribute_contain*
  - Add `--only-dangerous-actions` for iam verb

### Fixtures
  - Fix `--layer` and add Usage in README


4.4.2
-----

2023/01/26

### New feature
  - Add 'os' filter
  - Add 'MQ' asset type

### Changes
  - Display InstanceID for EC2
  - Filter IAM roles to display only Instance Profiles

4.4.1
-----

2023/01/10

### New feature
  - Add Lambda object, displayed in draw for API Gateway
  - Add `-o|--output` to save JSON audit and discovery in the specified file

4.4.0
-----

2023/01/06

### New feature
  - Add `--limit` and `--all` for draw

### Changes
  - Add Public ELB rule

4.3.0
-----

2022/09/08

### New feature
  - Add `draw` verb : `aws-tower draw <my-profile>` to display a threat map

### Changes
  - Dissociate IAM services and actions, easier to read and understand findings
  - whitelist more IAM actions as readers and not poweruser
  - Add more retryier in lambda monitoring and split in another lambda child
  - Update deprecated RDS/EKS engine in rules

### Fixtures
  - Fix iam_scan to use min-rights

4.2.2
-----

2022/08/24

### New feature
  - Add 'Endpoint Service has untrusted account in principals' rule
  - Add option `-p|--list-profiles` to list available profiles

### Changes
  - Detect SSH keys issues if creation time > 6 months
  - Remove `-n|--name` option

### Fixtures
  - Handle boto3 errors with pretty output (sso and more)

4.2.1
-----

2022/06/22

### New feature
  - Add 'Public RDS database' rule
  - [BETA] Add `-l|--layer` to generate a layer for the ATT&CK navigator

4.2.0
------

2022/06/18

### New feature
  - Improve filtering: add option `-f|--filter` (see README)

### Changes
  - Deprecate of `-n|--name`, use `-f|--filter` instead

### Fixtures
  - Disabled cloudfront no longer appear in result


4.1.0
------

2022/04/21

### New feature
  - Add VPC Peering
  - Add VPC Endpoint services
  - Add VPC VPN
  - Add multiple dangerous actions

### Changes
  - Lower severity for S3 IgnorePublicACLs `medium -> low`

### Fixtures
  - Fix missing asset_id in lambda monitoring
  - Factorize Pattern compilation for audit

4.0.1
------

2022/02/28

### Changes
  - Move lambda code to `monitoring/aws_lambda/` directory

4.0.0
------

2021/12/09

### New feature
  - Rich color for the CLI and `--no-color` argument
  - Add EKS
  - Add RDS version alerting: mariadb, postgres, mysql, sqlserver-se (mssql)
  - lambda: Update finding 'updated_at', in Patrowl, at each iteration
  - lambda: Scan multiple regions
  - Add EC2 associated roles, if at least EC2 and IAM are selected
  - Add cache \o/ (`--no-cache` and `--clean-cache` too)
  - Add IAM 'dangerous roles' detection

### Changes
  - Remove not vuln members in assetgroup (IAM and S3)
  - DnsRecord severity changes from medium to low
  - Remove 'support' IAM permission by default
  - Rename ELBV2 to ELB

### Fixture
  - Avoid crash if sts get caller identity fails
  - Avoid crash if S3 Acls and permissions fails
  - Avoid crash if Route53 permissions fails
  - Don't scan Route53 if it's EC2 or ELB are not selected
  - Avoid crash when 'Resource' is not present in RolePolicy (NotResource is ignored)

3.11.0
-----

2021/10/04

### New feature
  - Add IAM_ROLENAME_PASSLIST to reduce noise
  - Lambda: Can limite meta-type check for each account

3.10.1
-----

2021/10/04

### Fixture
  - Fix unknown region/vpc/subnet if token lacks permissions

3.10.0
-----

2021/09/28

### New feature
  - Display errors if user with few authorizations
  - Add welcome logging

3.9.0
-----

2021/05/28

### New feature
  - Add API GATEWAY monitoring
  - Add CloudFront monitoring

### Changes
  - [Lambda] Add in assetgroup in the laucher directly, before starting every sub lambdas

3.8.0
-----

2021/05/26

### New feature
  - Add region for lambda profile configuration

3.7.0
-----

2021/04/20

### Changes
  - Can specify IAM resource-name only, not necessarily the complete ARN

3.6.3
-----

2021/04/15

### Changes
  - Add hashcode for all findings

3.6.2
-----

2021/04/14

### Changes
  - Strip too long finding title in Patrowl import and add a hashcode

3.6.1
-----

2021/04/14

### Fixture
  - Fix missing 'Resource' parameter in policy statement

3.6.0
-----

2021/04/08

### New features
  - Add ACTION_PASSLIST to hide some legit actions
  - Hide not roles without resources `'*'` to limit false positive

### Fixture
  - Lambda: Block asset add in assetgroup is remote is empty (becaus of previous request failure)

3.5.0
-----

2021/04/07

### New feature
  - Add finding_description method in assettypes

### Changes
  - S3 Groups are returned instead of S3
  - Add 'env' parameter in lambda.config

3.4.1
-----

2021/04/06

### Fixtures
  - Fix not referenced is_lost_asset in lambda...

3.4.0
-----

2021/04/06

### Changes
  - Lambda: Can retrieve lost assets (asset without asset-group)
  - Lambda: Add in asset group at the end of the lambda (instead of each new asset)

3.3.1
-----

2021/03/19

### Changes
  - Case insensitive during name search `--name|-n`
  - Hidding IAM roles without Poweruser/Admin actions
  - Stack IAM roles in an IAM Group
  - Lambda: Remove Patterns and use asset.audit() only

3.3.0
-----

2021/03/17

### New features
  - Add IAM service type in discover and audit
  - Add IAM rules

### Changes
  - `--action-category` is replaced by `--min-rights`


3.2.0
-----

2021/03/12

### New features
  - Add a iam positional argument, to display info avec IAM arn


3.1.0
-----

2021/02/23

### New features
  - Add a -n|--name optional argument, to filter the asset name

### Fixtures
  - Fix rules by splitting public|private assets


3.0.0
-----

2021/02/18

### New features
  - Add a lambda launcher to have one lambda per account

### Breaking changes
  - rules are in yaml, not json
  - rename 'scan' positional argument into 'audit'

### Changes
  - output is changed
  - code is simplified
  - updated requirements.txt (and requirements.lambda.txt)
  - audit minimal severity is 'medium', not 'low'
