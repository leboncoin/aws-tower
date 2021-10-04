CHANGELOG
=========

AWS-TOWER
-----

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
