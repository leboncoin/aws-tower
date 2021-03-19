CHANGELOG
=========

AWS-TOWER
-----

3.3.1
-----

2021/03/19

### Changes
  - Case insensitive during name search `--name|-n`
  - Hidding IAM roles without Poweruser/Admin actions
  - Stack IAM roles in an IAM Group

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
