CHANGELOG
=========

AWS-TOWER
-----

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
