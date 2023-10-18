#!/bin/bash

rm -f archive_alerting.zip
rm -Rf ./package

pip install -r monitoring/aws_alerting/requirements.txt --target ./package

zip -r archive_alerting.zip package/ monitoring/aws_alerting/
