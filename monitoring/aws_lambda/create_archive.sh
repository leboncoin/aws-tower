#!/bin/bash

rm -f aws_lambda.zip
rm -Rf ./package

pip install -r monitoring/aws_lambda/requirements.txt --target ./package

zip -r aws_lambda.zip config/ libs/ package/ monitoring/aws_lambda/
