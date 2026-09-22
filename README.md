# IAM Security Auditor

Python tool built to audit AWS IAM configurations and flag security risks across user accounts.

## What it does

Connects to an AWS account and checks every IAM user for three 
common security issues I kept seeing referenced in cloud security 
roles:

- MFA not enabled - leaves accounts vulnerable to password attacks and social engineering
- Access keys older than 90 days - stale keys are a common attack vector
- AdministratorAccess policy attached - full admin should be rare in any account

Generates a timestamped JSON report so audits can be tracked over time.

## Why I built this

IAM misconfigurations are consistently in the top causes of AWS breaches. I wanted to build something practical that would catch the most common issues automatically rather than checking manually.

## Tech used

- Python 3
- boto3 (AWS SDK)
- AWS IAM

## How to run it

Clone the repo, configure AWS CLI with your credentials, then:

pip install boto3
python3 iam_auditor.py

## What's next

- Planning to add checks for unused IAM roles, overly permissive 
- S3 bucket policies, and export to HTML report format.
