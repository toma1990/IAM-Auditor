# IAM Security Auditor

A Python tool that audits AWS IAM user configurations and flags 
common security misconfigurations with AI-powered remediation guidance.

## What I set out to solve

IAM misconfigurations are consistently one of the top causes of 
AWS breaches. Missing MFA, overprivileged users, and stale access 
keys are easy to introduce and easy to miss in a large account. 
This tool automates the checks so they can be run consistently 
rather than relying on manual review.

## What I implemented

Three checks run against every IAM user in the account:

| Check | Condition flagged | Severity |
|-------|------------------|----------|
| MFA enabled | No MFA devices assigned | HIGH |
| AdministratorAccess policy | Managed policy directly attached | HIGH |
| Access key age | Key older than 90 days | MEDIUM |

Generates timestamped JSON and HTML reports saved to a reports/ folder.
Uses AWS Bedrock to generate plain English remediation advice for 
every finding, including risk level and step by step fix instructions.

## Scope and limitations

This tool checks a specific and limited set of IAM conditions. 
It does not perform a comprehensive IAM permissions audit.

What it does not check:
- Inline policies - administrator equivalent access granted through 
  inline policies will not be detected
- Group memberships - permissions inherited through groups are not assessed
- Role trust relationships - cross account or service roles are not reviewed
- Effective permissions - only direct policy attachments are checked, 
  not the combined effect of all policies on a user
- Service control policies - organisation level restrictions are not considered

The 90-day access key threshold is a common benchmark. Key age alone 
does not prove a key is compromised - it indicates the key should be 
reviewed and rotated as a precaution.

## What was actually tested

The tool was run against a live AWS account with test users created 
specifically to generate findings:

- test-user-1 with no MFA and AdministratorAccess attached - both 
  findings correctly detected
- Account with no IAM users - correctly returned zero findings
- AI remediation confirmed working via AWS Bedrock with risk-rated 
  step by step guidance generated

## Why I chose this approach

boto3 was chosen because it gives direct programmatic access to IAM 
APIs without requiring additional tooling. Pagination was implemented 
from the start because AWS IAM APIs return a maximum of 100 results 
per call and silently truncate larger result sets without it.

Bedrock integration adds a remediation layer that goes beyond simply 
flagging issues - it explains why each finding matters and what to 
do about it in plain English, which is useful for accounts where the 
person reviewing the report may not be a security specialist.

## What I would change before production

- Add inline policy inspection to catch administrator equivalent 
  access not using the managed policy
- Check group memberships to assess permissions inherited indirectly
- Add a permissions coverage section to the report showing what 
  was and was not assessed
- Separate the AI call failure from the core report so a Bedrock 
  outage does not prevent the audit completing
- Sanitise HTML output to prevent markup injection from user-controlled 
  field values such as usernames

## How to run it

Configure AWS CLI with read-only IAM permissions, then:

pip install boto3 markdown
python3 iam_auditor.py

Reports are saved to the reports/ folder.
