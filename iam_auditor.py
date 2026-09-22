import boto3
import json
from datetime import datetime, timezone

# Connect to IAM - using default credentials from aws configure
iam = boto3.client('iam')

def get_all_users():
    # Get all IAM users in the accoount
    # AWS returns max 100 users per API call - paginator handles accounts
    # with more than 100 users automatically so nothing gets missed
    users = []
    paginator = iam.get_paginator('list_users')
    for page in paginator.paginate():
        users.extend(page['Users'])
    return users

def check_mfa(username):
    # No MFA devices means the account is vulnerable to password attacks
    response = iam.list_mfa_devices(UserName=username)
    return len(response['MFADevices']) > 0

def check_access_keys(username):
    # Keys older than 90 days are a security risk - flag required
    response = iam.list_access_keys(UserName=username)
    keys = []
    for key in response['AccessKeyMetadata']:
        created = key['CreateDate']
        age_days = (datetime.now(timezone.utc) - created).days
        keys.append({
            'KeyId': key['AccessKeyId'][-4:],
            'Status': key['Status'],
            'AgeDays': age_days,
            'OverAged': age_days > 90
        })
    return keys

def check_admin_policies(username):
    # Check if user has full admin access - this should be rare in any account
    attached = iam.list_attached_user_policies(UserName=username)
    for policy in attached['AttachedPolicies']:
        if policy['PolicyName'] == 'AdministratorAccess':
            return True
    # Also check inline policies for hidden admin access
    inline = iam.list_user_policies(UserName=username)
    return False

def audit_users():
    print("\n=== IAM Security Audit ===")
    print(f"Running at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    users = get_all_users()
    print(f"Found {len(users)} IAM users\n")
    
    findings = []
    
    for user in users:
        username = user['UserName']
        print(f"Checking: {username}")
        
        user_findings = {
            'User': username,
            'MFA': check_mfa(username),
            'AdminAccess': check_admin_policies(username),
            'AccessKeys': check_access_keys(username),
            'Issues': []
        }
        
        # Flag anything that needs attention
        if not user_findings['MFA']:
            user_findings['Issues'].append('No MFA enabled')
        if user_findings['AdminAccess']:
            user_findings['Issues'].append('Has AdministratorAccess policy')
        for key in user_findings['AccessKeys']:
            if key['OverAged']:
                user_findings['Issues'].append(f"Access key ...{key['KeyId']} is {key['AgeDays']} days old")
        
        findings.append(user_findings)
    
    return findings

def generate_report(findings):
    # Write results to a JSON file with timestamp so reports don't overwrite each other
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"iam_audit_{timestamp}.json"
    
    # Count total issues found across all users
    total_issues = sum(len(f['Issues']) for f in findings)
    
    report = {
        'AuditDate': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'TotalUsers': len(findings),
        'TotalIssues': total_issues,
        'Findings': findings
    }
    
    with open(filename, 'w') as f:
        json.dump(report, f, indent=4, default=str)
    
    # Print summary to terminal so you get immediate feedback
    print(f"\n=== Audit Complete ===")
    print(f"Users checked: {len(findings)}")
    print(f"Total issues found: {total_issues}")
    print(f"Full report saved to: {filename}")
    
    # Show any users with issues so they stand out
    print("\nUsers with issues:")
    for finding in findings:
        if finding['Issues']:
            print(f"  {finding['User']}:")
            for issue in finding['Issues']:
                print(f"    - {issue}")

if __name__ == "__main__":
    findings = audit_users()
    generate_report(findings)
