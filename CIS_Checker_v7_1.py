#!/bin/python3
# CIS 7.0.0 Check for AWS
# Author: Michael Raines
# Updated to CIS AWS Foundations Benchmark v7.0.0 (03-25-2026)
# Supports multi-account auditing via STS AssumeRole

import boto3
import json
import datetime
import logging
import botocore
import argparse
import os
import sys
import io
import shutil
import requests
from tqdm import tqdm
from PIL import Image
from io import BytesIO
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.firefox import GeckoDriverManager


parser = argparse.ArgumentParser(description="Run AWS CIS 7.0.0 security compliance checks.")
parser.add_argument("--check", help="Specify the check to run, e.g., 2.4.")
parser.add_argument("--profile", default="default", help="Specify the AWS profile to use (default: 'default').")
parser.add_argument("--regions", type=str, help="Comma-separated list of AWS regions.")
parser.add_argument("--html-only", action="store_true", help="Regenerate the HTML report without running checks.")
parser.add_argument("--screenshot", action="store_true", help="Capture screenshots after generating HTML report.")
parser.add_argument("--role", type=str, help="IAM Role ARN to assume in target accounts (e.g. arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME). Use {account} as placeholder for account ID.")
parser.add_argument("--accounts", type=str, help="Comma-separated list of AWS account IDs to audit. Requires --role.")
args = parser.parse_args()

#Requirements.txt
'''
selenium
webdriver_manager
Pillow
boto3
selenium
webdriver-manager
botocore
tqdm
'''


# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    filename='CIS_checker.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.DEBUG
)
logger = logging.getLogger()


# ─── Session helpers ─────────────────────────────────────────────────────────
DEFAULT_REGIONS = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]


def get_base_session():
    return boto3.Session(profile_name=args.profile)


def assume_role_session(base_session, role_arn, account_id):
    """Return a boto3 Session authenticated via STS AssumeRole."""
    sts = base_session.client('sts')
    resp = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"CIS_Checker_{account_id}"
    )
    creds = resp['Credentials']
    return boto3.Session(
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken']
    )


def get_regions(session):
    if args.regions:
        return args.regions.split(",")
    try:
        return [r['RegionName'] for r in session.client('ec2').describe_regions()['Regions']]
    except botocore.exceptions.ClientError as e:
        print(f"Error fetching AWS regions dynamically: {e}")
        print(f"Falling back to default regions: {', '.join(DEFAULT_REGIONS)}")
        return DEFAULT_REGIONS


# ─── File output helpers ─────────────────────────────────────────────────────
def datetime_handler(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    raise TypeError("Type not serializable")


def _transform_results(results):
    """Convert the internal results dict to the target JSON format consumed by the parser."""
    output = []
    for check_num, data in results.items():
        meta = _CHECK_META.get(check_num, {})
        name = meta[0] if meta else f"{check_num} {data.get('description', '')}"
        remediation = meta[1] if meta else "Review the relevant AWS console settings and apply the recommended configuration in accordance with the CIS AWS Foundations Benchmark."

        # Build check-ID key matching O365 convention: CIS_AWS_v7.0.0_<num>
        safe_num = check_num.replace(".", "_")
        check_key = f"CIS_AWS_v7.0.0_{safe_num}"

        finding = {
            "asset": f"/accounts/{_current_account_id}",
            "status": data.get("status", "UNKNOWN"),
            "name": name,
            "description": data.get("explanation", data.get("description", "")),
            "details": data.get("result", {}),
            "impact": "Minor",
            "likelihood": "Low",
            "risk": "Informational",
            "remediation": remediation,
        }
        output.append({check_key: [finding]})
    return output


def write_results_to_file(results, filepath="results.json"):
    with open(filepath, "w") as outfile:
        json.dump(_transform_results(results), outfile, indent=4, default=datetime_handler)


def move_to_output(src_path, dest_directory):
    if os.path.exists(src_path):
        dest_path = os.path.join(dest_directory, os.path.basename(src_path))
        shutil.move(src_path, dest_path)
    else:
        print(f"Source path does not exist: {src_path}")


# ─── Explanation strings (v7.0.0 numbering) ──────────────────────────────────
explanation_2_4  = "The root account should not have any access keys associated with it."
explanation_2_5  = "If AccountMFAEnabled contains a value of 0, MFA is not enabled for the root user."
explanation_2_6  = "If VirtualMFA contains ARN with the name 'root' in it, virtual MFA is used. Hardware MFA is preferred."
explanation_2_7  = "There is no prescribed time limit but the check fails if the root user has been used within 90 days."
explanation_2_8  = "MinimumPasswordLength should be 14 or greater."
explanation_2_9  = "PasswordReusePrevention should be 24 or higher."
explanation_2_10 = "If HasConsolePassword is true, MFAActive must also be true."
explanation_2_11 = "Users where credentials have not been used in 45 days or more should be disabled."
explanation_2_12 = "Access keys older than 90 days should be rotated."
explanation_2_13 = "Users should only receive permissions through groups, not direct policy attachments."
explanation_2_14 = "Users should follow the concept of least privilege and should not receive full admin privileges."
explanation_2_15 = "If PolicyRoles returns an empty value, a support role has not been set."
explanation_2_16 = "An IAM instance role should be applied to every EC2 instance."
explanation_2_17 = "Expired certificates should be removed from IAM to avoid accidental use."
explanation_2_18 = "IAM Access Analyzer should be enabled in all regions."
explanation_2_19 = "IAM users should be managed through an identity provider or AWS Organizations."
explanation_2_20 = "Roles_With_AWSCloudShellFullAccess should be empty to ensure users do not have full access to CloudShell."
explanation_2_21 = "Resource policies should not allow unrestricted access using 'Principal': '*' without conditions."
explanation_3_1_1 = "Effect should be set to deny and aws:SecureTransport should be false."
explanation_3_1_2 = "MFADelete should be enabled for all S3 buckets."
explanation_3_1_4 = "A public access block should be present and all settings should be true."
explanation_3_2_1 = "StorageEncrypted should return a value of true to ensure RDS instances are encrypted at rest."
explanation_3_2_2 = "AutoMinorVersionUpgrade should return a value of true."
explanation_3_2_3 = "The PubliclyAccessible flag should be set false."
explanation_3_2_4 = "RDS instances should use Multi-AZ deployments for high availability."
explanation_3_3_1 = "Each EFS filesystem should be encrypted."
explanation_4_1  = "CloudTrail should be enabled and logging in all regions."
explanation_4_2  = "CloudTrail Log File Validation should be enabled."
explanation_4_3  = "AWS Config recording should not return a value of false."
explanation_4_4  = "LoggingEnabled should not return a null value for the CloudTrail S3 bucket."
explanation_4_5  = "KmsKeyId should return the ARN of the KMS key used to encrypt CloudTrail logs."
explanation_4_6  = "KeyRotationEnabled should return a value of true for all customer-created symmetric CMKs."
explanation_4_7  = "Every VPC should have flow logging enabled."
explanation_4_8  = "S3 object-level write events should be logged via CloudTrail."
explanation_4_9  = "S3 object-level read events should be logged via CloudTrail."
explanation_4_10 = "All AWS-managed web front-end services (CloudFront, ALB, NLB, API Gateway) must have access logging enabled."
explanation_5_1  = "Unauthorized API calls should generate CloudWatch alarms via CloudTrail metric filters."
explanation_5_16 = "AWS Security Hub should be enabled."
explanation_6_1_1 = "EbsEncryptionByDefault should be set to true in all regions."
explanation_6_2  = "NACLs should not allow unrestricted ingress on administrative ports."
explanation_6_3  = "Security groups should not allow ingress from 0.0.0.0/0 to administrative ports."
explanation_6_4  = "Security groups should not allow ingress from ::/0 (IPv6) to administrative ports."
explanation_6_5  = "Default security groups should restrict all traffic. This encourages least-privilege security group development."
explanation_6_6  = "VPC peering routing tables should follow least-access principles."
explanation_6_7  = "EC2 instances should use IMDSv2 (HttpTokens=required)."
explanation_6_8  = "VPC Endpoints should be used to keep AWS service traffic off the public internet."

# Module-level account identifier – set once per audit run (used for asset field)
_current_account_id = "aws"

# ─── Remediation strings ──────────────────────────────────────────────────────
remediation_2_4  = "Remove any access keys associated with the root account by navigating to the IAM console, selecting Security Credentials under the root account, and deleting all listed access keys."
remediation_2_5  = "Enable MFA for the root user by signing in as root, navigating to the IAM console Security Credentials page, and following the steps to assign a virtual or hardware MFA device."
remediation_2_6  = "Replace any virtual MFA device assigned to the root account with a hardware MFA device by navigating to the IAM console Security Credentials page, deleting the virtual device, and enrolling a hardware token."
remediation_2_7  = "Avoid using the root account for day-to-day tasks; create individual IAM users or roles with least-privilege permissions for all administrative activities."
remediation_2_8  = "Update the IAM account password policy to require a minimum password length of 14 characters by navigating to IAM > Account Settings > Password Policy."
remediation_2_9  = "Update the IAM account password policy to prevent the reuse of the last 24 passwords by navigating to IAM > Account Settings > Password Policy."
remediation_2_10 = "Enable MFA for each IAM user with console access by navigating to IAM > Users, selecting each affected user, and assigning a virtual or hardware MFA device under the Security Credentials tab."
remediation_2_11 = "Disable or delete IAM credentials (passwords and access keys) that have not been used within 45 days by reviewing the IAM credential report and removing stale credentials."
remediation_2_12 = "Rotate IAM access keys that are older than 90 days by creating a new key, updating all references, and then deactivating and deleting the old key via IAM > Users > Security Credentials."
remediation_2_13 = "Remove directly attached policies from IAM users and manage permissions exclusively through IAM groups by navigating to IAM > Users and detaching any inline or managed policies."
remediation_2_14 = "Detach or delete any IAM policies that grant full '*:*' administrative access and replace them with least-privilege policies scoped to specific actions and resources."
remediation_2_15 = "Create a dedicated IAM role and attach the AWSSupportAccess managed policy to ensure a support role exists for managing incidents with AWS Support."
remediation_2_16 = "Assign an IAM instance profile to every EC2 instance by navigating to EC2 > Instances, selecting the instance, and attaching an appropriate IAM role with least-privilege permissions."
remediation_2_17 = "Remove expired SSL/TLS certificates from IAM by navigating to IAM > Certificate Manager, identifying expired certificates, and deleting them."
remediation_2_18 = "Enable IAM Access Analyzer in all AWS regions by navigating to IAM Access Analyzer in each region's console and creating an analyzer scoped to the account or organization."
remediation_2_19 = "Configure an identity provider (SAML/OIDC) or enroll the account in AWS Organizations so that IAM users are centrally managed through federated identity rather than local IAM accounts."
remediation_2_20 = "Remove the AWSCloudShellFullAccess policy from any users, groups, or roles that do not require it by navigating to IAM and detaching the policy from each entity."
remediation_2_21 = "Review and update all resource-based policies (S3 bucket policies, KMS key policies, etc.) to remove statements that allow unrestricted access via 'Principal': '*' without compensating conditions."
remediation_3_1_1 = "Add a bucket policy statement with Effect: Deny and Condition: aws:SecureTransport: false to enforce HTTPS-only access on each non-compliant S3 bucket."
remediation_3_1_2 = "Enable MFA Delete on each S3 bucket by using the AWS CLI with root credentials: aws s3api put-bucket-versioning --bucket <bucket> --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa '<serial> <token>'."
remediation_3_1_4 = "Enable Block Public Access for each non-compliant S3 bucket by navigating to S3 > Bucket > Permissions > Block Public Access and enabling all four settings."
remediation_3_2_1 = "Enable encryption at rest for each non-compliant RDS instance by modifying the instance to use AWS-managed or customer-managed KMS encryption; note that encryption cannot be enabled on an existing unencrypted instance and requires a snapshot-restore workflow."
remediation_3_2_2 = "Enable Auto Minor Version Upgrade for each non-compliant RDS instance by navigating to RDS > Databases, selecting the instance, and enabling the Auto minor version upgrade option under Maintenance."
remediation_3_2_3 = "Disable public accessibility for each non-compliant RDS instance by modifying the instance in the RDS console and setting Publicly Accessible to No."
remediation_3_2_4 = "Enable Multi-AZ deployment for each non-compliant RDS instance by modifying the instance in the RDS console and selecting the Multi-AZ option under Availability & Durability."
remediation_3_3_1 = "Enable encryption for each non-compliant EFS file system; note that encryption cannot be enabled on an existing file system and requires creating a new encrypted file system and migrating data."
remediation_4_1  = "Create or update a CloudTrail trail to enable multi-region logging and ensure it is actively logging by navigating to CloudTrail > Trails and verifying that logging is turned on."
remediation_4_2  = "Enable log file validation on each CloudTrail trail by modifying the trail in the CloudTrail console or running: aws cloudtrail update-trail --name <trail> --enable-log-file-validation."
remediation_4_3  = "Enable AWS Config recording in all regions by navigating to AWS Config > Settings and starting the configuration recorder with an appropriate delivery channel."
remediation_4_4  = "Enable server access logging on the S3 bucket used by CloudTrail by navigating to S3 > Bucket > Properties > Server Access Logging and specifying a target bucket."
remediation_4_5  = "Enable KMS log file encryption on the CloudTrail trail by modifying the trail in the CloudTrail console and selecting a KMS key under Log file SSE-KMS encryption."
remediation_4_6  = "Enable automatic key rotation for each customer-managed KMS CMK by navigating to KMS > Customer Managed Keys, selecting the key, and enabling automatic key rotation under Key Rotation."
remediation_4_7  = "Enable VPC Flow Logs for each non-compliant VPC by navigating to VPC > Your VPCs, selecting the VPC, and creating a flow log that publishes to CloudWatch Logs or S3."
remediation_4_8  = "Configure a CloudTrail event selector to capture S3 object-level write events by updating the trail's event selectors to include Data Events of type AWS::S3::Object with ReadWriteType WriteOnly or All."
remediation_4_9  = "Configure a CloudTrail event selector to capture S3 object-level read events by updating the trail's event selectors to include Data Events of type AWS::S3::Object with ReadWriteType ReadOnly or All."
remediation_4_10 = "Enable access logging for each non-compliant web front-end service (CloudFront, ALB/NLB, API Gateway) by configuring the access log destination in each service's settings within the AWS console."
remediation_5_1  = "Create a CloudWatch metric filter and alarm on the CloudTrail log group to detect and alert on unauthorized API calls matching patterns for UnauthorizedOperation and AccessDenied events."
remediation_5_16 = "Enable AWS Security Hub in each region by navigating to Security Hub in the AWS console and completing the initial setup wizard; optionally enable relevant security standards."
remediation_6_1_1 = "Enable EBS encryption by default in each non-compliant region by navigating to EC2 > Account Attributes > EBS Encryption and enabling the 'Always encrypt new EBS volumes' setting."
remediation_6_2  = "Review and update Network ACL rules to remove or restrict ingress entries that allow all traffic (0.0.0.0/0) to administrative ports (22, 3389) by navigating to VPC > Network ACLs."
remediation_6_3  = "Update non-compliant security groups to remove inbound rules allowing 0.0.0.0/0 access to administrative ports (22, 3389) and replace them with specific, trusted IP ranges."
remediation_6_4  = "Update non-compliant security groups to remove inbound rules allowing ::/0 (IPv6) access to administrative ports (22, 3389) and replace them with specific, trusted IPv6 ranges."
remediation_6_5  = "Update default security groups in each VPC to remove all inbound and outbound rules, ensuring that no traffic is permitted by default, and use custom security groups for all resources."
remediation_6_6  = "Review VPC peering connection routing tables and restrict routes to only the specific CIDR ranges required, avoiding overly broad routes that grant access beyond what is necessary."
remediation_6_7  = "Enforce IMDSv2 on each non-compliant EC2 instance by modifying the instance metadata options: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required."
remediation_6_8  = "Create VPC endpoints for AWS services used within each non-compliant VPC by navigating to VPC > Endpoints and creating interface or gateway endpoints for the required services."

# Mapping of check number → (name prefix with number, remediation string)
_CHECK_META = {
    "2.4":   ("2.4 Ensure no 'root' user account access key exists",                                                           remediation_2_4),
    "2.5":   ("2.5 Ensure MFA is enabled for the 'root' user account",                                                        remediation_2_5),
    "2.6":   ("2.6 Ensure hardware MFA is enabled for the 'root' user account",                                               remediation_2_6),
    "2.7":   ("2.7 Eliminate use of the 'root' user for administrative and daily tasks",                                       remediation_2_7),
    "2.8":   ("2.8 Ensure IAM password policy requires minimum length of 14 or greater",                                      remediation_2_8),
    "2.9":   ("2.9 Ensure IAM password policy prevents password reuse",                                                        remediation_2_9),
    "2.10":  ("2.10 Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",      remediation_2_10),
    "2.11":  ("2.11 Ensure credentials unused for 45 days or more are disabled",                                               remediation_2_11),
    "2.12":  ("2.12 Ensure access keys are rotated every 90 days or less",                                                     remediation_2_12),
    "2.13":  ("2.13 Ensure IAM users receive permissions only through groups",                                                  remediation_2_13),
    "2.14":  ("2.14 Ensure IAM policies that allow full '*:*' administrative privileges are not attached",                     remediation_2_14),
    "2.15":  ("2.15 Ensure a support role has been created to manage incidents with AWS Support",                               remediation_2_15),
    "2.16":  ("2.16 Ensure IAM instance roles are used for AWS resource access from instances",                                 remediation_2_16),
    "2.17":  ("2.17 Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed",                               remediation_2_17),
    "2.18":  ("2.18 Ensure that IAM External Access Analyzer is enabled for all regions",                                      remediation_2_18),
    "2.19":  ("2.19 Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments", remediation_2_19),
    "2.20":  ("2.20 Ensure access to AWSCloudShellFullAccess is restricted",                                                   remediation_2_20),
    "2.21":  ("2.21 Ensure AWS resource policies do not allow unrestricted access using 'Principal': '*'",                    remediation_2_21),
    "3.1.1": ("3.1.1 Ensure S3 Bucket Policy is set to deny HTTP requests",                                                    remediation_3_1_1),
    "3.1.2": ("3.1.2 Ensure MFA Delete is enabled on S3 buckets",                                                              remediation_3_1_2),
    "3.1.4": ("3.1.4 Ensure that S3 Buckets are configured with 'Block Public Access' enabled",                               remediation_3_1_4),
    "3.2.1": ("3.2.1 Ensure that encryption-at-rest is enabled for RDS Instances",                                             remediation_3_2_1),
    "3.2.2": ("3.2.2 Ensure the Auto Minor Version Upgrade feature is enabled for RDS instances",                              remediation_3_2_2),
    "3.2.3": ("3.2.3 Ensure that RDS instances are not publicly accessible",                                                   remediation_3_2_3),
    "3.2.4": ("3.2.4 Ensure Multi-AZ deployments are used for enhanced availability in Amazon RDS",                            remediation_3_2_4),
    "3.3.1": ("3.3.1 Ensure that encryption is enabled for EFS file systems",                                                  remediation_3_3_1),
    "4.1":   ("4.1 Ensure CloudTrail is enabled and logging in all regions",                                                    remediation_4_1),
    "4.2":   ("4.2 Ensure CloudTrail Log File Validation is enabled",                                                           remediation_4_2),
    "4.3":   ("4.3 Ensure AWS Config recording is enabled",                                                                     remediation_4_3),
    "4.4":   ("4.4 Ensure CloudTrail S3 bucket access logging is enabled",                                                     remediation_4_4),
    "4.5":   ("4.5 Ensure CloudTrail logs are encrypted at rest using KMS CMKs",                                               remediation_4_5),
    "4.6":   ("4.6 Ensure rotation for customer-created symmetric CMKs is enabled",                                            remediation_4_6),
    "4.7":   ("4.7 Ensure VPC flow logging is enabled in all VPCs",                                                            remediation_4_7),
    "4.8":   ("4.8 Ensure that object-level logging for write events is enabled for S3 buckets",                               remediation_4_8),
    "4.9":   ("4.9 Ensure that object-level logging for read events is enabled for S3 buckets",                                remediation_4_9),
    "4.10":  ("4.10 Ensure all AWS-managed web front-end services have access logging enabled",                                 remediation_4_10),
    "5.1":   ("5.1 Ensure unauthorized API calls are monitored",                                                                remediation_5_1),
    "5.16":  ("5.16 Ensure AWS Security Hub is enabled",                                                                        remediation_5_16),
    "6.1.1": ("6.1.1 Ensure EBS volume encryption is enabled in all regions",                                                  remediation_6_1_1),
    "6.2":   ("6.2 Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports",                remediation_6_2),
    "6.3":   ("6.3 Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports",             remediation_6_3),
    "6.4":   ("6.4 Ensure no security groups allow ingress from ::/0 to remote server administration ports",                  remediation_6_4),
    "6.5":   ("6.5 Ensure the default security group of every VPC restricts all traffic",                                      remediation_6_5),
    "6.6":   ("6.6 Ensure routing tables for VPC peering are least access",                                                    remediation_6_6),
    "6.7":   ("6.7 Ensure that EC2 Metadata Service only allows IMDSv2",                                                       remediation_6_7),
    "6.8":   ("6.8 Ensure VPC Endpoints are used for access to AWS Services",                                                  remediation_6_8),
}


# ═══════════════════════════════════════════════════════════════════════════════
# Section 2 – Identity and Access Management
# ═══════════════════════════════════════════════════════════════════════════════

def check_2_4(session, results, filepath):
    """2.4 – Ensure no 'root' user account access key exists."""
    iam = session.client('iam')
    try:
        summary = iam.get_account_summary()
        keys_present = summary.get('SummaryMap', {}).get('AccountAccessKeysPresent', 0)
        results["2.4"] = {
            "description": "Ensure no 'root' user account access key exists",
            "result": {"AccountAccessKeysPresent": keys_present,
                       "message": "Root access keys detected!" if keys_present else "No root access keys found."},
            "explanation": explanation_2_4,
            "status": "FAIL" if keys_present else "PASS"
        }
    except Exception as e:
        logger.error(f"Error in 2.4: {e}")
        results["2.4"] = {"description": "Ensure no 'root' user account access key exists",
                          "result": str(e), "explanation": explanation_2_4, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_5(session, results, filepath):
    """2.5 – Ensure MFA is enabled for the 'root' user account."""
    iam = session.client('iam')
    try:
        summary = iam.get_account_summary()
        mfa_enabled = summary['SummaryMap']['AccountMFAEnabled']
        results["2.5"] = {
            "description": "Ensure MFA is enabled for the 'root' user account",
            "result": {"AccountMFAEnabled": mfa_enabled,
                       "message": "MFA is enabled for the root user account." if mfa_enabled == 1 else "MFA is NOT enabled for the root user account!"},
            "explanation": explanation_2_5,
            "status": "PASS" if mfa_enabled == 1 else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 2.5: {e}")
        results["2.5"] = {"description": "Ensure MFA is enabled for the 'root' user account",
                          "result": str(e), "explanation": explanation_2_5, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_6(session, results, filepath):
    """2.6 – Ensure hardware MFA is enabled for the 'root' user account."""
    iam = session.client('iam')
    try:
        virtual_mfas = iam.list_virtual_mfa_devices()
        root_has_virtual = any('root' in mfa['SerialNumber'] for mfa in virtual_mfas.get('VirtualMFADevices', []))
        results["2.6"] = {
            "description": "Ensure hardware MFA is enabled for the 'root' user account",
            "result": {"root_has_virtual_mfa": root_has_virtual,
                       "virtual_mfas": virtual_mfas.get('VirtualMFADevices', [])},
            "explanation": explanation_2_6,
            "status": "FAIL" if root_has_virtual else "PASS"
        }
    except Exception as e:
        logger.error(f"Error in 2.6: {e}")
        results["2.6"] = {"description": "Ensure hardware MFA is enabled for the 'root' user account",
                          "result": str(e), "explanation": explanation_2_6, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_7(session, results, filepath):
    """2.7 – Eliminate use of the 'root' user for administrative and daily tasks."""
    client = session.client('iam')
    root_activity = {"LastUsedDate": "Never Used", "LastUsedService": "N/A", "LastUsedRegion": "N/A"}
    try:
        response = client.get_account_summary()
        summary_map = response['SummaryMap']
        if 'RootUserLastUsedDate' in summary_map:
            last_used = summary_map['RootUserLastUsedDate']
            if last_used:
                root_activity['LastUsedDate'] = last_used.strftime('%Y-%m-%d %H:%M:%S')
                root_activity['LastUsedService'] = summary_map.get('RootUserLastUsedService', 'N/A')
                root_activity['LastUsedRegion'] = summary_map.get('RootUserLastUsedRegion', 'N/A')

        if root_activity["LastUsedDate"] == "Never Used":
            status = "PASS"
        else:
            last_dt = datetime.datetime.strptime(root_activity["LastUsedDate"], '%Y-%m-%d %H:%M:%S')
            status = "PASS" if (datetime.datetime.utcnow() - last_dt).days > 90 else "FAIL"
    except Exception as e:
        logger.error(f"Error in 2.7: {e}")
        root_activity["Error"] = str(e)
        status = "ERROR"
    results["2.7"] = {"description": "Eliminate use of the 'root' user for administrative and daily tasks",
                      "result": root_activity, "explanation": explanation_2_7, "status": status}
    write_results_to_file(results, filepath)


def check_2_8(session, results, filepath):
    """2.8 – Ensure IAM password policy requires minimum length of 14 or greater."""
    client = session.client('iam')
    try:
        policy = client.get_account_password_policy()['PasswordPolicy']
        min_len = policy.get('MinimumPasswordLength', 0)
        results["2.8"] = {
            "description": "Ensure IAM password policy requires minimum length of 14 or greater",
            "result": {"MinimumPasswordLength": min_len},
            "explanation": explanation_2_8,
            "status": "PASS" if min_len >= 14 else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 2.8: {e}")
        results["2.8"] = {"description": "Ensure IAM password policy requires minimum length of 14 or greater",
                          "result": str(e), "explanation": explanation_2_8, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_9(session, results, filepath):
    """2.9 – Ensure IAM password policy prevents password reuse."""
    client = session.client('iam')
    try:
        policy = client.get_account_password_policy()['PasswordPolicy']
        reuse_prev = policy.get('PasswordReusePrevention', 0)
        results["2.9"] = {
            "description": "Ensure IAM password policy prevents password reuse",
            "result": policy,
            "explanation": explanation_2_9,
            "status": "PASS" if reuse_prev and reuse_prev >= 24 else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 2.9: {e}")
        results["2.9"] = {"description": "Ensure IAM password policy prevents password reuse",
                          "result": str(e), "explanation": explanation_2_9, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_10(session, results, filepath):
    """2.10 – Ensure MFA is enabled for all IAM users that have a console password."""
    client = session.client('iam')
    non_compliant = []
    try:
        paginator = client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                try:
                    client.get_login_profile(UserName=user['UserName'])
                    has_console = True
                except client.exceptions.NoSuchEntityException:
                    has_console = False
                if has_console:
                    mfa_devices = client.list_mfa_devices(UserName=user['UserName'])['MFADevices']
                    if not mfa_devices:
                        non_compliant.append({"User": user['UserName'], "HasConsolePassword": True, "MFAActive": False})
        results["2.10"] = {
            "description": "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
            "result": non_compliant if non_compliant else "All console users have MFA enabled.",
            "explanation": explanation_2_10,
            "status": "PASS" if not non_compliant else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 2.10: {e}")
        results["2.10"] = {"description": "Ensure MFA is enabled for all IAM users with console access",
                           "result": str(e), "explanation": explanation_2_10, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_11(session, results, filepath):
    """2.11 – Ensure credentials unused for 45 days or more are disabled."""
    client = session.client('iam')
    non_compliant = []
    try:
        for user in client.list_users()['Users']:
            keys = client.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            for key in keys:
                last_used_info = client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                last_used = last_used_info.get('AccessKeyLastUsed', {}).get('LastUsedDate', key['CreateDate'])
                days = (datetime.datetime.now(datetime.timezone.utc) - last_used).days
                if days > 45:
                    non_compliant.append({"User": user['UserName'],
                                          "LastUsedDate": last_used.strftime('%Y-%m-%d %H:%M:%S UTC')})
                    break
        results["2.11"] = {
            "description": "Ensure credentials unused for 45 days or more are disabled",
            "result": non_compliant if non_compliant else "All credentials are within the 45-day threshold.",
            "explanation": explanation_2_11,
            "status": "PASS" if not non_compliant else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 2.11: {e}")
        results["2.11"] = {"description": "Ensure credentials unused for 45 days or more are disabled",
                           "result": str(e), "explanation": explanation_2_11, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_12(session, results, filepath):
    """2.12 – Ensure access keys are rotated every 90 days or less."""
    client = session.client('iam')
    non_compliant = []
    try:
        for user in client.list_users()['Users']:
            keys = client.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            for key in keys:
                days_old = (datetime.datetime.now(datetime.timezone.utc) - key['CreateDate']).days
                if days_old > 90:
                    non_compliant.append({"User": user['UserName'],
                                          "AccessKeyId": key['AccessKeyId'],
                                          "CreateDate": key['CreateDate'].strftime('%Y-%m-%d %H:%M:%S UTC')})
        results["2.12"] = {
            "description": "Ensure access keys are rotated every 90 days or less",
            "result": non_compliant if non_compliant else "All access keys are within 90-day rotation policy.",
            "explanation": explanation_2_12,
            "status": "PASS" if not non_compliant else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 2.12: {e}")
        results["2.12"] = {"description": "Ensure access keys are rotated every 90 days or less",
                           "result": str(e), "explanation": explanation_2_12, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_13(session, results, filepath):
    """2.13 – Ensure IAM users receive permissions only through groups."""
    client = session.client('iam')
    non_compliant = []
    try:
        for user in client.list_users()['Users']:
            attached = client.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
            inline = client.list_user_policies(UserName=user['UserName'])['PolicyNames']
            if attached or inline:
                non_compliant.append({"User": user['UserName'],
                                      "AttachedPolicies": [p['PolicyName'] for p in attached],
                                      "InlinePolicies": inline})
        results["2.13"] = {
            "description": "Ensure IAM users receive permissions only through groups",
            "result": non_compliant if non_compliant else "All users receive permissions through groups only.",
            "explanation": explanation_2_13,
            "status": "PASS" if not non_compliant else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 2.13: {e}")
        results["2.13"] = {"description": "Ensure IAM users receive permissions only through groups",
                           "result": str(e), "explanation": explanation_2_13, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_14(session, results, filepath):
    """2.14 – Ensure IAM policies that allow full '*:*' administrative privileges are not attached."""
    client = session.client('iam')
    full_admin = []
    try:
        paginator = client.get_paginator('list_policies')
        for page in paginator.paginate(Scope='All'):
            for policy in page['Policies']:
                version = client.get_policy_version(PolicyArn=policy['Arn'],
                                                     VersionId=policy['DefaultVersionId'])
                statements = version['PolicyVersion']['Document'].get('Statement', [])
                if isinstance(statements, dict):
                    statements = [statements]
                for stmt in statements:
                    if (stmt.get('Effect') == 'Allow' and
                            stmt.get('Action') == '*' and
                            stmt.get('Resource') == '*'):
                        users = client.list_entities_for_policy(PolicyArn=policy['Arn'], EntityFilter='User')['PolicyUsers']
                        roles = client.list_entities_for_policy(PolicyArn=policy['Arn'], EntityFilter='Role')['PolicyRoles']
                        groups = client.list_entities_for_policy(PolicyArn=policy['Arn'], EntityFilter='Group')['PolicyGroups']
                        full_admin.append({"PolicyName": policy['PolicyName'], "PolicyArn": policy['Arn'],
                                           "Users": [u['UserName'] for u in users],
                                           "Roles": [r['RoleName'] for r in roles],
                                           "Groups": [g['GroupName'] for g in groups]})
                        break
        results["2.14"] = {
            "description": "Ensure IAM policies that allow full '*:*' administrative privileges are not attached",
            "result": full_admin if full_admin else "No policies found with full administrative privileges.",
            "explanation": explanation_2_14,
            "status": "PASS" if not full_admin else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 2.14: {e}")
        results["2.14"] = {"description": "Ensure IAM policies that allow full '*:*' administrative privileges are not attached",
                           "result": str(e), "explanation": explanation_2_14, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_15(session, results, filepath):
    """2.15 – Ensure a support role has been created to manage incidents with AWS Support."""
    client = session.client('iam')
    try:
        for scope in ['AWS', 'Local']:
            for policy in client.list_policies(Scope=scope)['Policies']:
                if policy['PolicyName'] == 'AWSSupportAccess':
                    entities = client.list_entities_for_policy(PolicyArn=policy['Arn'])
                    results["2.15"] = {
                        "description": "Ensure a support role has been created to manage incidents with AWS Support",
                        "result": {
                            "PolicyName": policy['PolicyName'], "PolicyArn": policy['Arn'],
                            "PolicyRoles": [r['RoleName'] for r in entities.get('PolicyRoles', [])],
                            "PolicyUsers": [u['UserName'] for u in entities.get('PolicyUsers', [])],
                            "PolicyGroups": [g['GroupName'] for g in entities.get('PolicyGroups', [])]
                        },
                        "explanation": explanation_2_15,
                        "status": "PASS" if entities.get('PolicyRoles') else "FAIL"
                    }
                    write_results_to_file(results, filepath)
                    return
        results["2.15"] = {"description": "Ensure a support role has been created to manage incidents with AWS Support",
                           "result": "AWSSupportAccess policy not found.",
                           "explanation": explanation_2_15, "status": "FAIL"}
    except Exception as e:
        logger.error(f"Error in 2.15: {e}")
        results["2.15"] = {"description": "Ensure a support role has been created to manage incidents with AWS Support",
                           "result": str(e), "explanation": explanation_2_15, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_16(session, results, filepath):
    """2.16 – Ensure IAM instance roles are used for AWS resource access from instances."""
    ec2 = session.client('ec2')
    try:
        instances = ec2.describe_instances()
        without_roles = []
        for res in instances['Reservations']:
            for inst in res['Instances']:
                name = next((t['Value'] for t in inst.get('Tags', []) if t['Key'] == 'Name'), None)
                iam_role = inst.get('IamInstanceProfile', {}).get('Arn', "No IAM Role")
                if iam_role == "No IAM Role":
                    without_roles.append({"InstanceId": inst['InstanceId'], "InstanceName": name,
                                          "IAMRole": iam_role, "State": inst['State']['Name'],
                                          "LaunchTime": inst['LaunchTime']})
        results["2.16"] = {
            "description": "Ensure IAM instance roles are used for AWS resource access from instances",
            "result": without_roles if without_roles else "All instances have IAM roles assigned.",
            "status": "PASS" if not without_roles else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 2.16: {e}")
        results["2.16"] = {"description": "Ensure IAM instance roles are used for AWS resource access from instances",
                           "result": str(e), "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_17(session, results, filepath):
    """2.17 – Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed."""
    iam = session.client('iam')
    expired = []
    try:
        for cert in iam.list_server_certificates()['ServerCertificateMetadataList']:
            exp = cert['Expiration']
            if exp < datetime.datetime.now(exp.tzinfo):
                expired.append({"ServerCertificateName": cert['ServerCertificateName'],
                                 "Arn": cert['Arn'], "Expiration": exp})
        results["2.17"] = {
            "description": "Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed",
            "result": expired if expired else "No expired certificates found.",
            "explanation": explanation_2_17,
            "status": "PASS" if not expired else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 2.17: {e}")
        results["2.17"] = {"description": "Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed",
                           "result": str(e), "explanation": explanation_2_17, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_18(session, results, filepath, regions):
    """2.18 – Ensure that IAM External Access Analyzer is enabled for all regions."""
    sts = session.client('sts')
    account_id = sts.get_caller_identity()["Account"]
    violations = []
    try:
        for region in regions:
            aa_client = session.client('accessanalyzer', region_name=region)
            paginator = aa_client.get_paginator('list_analyzers')
            try:
                pages = list(paginator.paginate())
                if not any(page.get('analyzers') for page in pages):
                    violations.append({'AccountId': account_id, 'Region': region,
                                       'Status': 'Access Analyzer not enabled'})
            except botocore.exceptions.ClientError as e:
                violations.append({'AccountId': account_id, 'Region': region,
                                   'Status': f"Error: {str(e)}"})
        results["2.18"] = {
            "description": "Ensure that IAM External Access Analyzer is enabled for all regions",
            "result": violations if violations else "AWS Access Analyzer is enabled in all regions.",
            "explanation": explanation_2_18,
            "status": "FAIL" if violations else "PASS"
        }
    except Exception as e:
        logger.error(f"Error in 2.18: {e}")
        results["2.18"] = {"description": "Ensure that IAM External Access Analyzer is enabled for all regions",
                           "result": str(e), "explanation": explanation_2_18, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_19(session, results, filepath):
    """2.19 – Ensure IAM users are managed centrally via identity federation or AWS Organizations."""
    iam = session.client('iam')
    try:
        identity_providers = iam.list_saml_providers()['SAMLProviderList']
        try:
            org = session.client('organizations').describe_organization()
            org_status = {"Available": True,
                          "MasterAccountId": org['Organization']['MasterAccountId'],
                          "MasterAccountEmail": org['Organization']['MasterAccountEmail']}
        except Exception:
            org_status = {"Available": False}
        results["2.19"] = {
            "description": "Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments",
            "result": {"Identity_Providers": [idp['Arn'] for idp in identity_providers],
                       "AWS_Organizations_Status": org_status},
            "explanation": explanation_2_19,
            "status": "PASS" if identity_providers or org_status['Available'] else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 2.19: {e}")
        results["2.19"] = {"description": "Ensure IAM users are managed centrally",
                           "result": str(e), "explanation": explanation_2_19, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_20(session, results, filepath):
    """2.20 – Ensure access to AWSCloudShellFullAccess is restricted."""
    iam = session.client('iam')
    roles_with_access = []
    try:
        paginator = iam.get_paginator('list_policies')
        for page in paginator.paginate(Scope='All'):
            for policy in page['Policies']:
                if policy['PolicyName'] == 'AWSCloudShellFullAccess':
                    entities = iam.list_entities_for_policy(PolicyArn=policy['Arn'])
                    roles_with_access = [r['RoleName'] for r in entities.get('PolicyRoles', [])]
                    roles_with_access += [u['UserName'] for u in entities.get('PolicyUsers', [])]
                    roles_with_access += [g['GroupName'] for g in entities.get('PolicyGroups', [])]
                    break
        results["2.20"] = {
            "description": "Ensure access to AWSCloudShellFullAccess is restricted",
            "result": {"Entities_With_CloudShellFullAccess": roles_with_access},
            "explanation": explanation_2_20,
            "status": "PASS" if not roles_with_access else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 2.20: {e}")
        results["2.20"] = {"description": "Ensure access to AWSCloudShellFullAccess is restricted",
                           "result": str(e), "explanation": explanation_2_20, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_2_21(session, results, filepath):
    """2.21 – Ensure AWS resource policies do not allow unrestricted access using 'Principal': '*'."""
    s3 = session.client('s3')
    violations = []
    try:
        buckets = s3.list_buckets().get('Buckets', [])
        for bucket in buckets:
            name = bucket['Name']
            try:
                policy_str = s3.get_bucket_policy(Bucket=name)['Policy']
                policy = json.loads(policy_str)
                for stmt in policy.get('Statement', []):
                    principal = stmt.get('Principal', '')
                    effect = stmt.get('Effect', '')
                    condition = stmt.get('Condition', None)
                    if effect == 'Allow' and (principal == '*' or principal == {'AWS': '*'}) and not condition:
                        violations.append({"Bucket": name, "Statement": stmt})
            except s3.exceptions.from_code('NoSuchBucketPolicy'):
                pass
            except Exception:
                pass
        results["2.21"] = {
            "description": "Ensure AWS resource policies do not allow unrestricted access using 'Principal': '*'",
            "result": violations if violations else "No resource policies with unrestricted '*' principal found.",
            "explanation": explanation_2_21,
            "status": "FAIL" if violations else "PASS"
        }
    except Exception as e:
        logger.error(f"Error in 2.21: {e}")
        results["2.21"] = {"description": "Ensure AWS resource policies do not allow unrestricted access using 'Principal': '*'",
                           "result": str(e), "explanation": explanation_2_21, "status": "ERROR"}
    write_results_to_file(results, filepath)


# ═══════════════════════════════════════════════════════════════════════════════
# Section 3 – Storage
# ═══════════════════════════════════════════════════════════════════════════════

def check_3_1_1(session, results, filepath):
    """3.1.1 – Ensure S3 Bucket Policy is set to deny HTTP requests."""
    s3 = session.client('s3')
    non_compliant = []
    try:
        buckets = s3.list_buckets().get('Buckets', [])
        for bucket in buckets:
            name = bucket['Name']
            try:
                region = s3.get_bucket_location(Bucket=name)['LocationConstraint'] or 'us-east-1'
                policy_str = s3.get_bucket_policy(Bucket=name)['Policy']
                policy = json.loads(policy_str)
                has_deny_http = any(
                    stmt.get('Effect') == 'Deny' and
                    stmt.get('Condition', {}).get('Bool', {}).get('aws:SecureTransport') == 'false'
                    for stmt in policy.get('Statement', [])
                )
                if not has_deny_http:
                    non_compliant.append({"BucketName": name, "Region": region, "Issue": "No HTTPS-enforce policy"})
            except Exception:
                non_compliant.append({"BucketName": name, "Issue": "No bucket policy or error"})
        results["3.1.1"] = {
            "description": "Ensure S3 Bucket Policy is set to deny HTTP requests",
            "result": non_compliant if non_compliant else "All buckets enforce HTTPS.",
            "explanation": explanation_3_1_1,
            "status": "PASS" if not non_compliant else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 3.1.1: {e}")
        results["3.1.1"] = {"description": "Ensure S3 Bucket Policy is set to deny HTTP requests",
                            "result": str(e), "explanation": explanation_3_1_1, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_3_1_2(session, results, filepath):
    """3.1.2 – Ensure MFA Delete is enabled on S3 buckets."""
    s3 = session.client('s3')
    non_compliant = []
    try:
        buckets = s3.list_buckets().get('Buckets', [])
        for bucket in buckets:
            name = bucket['Name']
            try:
                versioning = s3.get_bucket_versioning(Bucket=name)
                mfa_delete = versioning.get('MFADelete', 'Disabled')
                if mfa_delete != 'Enabled':
                    non_compliant.append({"BucketName": name, "MFADelete": mfa_delete})
            except Exception as e:
                non_compliant.append({"BucketName": name, "Error": str(e)})
        results["3.1.2"] = {
            "description": "Ensure MFA Delete is enabled on S3 buckets",
            "result": non_compliant if non_compliant else "MFA Delete is enabled on all buckets.",
            "explanation": explanation_3_1_2,
            "status": "PASS" if not non_compliant else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 3.1.2: {e}")
        results["3.1.2"] = {"description": "Ensure MFA Delete is enabled on S3 buckets",
                            "result": str(e), "explanation": explanation_3_1_2, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_3_1_4(session, results, filepath):
    """3.1.4 – Ensure that S3 is configured with 'Block Public Access' enabled."""
    s3 = session.client('s3')
    from botocore.exceptions import ClientError
    non_compliant = []
    try:
        buckets = s3.list_buckets().get('Buckets', [])
        for bucket in buckets:
            name = bucket['Name']
            try:
                region = s3.get_bucket_location(Bucket=name)['LocationConstraint'] or 'us-east-1'
                regional_s3 = session.client('s3', region_name=region)
                settings = regional_s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
                if not all([settings.get('BlockPublicAcls'), settings.get('IgnorePublicAcls'),
                            settings.get('BlockPublicPolicy'), settings.get('RestrictPublicBuckets')]):
                    non_compliant.append({"BucketName": name, "Region": region, "Settings": settings})
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    non_compliant.append({"BucketName": name, "Error": "No public access block configuration."})
                else:
                    non_compliant.append({"BucketName": name, "Error": str(e)})
        results["3.1.4"] = {
            "description": "Ensure that S3 Buckets are configured with 'Block Public Access' enabled",
            "result": non_compliant if non_compliant else "All buckets have public access blocked.",
            "explanation": explanation_3_1_4,
            "status": "PASS" if not non_compliant else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 3.1.4: {e}")
        results["3.1.4"] = {"description": "Ensure that S3 Buckets are configured with 'Block Public Access' enabled",
                            "result": str(e), "explanation": explanation_3_1_4, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_3_2_1(session, results, filepath, regions):
    """3.2.1 – Ensure that encryption-at-rest is enabled for RDS Instances."""
    unencrypted = []
    try:
        for region in regions:
            rds = session.client('rds', region_name=region)
            for page in rds.get_paginator('describe_db_instances').paginate():
                for inst in page['DBInstances']:
                    if not inst.get('StorageEncrypted'):
                        unencrypted.append({'Region': region, 'DBInstanceIdentifier': inst['DBInstanceIdentifier'],
                                            'StorageEncrypted': inst.get('StorageEncrypted')})
        results["3.2.1"] = {
            "description": "Ensure that encryption-at-rest is enabled for RDS Instances",
            "result": unencrypted if unencrypted else "All RDS instances are encrypted.",
            "explanation": explanation_3_2_1,
            "status": "PASS" if not unencrypted else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 3.2.1: {e}")
        results["3.2.1"] = {"description": "Ensure that encryption-at-rest is enabled for RDS Instances",
                            "result": str(e), "explanation": explanation_3_2_1, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_3_2_2(session, results, filepath, regions):
    """3.2.2 – Ensure the Auto Minor Version Upgrade feature is enabled for RDS instances."""
    non_compliant = []
    try:
        for region in regions:
            rds = session.client('rds', region_name=region)
            for page in rds.get_paginator('describe_db_instances').paginate():
                for inst in page['DBInstances']:
                    if not inst.get('AutoMinorVersionUpgrade'):
                        non_compliant.append({'Region': region, 'DBInstanceIdentifier': inst['DBInstanceIdentifier'],
                                              'AutoMinorVersionUpgrade': inst.get('AutoMinorVersionUpgrade')})
        results["3.2.2"] = {
            "description": "Ensure the Auto Minor Version Upgrade feature is enabled for RDS instances",
            "result": non_compliant if non_compliant else "All RDS instances have Auto Minor Version Upgrade enabled.",
            "explanation": explanation_3_2_2,
            "status": "PASS" if not non_compliant else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 3.2.2: {e}")
        results["3.2.2"] = {"description": "Ensure the Auto Minor Version Upgrade feature is enabled for RDS instances",
                            "result": str(e), "explanation": explanation_3_2_2, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_3_2_3(session, results, filepath, regions):
    """3.2.3 – Ensure that RDS instances are not publicly accessible."""
    public = []
    try:
        for region in regions:
            rds = session.client('rds', region_name=region)
            for page in rds.get_paginator('describe_db_instances').paginate():
                for inst in page['DBInstances']:
                    if inst.get('PubliclyAccessible'):
                        public.append({'Region': region, 'DBInstanceIdentifier': inst['DBInstanceIdentifier'],
                                       'PubliclyAccessible': True})
        results["3.2.3"] = {
            "description": "Ensure that RDS instances are not publicly accessible",
            "result": public if public else "No publicly accessible RDS instances found.",
            "explanation": explanation_3_2_3,
            "status": "PASS" if not public else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 3.2.3: {e}")
        results["3.2.3"] = {"description": "Ensure that RDS instances are not publicly accessible",
                            "result": str(e), "explanation": explanation_3_2_3, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_3_2_4(session, results, filepath, regions):
    """3.2.4 – Ensure Multi-AZ deployments are used for enhanced availability in Amazon RDS."""
    non_compliant = []
    try:
        for region in regions:
            rds = session.client('rds', region_name=region)
            for page in rds.get_paginator('describe_db_instances').paginate():
                for inst in page['DBInstances']:
                    if not inst.get('MultiAZ'):
                        non_compliant.append({'Region': region, 'DBInstanceIdentifier': inst['DBInstanceIdentifier'],
                                              'MultiAZ': inst.get('MultiAZ', False)})
        results["3.2.4"] = {
            "description": "Ensure Multi-AZ deployments are used for enhanced availability in Amazon RDS",
            "result": non_compliant if non_compliant else "All RDS instances use Multi-AZ deployments.",
            "explanation": explanation_3_2_4,
            "status": "PASS" if not non_compliant else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 3.2.4: {e}")
        results["3.2.4"] = {"description": "Ensure Multi-AZ deployments are used for enhanced availability in Amazon RDS",
                            "result": str(e), "explanation": explanation_3_2_4, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_3_3_1(session, results, filepath, regions):
    """3.3.1 – Ensure that encryption is enabled for EFS file systems."""
    unencrypted = {}
    try:
        for region in regions:
            efs = session.client('efs', region_name=region)
            for page in efs.get_paginator('describe_file_systems').paginate():
                for fs in page['FileSystems']:
                    if not fs.get('Encrypted'):
                        unencrypted.setdefault(region, []).append(
                            {"FileSystemId": fs['FileSystemId'], "Encrypted": fs.get('Encrypted', False)})
        if unencrypted:
            formatted = [f"Region: {r}, FileSystemId: {f['FileSystemId']}, Encrypted: {f['Encrypted']}"
                         for r, fss in unencrypted.items() for f in fss]
            results["3.3.1"] = {"description": "Ensure that encryption is enabled for EFS file systems",
                                 "result": formatted, "explanation": explanation_3_3_1, "status": "FAIL"}
        else:
            results["3.3.1"] = {"description": "Ensure that encryption is enabled for EFS file systems",
                                 "result": "Encryption is enabled for all EFS file systems.",
                                 "explanation": explanation_3_3_1, "status": "PASS"}
    except Exception as e:
        logger.error(f"Error in 3.3.1: {e}")
        results["3.3.1"] = {"description": "Ensure that encryption is enabled for EFS file systems",
                            "result": str(e), "explanation": explanation_3_3_1, "status": "ERROR"}
    write_results_to_file(results, filepath)


# ═══════════════════════════════════════════════════════════════════════════════
# Section 4 – Logging
# ═══════════════════════════════════════════════════════════════════════════════

def check_4_1(session, results, filepath, regions):
    """4.1 – Ensure CloudTrail is enabled in all regions."""
    missing = []
    try:
        for region in regions:
            ct = session.client('cloudtrail', region_name=region)
            trails = ct.describe_trails()['trailList']
            if trails:
                statuses = [ct.get_trail_status(Name=t['Name']) for t in trails]
                if not any(ts.get('IsLogging') for ts in statuses):
                    missing.append(region)
            else:
                missing.append(region)
        results["4.1"] = {
            "description": "Ensure CloudTrail is enabled in all regions",
            "result": missing if missing else "CloudTrail is enabled in all regions.",
            "explanation": explanation_4_1,
            "status": "PASS" if not missing else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 4.1: {e}")
        results["4.1"] = {"description": "Ensure CloudTrail is enabled in all regions",
                          "result": str(e), "explanation": explanation_4_1, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_4_2(session, results, filepath):
    """4.2 – Ensure CloudTrail log file validation is enabled."""
    ct = session.client('cloudtrail')
    without_validation = []
    try:
        for trail in ct.describe_trails()['trailList']:
            if not trail.get('LogFileValidationEnabled'):
                without_validation.append({"TrailName": trail['Name'],
                                           "LogFileValidationEnabled": trail.get('LogFileValidationEnabled', False)})
        results["4.2"] = {
            "description": "Ensure CloudTrail log file validation is enabled",
            "result": without_validation if without_validation else "All trails have log file validation enabled.",
            "explanation": explanation_4_2,
            "status": "PASS" if not without_validation else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 4.2: {e}")
        results["4.2"] = {"description": "Ensure CloudTrail log file validation is enabled",
                          "result": str(e), "explanation": explanation_4_2, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_4_3(session, results, filepath, regions):
    """4.3 – Ensure AWS Config is enabled in all regions."""
    region_statuses = []
    try:
        for region in regions:
            cfg = session.client('config', region_name=region)
            try:
                recording = cfg.describe_configuration_recorders()['ConfigurationRecorders'][0]['recording']
                region_statuses.append({"region": region, "recording": recording})
            except Exception:
                region_statuses.append({"region": region, "recording": False})
        non_configured = [r for r in region_statuses if not r.get('recording')]
        results["4.3"] = {
            "description": "Ensure AWS Config is enabled in all regions",
            "result": region_statuses,
            "explanation": explanation_4_3,
            "status": "PASS" if not non_configured else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 4.3: {e}")
        results["4.3"] = {"description": "Ensure AWS Config is enabled in all regions",
                          "result": str(e), "explanation": explanation_4_3, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_4_4(session, results, filepath):
    """4.4 – Ensure that server access logging is enabled on the CloudTrail S3 bucket."""
    ct = session.client('cloudtrail')
    s3 = session.client('s3')
    details = []
    try:
        for trail in ct.describe_trails()['trailList']:
            name = trail['S3BucketName']
            try:
                logging_enabled = s3.get_bucket_logging(Bucket=name).get('LoggingEnabled', None)
            except Exception as e:
                logging_enabled = str(e)
            details.append({'BucketName': name, 'LoggingEnabled': logging_enabled})
        without_logging = [d for d in details if not d.get('LoggingEnabled')]
        results["4.4"] = {
            "description": "Ensure that server access logging is enabled on the CloudTrail S3 bucket",
            "result": details,
            "explanation": explanation_4_4,
            "status": "PASS" if not without_logging else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 4.4: {e}")
        results["4.4"] = {"description": "Ensure that server access logging is enabled on the CloudTrail S3 bucket",
                          "result": str(e), "explanation": explanation_4_4, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_4_5(session, results, filepath):
    """4.5 – Ensure CloudTrail logs are encrypted at rest using KMS CMKs."""
    ct = session.client('cloudtrail')
    trail_details = []
    try:
        for trail in ct.describe_trails()['trailList']:
            kms_key = trail.get('KmsKeyId', None)
            trail_details.append({'TrailName': trail['Name'], 'KmsKeyId': kms_key})
        without_kms = [t for t in trail_details if not t.get('KmsKeyId')]
        results["4.5"] = {
            "description": "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
            "result": trail_details,
            "explanation": explanation_4_5,
            "status": "PASS" if not without_kms else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 4.5: {e}")
        results["4.5"] = {"description": "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
                          "result": str(e), "explanation": explanation_4_5, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_4_6(session, results, filepath):
    """4.6 – Ensure rotation for customer-created symmetric CMKs is enabled."""
    kms = session.client('kms')
    rotation_details = []
    try:
        rotation_details = []
        paginator = kms.get_paginator('list_keys')
        for page in paginator.paginate():
            for key in page['Keys']:
                meta = kms.describe_key(KeyId=key['KeyId'])['KeyMetadata']
                if meta.get('KeySpec') == 'SYMMETRIC_DEFAULT' and meta.get('KeyManager') == 'CUSTOMER':
                    rot = kms.get_key_rotation_status(KeyId=key['KeyId'])
                    rotation_details.append({'KeyId': key['KeyId'],
                                             'KeyRotationEnabled': rot['KeyRotationEnabled']})
        without_rotation = [k for k in rotation_details if not k.get('KeyRotationEnabled')]
        results["4.6"] = {
            "description": "Ensure rotation for customer-created symmetric CMKs is enabled",
            "result": rotation_details if rotation_details else "No customer-managed symmetric keys found.",
            "explanation": explanation_4_6,
            "status": "PASS" if not without_rotation else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 4.6: {e}")
        results["4.6"] = {"description": "Ensure rotation for customer-created symmetric CMKs is enabled",
                          "result": str(e), "explanation": explanation_4_6, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_4_7(session, results, filepath):
    """4.7 – Ensure VPC flow logging is enabled in all VPCs."""
    ec2 = session.client('ec2')
    try:
        all_vpcs = [v['VpcId'] for v in ec2.describe_vpcs()['Vpcs']]
        logged_vpcs = [fl['ResourceId'] for fl in ec2.describe_flow_logs()['FlowLogs']]
        missing = [v for v in all_vpcs if v not in logged_vpcs]
        results["4.7"] = {
            "description": "Ensure VPC flow logging is enabled in all VPCs",
            "result": [{"VPC": v} for v in missing] if missing else "Flow logging is enabled for all VPCs.",
            "explanation": explanation_4_7,
            "status": "PASS" if not missing else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 4.7: {e}")
        results["4.7"] = {"description": "Ensure VPC flow logging is enabled in all VPCs",
                          "result": str(e), "explanation": explanation_4_7, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_4_8(session, results, filepath):
    """4.8 – Ensure that object-level logging for write events is enabled for S3 buckets."""
    ct = session.client('cloudtrail')
    trail_details = []
    try:
        all_trails = ct.list_trails()['Trails']
        if not all_trails:
            results["4.8"] = {"description": "Ensure that object-level logging for write events is enabled for S3 buckets",
                              "result": "No CloudTrail trails configured.", "status": "FAIL"}
            write_results_to_file(results, filepath)
            return
        for ts in all_trails:
            name = ts['Name']
            try:
                config = ct.get_trail(Name=name).get('Trail', {})
                is_multi = config.get('IsMultiRegionTrail', False)
                selectors = ct.get_event_selectors(TrailName=name).get('EventSelectors', [])
                write_enabled = any(
                    sel.get('ReadWriteType') in ['WriteOnly', 'All']
                    for sel in selectors
                    if any(r.get('Type') == 'AWS::S3::Object' for r in sel.get('DataResources', []))
                )
                trail_details.append({"TrailName": name, "IsMultiRegionTrail": is_multi,
                                       "HasS3WriteEvents": write_enabled,
                                       "Compliant": is_multi and write_enabled})
            except Exception as e:
                trail_details.append({"TrailName": name, "Error": str(e)})
        non_compliant = [t for t in trail_details if not t.get("Compliant")]
        results["4.8"] = {
            "description": "Ensure that object-level logging for write events is enabled for S3 buckets",
            "result": {"TrailDetails": trail_details, "NonCompliantTrails": non_compliant},
            "explanation": explanation_4_8,
            "status": "PASS" if not non_compliant else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 4.8: {e}")
        results["4.8"] = {"description": "Ensure that object-level logging for write events is enabled for S3 buckets",
                          "result": {"Error": str(e)}, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_4_9(session, results, filepath):
    """4.9 – Ensure that object-level logging for read events is enabled for S3 buckets."""
    ct = session.client('cloudtrail')
    trail_details = []
    try:
        all_trails = ct.describe_trails()['trailList']
        if not all_trails:
            results["4.9"] = {"description": "Ensure that object-level logging for read events is enabled for S3 buckets",
                              "result": "No CloudTrail trails configured.", "status": "FAIL"}
            write_results_to_file(results, filepath)
            return
        for ts in all_trails:
            name = ts['Name']
            try:
                selectors = ct.get_event_selectors(TrailName=name).get('EventSelectors', [])
                read_enabled = any(
                    sel.get('ReadWriteType') in ['ReadOnly', 'All']
                    for sel in selectors
                    if any(r.get('Type') == 'AWS::S3::Object' for r in sel.get('DataResources', []))
                )
                trail_details.append({"TrailName": name, "TrailARN": ts['TrailARN'],
                                       "HasS3ReadEvents": read_enabled, "Compliant": read_enabled})
            except Exception as e:
                trail_details.append({"TrailName": name, "Error": str(e)})
        non_compliant = [t for t in trail_details if not t.get("Compliant")]
        results["4.9"] = {
            "description": "Ensure that object-level logging for read events is enabled for S3 buckets",
            "result": {"TrailDetails": trail_details, "NonCompliantTrails": non_compliant},
            "explanation": explanation_4_9,
            "status": "PASS" if not non_compliant else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 4.9: {e}")
        results["4.9"] = {"description": "Ensure that object-level logging for read events is enabled for S3 buckets",
                          "result": {"Error": str(e)}, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_4_10(session, results, filepath, regions):
    """4.10 – Ensure all AWS-managed web front-end services have access logging enabled."""
    violations = []
    try:
        # CloudFront (global)
        try:
            cf = session.client('cloudfront')
            paginator = cf.get_paginator('list_distributions')
            for page in paginator.paginate():
                for dist in page.get('DistributionList', {}).get('Items', []):
                    logging_cfg = dist.get('Logging', {})
                    if not logging_cfg.get('Enabled', False):
                        violations.append({'Service': 'CloudFront', 'Id': dist['Id'],
                                           'DomainName': dist.get('DomainName'), 'Issue': 'Access logging disabled'})
        except Exception as e:
            violations.append({'Service': 'CloudFront', 'Error': str(e)})

        for region in regions:
            # ALB / NLB
            try:
                elbv2 = session.client('elbv2', region_name=region)
                for page in elbv2.get_paginator('describe_load_balancers').paginate():
                    for lb in page['LoadBalancers']:
                        attrs = elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb['LoadBalancerArn'])['Attributes']
                        logging_enabled = any(
                            a['Key'] == 'access_logs.s3.enabled' and a['Value'] == 'true' for a in attrs
                        )
                        if not logging_enabled:
                            violations.append({'Service': f"ELB ({lb['Type']})", 'Region': region,
                                               'Name': lb['LoadBalancerName'], 'Issue': 'Access logging disabled'})
            except Exception as e:
                violations.append({'Service': 'ELB', 'Region': region, 'Error': str(e)})

            # API Gateway REST
            try:
                apigw = session.client('apigateway', region_name=region)
                for page in apigw.get_paginator('get_rest_apis').paginate():
                    for api in page['items']:
                        stages = apigw.get_stages(restApiId=api['id']).get('item', [])
                        for stage in stages:
                            if not stage.get('accessLogSettings', {}).get('destinationArn'):
                                violations.append({'Service': 'API Gateway REST', 'Region': region,
                                                   'ApiName': api['name'], 'Stage': stage['stageName'],
                                                   'Issue': 'Access logging not configured'})
            except Exception as e:
                violations.append({'Service': 'API Gateway REST', 'Region': region, 'Error': str(e)})

        results["4.10"] = {
            "description": "Ensure all AWS-managed web front-end services have access logging enabled",
            "result": violations if violations else "All web front-end services have access logging enabled.",
            "explanation": explanation_4_10,
            "status": "PASS" if not violations else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 4.10: {e}")
        results["4.10"] = {"description": "Ensure all AWS-managed web front-end services have access logging enabled",
                           "result": str(e), "explanation": explanation_4_10, "status": "ERROR"}
    write_results_to_file(results, filepath)


# ═══════════════════════════════════════════════════════════════════════════════
# Section 5 – Monitoring
# ═══════════════════════════════════════════════════════════════════════════════

def check_5_1(session, results, filepath, regions):
    """5.1 – Ensure unauthorized API calls are monitored."""
    try:
        for region in regions:
            ct = session.client('cloudtrail', region_name=region)
            logs = session.client('logs', region_name=region)
            cw = session.client('cloudwatch', region_name=region)
            sns = session.client('sns', region_name=region)

            trails = ct.describe_trails()['trailList']
            multi_trail = None
            for trail in trails:
                if trail.get('IsMultiRegionTrail') and region == trail['HomeRegion']:
                    status = ct.get_trail_status(Name=trail['Name'])
                    if not status.get('IsLogging'):
                        results["5.1"] = {"description": "Ensure unauthorized API calls are monitored",
                                          "result": {"message": f"Non-compliance in {region}: trail exists but IsLogging=FALSE.",
                                                     "trail": trail['Name']},
                                          "status": "FAIL"}
                        write_results_to_file(results, filepath)
                        return
                    multi_trail = trail
                    break

            if not multi_trail:
                continue

            log_group = multi_trail.get('CloudWatchLogsLogGroupArn', '')
            if not log_group:
                results["5.1"] = {"description": "Ensure unauthorized API calls are monitored",
                                  "result": {"message": f"No CW Logs log group on trail in {region}."},
                                  "status": "FAIL"}
                write_results_to_file(results, filepath)
                return

            log_group_name = log_group.split(':')[-1].split('*')[0]

            selectors = ct.get_event_selectors(TrailName=multi_trail['Name'])
            mgmt_events = any(
                s.get('IncludeManagementEvents') and s.get('ReadWriteType') == 'All'
                for s in selectors['EventSelectors']
            )
            if not mgmt_events:
                results["5.1"] = {"description": "Ensure unauthorized API calls are monitored",
                                  "result": {"message": f"No management event capture in {region}."},
                                  "status": "FAIL"}
                write_results_to_file(results, filepath)
                return

            filters = logs.describe_metric_filters(logGroupName=log_group_name)['metricFilters']
            metric_name = None
            for f in filters:
                if ('UnauthorizedOperation' in f['filterPattern'] or 'AccessDenied' in f['filterPattern']):
                    metric_name = f['metricTransformations'][0]['metricName']
                    break

            if not metric_name:
                results["5.1"] = {"description": "Ensure unauthorized API calls are monitored",
                                  "result": {"message": f"No metric filter for unauthorized calls in {region}."},
                                  "status": "FAIL"}
                write_results_to_file(results, filepath)
                return

            alarms = cw.describe_alarms(MetricName=metric_name)['MetricAlarms']
            if not alarms or not alarms[0].get('AlarmActions'):
                results["5.1"] = {"description": "Ensure unauthorized API calls are monitored",
                                  "result": {"message": f"No CloudWatch alarm for unauthorized calls in {region}."},
                                  "status": "FAIL"}
                write_results_to_file(results, filepath)
                return

        results["5.1"] = {"description": "Ensure unauthorized API calls are monitored",
                          "result": "Compliant across all regions.",
                          "explanation": explanation_5_1, "status": "PASS"}
    except Exception as e:
        logger.error(f"Error in 5.1: {e}")
        results["5.1"] = {"description": "Ensure unauthorized API calls are monitored",
                          "result": str(e), "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_5_16(session, results, filepath):
    """5.16 – Ensure AWS Security Hub is enabled."""
    sh = session.client('securityhub')
    try:
        sh.describe_hub()
        results["5.16"] = {"description": "Ensure AWS Security Hub is enabled",
                           "result": "AWS Security Hub is enabled.",
                           "explanation": explanation_5_16, "status": "PASS"}
    except sh.exceptions.InvalidAccessException:
        results["5.16"] = {"description": "Ensure AWS Security Hub is enabled",
                           "result": "AWS Security Hub is NOT enabled.",
                           "explanation": explanation_5_16, "status": "FAIL"}
    except Exception as e:
        logger.error(f"Error in 5.16: {e}")
        results["5.16"] = {"description": "Ensure AWS Security Hub is enabled",
                           "result": str(e), "explanation": explanation_5_16, "status": "ERROR"}
    write_results_to_file(results, filepath)


# ═══════════════════════════════════════════════════════════════════════════════
# Section 6 – Networking
# ═══════════════════════════════════════════════════════════════════════════════

def check_6_1_1(session, results, filepath, regions):
    """6.1.1 – Ensure EBS volume encryption is enabled in all regions."""
    non_compliant = []
    try:
        for region in regions:
            ec2 = session.client('ec2', region_name=region)
            try:
                if not ec2.get_ebs_encryption_by_default()['EbsEncryptionByDefault']:
                    non_compliant.append({'region': region, 'EbsEncryptionByDefault': False})
            except Exception as e:
                logger.warning(f"Error checking EBS encryption in {region}: {e}")
        results["6.1.1"] = {
            "description": "Ensure EBS volume encryption is enabled in all regions",
            "result": non_compliant if non_compliant else "All regions have EBS encryption enabled by default.",
            "explanation": explanation_6_1_1,
            "status": "PASS" if not non_compliant else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 6.1.1: {e}")
        results["6.1.1"] = {"description": "Ensure EBS volume encryption is enabled in all regions",
                            "result": str(e), "explanation": explanation_6_1_1, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_6_2(session, results, filepath):
    """6.2 – Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports."""
    ec2 = session.client('ec2')
    violations = []
    try:
        for page in ec2.get_paginator('describe_network_acls').paginate():
            for nacl in page['NetworkAcls']:
                for entry in nacl['Entries']:
                    if (not entry.get('Egress', True) and
                            entry.get('CidrBlock') == '0.0.0.0/0' and
                            entry.get('RuleAction', '').lower() == 'allow' and
                            entry.get('Protocol') in ['6', '17', '-1']):
                        if 'PortRange' in entry:
                            if (entry['PortRange']['From'] <= 22 <= entry['PortRange']['To'] or
                                    entry['PortRange']['From'] <= 3389 <= entry['PortRange']['To']):
                                violations.append({'NACL ID': nacl['NetworkAclId'],
                                                   'Rule Number': entry['RuleNumber'],
                                                   'Port From': entry['PortRange']['From'],
                                                   'Port To': entry['PortRange']['To'],
                                                   'CidrBlock': entry['CidrBlock']})
                        elif entry.get('Protocol') == '-1':
                            violations.append({'NACL ID': nacl['NetworkAclId'],
                                               'Rule Number': entry['RuleNumber'],
                                               'Protocol': '-1 (All)', 'CidrBlock': entry['CidrBlock']})
        results["6.2"] = {
            "description": "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports",
            "result": violations if violations else "No violating NACL entries found.",
            "explanation": explanation_6_2,
            "status": "PASS" if not violations else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 6.2: {e}")
        results["6.2"] = {"description": "Ensure no NACLs allow ingress from 0.0.0.0/0 to admin ports",
                          "result": str(e), "explanation": explanation_6_2, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_6_3(session, results, filepath):
    """6.3 – Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports."""
    ec2 = session.client('ec2')
    admin_ports = [22, 3389]
    violations = []
    try:
        for page in ec2.get_paginator('describe_security_groups').paginate():
            for sg in page['SecurityGroups']:
                for perm in sg['IpPermissions']:
                    if 'FromPort' in perm and 'ToPort' in perm:
                        for ip_range in perm.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                for port in admin_ports:
                                    if perm['FromPort'] <= port <= perm['ToPort']:
                                        violations.append({'Security Group ID': sg['GroupId'],
                                                           'Port Range': f"{perm['FromPort']}-{perm['ToPort']}",
                                                           'Protocol': perm.get('IpProtocol'),
                                                           'Allowed CIDR': ip_range['CidrIp']})
                                        break
        results["6.3"] = {
            "description": "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports",
            "result": violations if violations else "No security groups violate this policy.",
            "explanation": explanation_6_3,
            "status": "PASS" if not violations else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 6.3: {e}")
        results["6.3"] = {"description": "Ensure no security groups allow ingress from 0.0.0.0/0 to admin ports",
                          "result": str(e), "explanation": explanation_6_3, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_6_4(session, results, filepath):
    """6.4 – Ensure no security groups allow ingress from ::/0 to remote server administration ports."""
    ec2 = session.client('ec2')
    admin_ports = [22, 3389]
    violations = []
    try:
        for page in ec2.get_paginator('describe_security_groups').paginate():
            for sg in page['SecurityGroups']:
                for perm in sg['IpPermissions']:
                    for ipv6 in perm.get('Ipv6Ranges', []):
                        if ipv6.get('CidrIpv6') == '::/0':
                            port_range = range(perm.get('FromPort', 0), perm.get('ToPort', 0) + 1)
                            if any(p in admin_ports for p in port_range):
                                violations.append({'Security Group ID': sg['GroupId'],
                                                   'Ingress Permission': perm})
        results["6.4"] = {
            "description": "Ensure no security groups allow ingress from ::/0 to remote server administration ports",
            "result": violations if violations else "No violating security groups found.",
            "explanation": explanation_6_4,
            "status": "PASS" if not violations else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 6.4: {e}")
        results["6.4"] = {"description": "Ensure no security groups allow ingress from ::/0 to admin ports",
                          "result": str(e), "explanation": explanation_6_4, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_6_5(session, results, filepath):
    """6.5 – Ensure the default security group of every VPC restricts all traffic."""
    ec2 = session.client('ec2')
    violations = []
    try:
        for vpc_page in ec2.get_paginator('describe_vpcs').paginate():
            for vpc in vpc_page['Vpcs']:
                default_sg_id = None
                for sg_page in ec2.get_paginator('describe_security_groups').paginate(
                        Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}]):
                    for sg in sg_page['SecurityGroups']:
                        if sg['GroupName'] == 'default':
                            default_sg_id = sg['GroupId']
                            break
                if default_sg_id:
                    sg_detail = ec2.describe_security_groups(GroupIds=[default_sg_id])['SecurityGroups'][0]
                    if sg_detail['IpPermissions']:
                        violations.append({'VPC_ID': vpc['VpcId'], 'SecurityGroup_ID': default_sg_id,
                                           'Violation': 'Unrestricted Ingress',
                                           'Ingress_Rules': sg_detail['IpPermissions']})
                    if sg_detail['IpPermissionsEgress']:
                        violations.append({'VPC_ID': vpc['VpcId'], 'SecurityGroup_ID': default_sg_id,
                                           'Violation': 'Unrestricted Egress',
                                           'Egress_Rules': sg_detail['IpPermissionsEgress']})
        results["6.5"] = {
            "description": "Ensure the default security group of every VPC restricts all traffic",
            "result": violations if violations else "All default security groups restrict all traffic.",
            "explanation": explanation_6_5,
            "status": "PASS" if not violations else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 6.5: {e}")
        results["6.5"] = {"description": "Ensure the default security group of every VPC restricts all traffic",
                          "result": str(e), "explanation": explanation_6_5, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_6_6(session, results, filepath):
    """6.6 – Ensure routing tables for VPC peering are 'least access'."""
    ec2 = session.client('ec2')
    violations = []
    try:
        route_tables = []
        for page in ec2.get_paginator('describe_route_tables').paginate():
            route_tables.extend(page['RouteTables'])
        for page in ec2.get_paginator('describe_vpc_peering_connections').paginate():
            for conn in page['VpcPeeringConnections']:
                pid = conn['VpcPeeringConnectionId']
                for rt in route_tables:
                    for route in rt['Routes']:
                        if route.get('VpcPeeringConnectionId') == pid:
                            if route.get('DestinationCidrBlock') == '0.0.0.0/0' or \
                                    route.get('DestinationIpv6CidrBlock') == '::/0':
                                violations.append({'PeeringConnectionId': pid,
                                                   'RouteTableId': rt['RouteTableId'], 'Route': route})
        results["6.6"] = {
            "description": "Ensure routing tables for VPC peering are 'least access'",
            "result": violations if violations else "All VPC peering routing tables use least access.",
            "explanation": explanation_6_6,
            "status": "PASS" if not violations else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 6.6: {e}")
        results["6.6"] = {"description": "Ensure routing tables for VPC peering are 'least access'",
                          "result": str(e), "explanation": explanation_6_6, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_6_7(session, results, filepath):
    """6.7 – Ensure that the EC2 Metadata Service only allows IMDSv2."""
    ec2 = session.client('ec2')
    violations = []
    try:
        for page in ec2.get_paginator('describe_instances').paginate():
            for res in page['Reservations']:
                for inst in res['Instances']:
                    http_tokens = inst.get('MetadataOptions', {}).get('HttpTokens', '')
                    if http_tokens != 'required':
                        violations.append({'InstanceId': inst['InstanceId'], 'HttpTokensValue': http_tokens})
        results["6.7"] = {
            "description": "Ensure that the EC2 Metadata Service only allows IMDSv2",
            "result": violations if violations else "All EC2 instances use IMDSv2.",
            "explanation": explanation_6_7,
            "status": "PASS" if not violations else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 6.7: {e}")
        results["6.7"] = {"description": "Ensure that the EC2 Metadata Service only allows IMDSv2",
                          "result": str(e), "explanation": explanation_6_7, "status": "ERROR"}
    write_results_to_file(results, filepath)


def check_6_8(session, results, filepath, regions):
    """6.8 – Ensure VPC Endpoints are used for access to AWS Services."""
    violations = []
    try:
        for region in regions:
            ec2 = session.client('ec2', region_name=region)
            vpcs = [v['VpcId'] for v in ec2.describe_vpcs()['Vpcs']]
            endpoints = ec2.describe_vpc_endpoints()['VpcEndpoints']
            vpcs_with_endpoints = set(ep['VpcId'] for ep in endpoints)
            for vpc_id in vpcs:
                if vpc_id not in vpcs_with_endpoints:
                    violations.append({'Region': region, 'VpcId': vpc_id,
                                       'Issue': 'No VPC endpoints configured'})
        results["6.8"] = {
            "description": "Ensure VPC Endpoints are used for access to AWS Services",
            "result": violations if violations else "All VPCs have at least one VPC endpoint configured.",
            "explanation": explanation_6_8,
            "status": "PASS" if not violations else "FAIL"
        }
    except Exception as e:
        logger.error(f"Error in 6.8: {e}")
        results["6.8"] = {"description": "Ensure VPC Endpoints are used for access to AWS Services",
                          "result": str(e), "explanation": explanation_6_8, "status": "ERROR"}
    write_results_to_file(results, filepath)


# ═══════════════════════════════════════════════════════════════════════════════
# HTML + Screenshot (unchanged from original)
# ═══════════════════════════════════════════════════════════════════════════════

def generate_html(results):
    html_content = """
    <html>
    <head>
        <link href="https://fonts.googleapis.com/css2?family=Fira+Code&display=swap" rel="stylesheet">
        <style>
            details { 
                border: 1px solid #aaa; 
                border-radius: 4px; 
                margin: 0.5em 0; 
                padding: 0.5em;
            }
            details > summary { 
                font-weight: bold; 
                cursor: pointer; 
                background-color: #fff; 
            }
            details > summary:hover { 
                background-color: #f0f0f0; 
            }
            .fail { color: red; }
            .pass { color: green; }
            details[open] pre {
                background-color: #23252e; 
                white-space: pre-wrap; 
                word-wrap: break-word; 
                font-family: 'Fira Code', monospace;
                font-size: 15px;
                color: white; 
                margin: 0;
                padding: 0.5em; 
                max-height: 600px; 
                overflow: auto; 
            }
            pre { 
                white-space: pre-wrap; 
                word-wrap: break-word; 
                font-family: 'Fira Code', monospace;
                margin: 0;
                padding: 0.5em;
            }
        </style>
    </head>
    <body>
    """
    for key, value in results.items():
        status_class = 'pass' if value.get('status') == 'PASS' else 'fail'
        result_content = json.dumps(value.get('result'), indent=4, default=datetime_handler) \
            if isinstance(value.get('result'), (dict, list)) else value.get('result')
        explanation = value.get('explanation', '')
        html_content += f"""
        <details>
            <summary class="{status_class}">
                <strong>{key}:</strong> {value.get('description')} ({value.get('status')})
            </summary>
            <p><strong>{explanation}</strong</p> 
            <pre>{result_content}</pre>
        </details>
        """
    html_content += """
    </body>
    </html>
    """
    return html_content


def sanitize_filename(text):
    return text.replace(':', '_').replace(' ', '_').replace('.', '_').replace('/', '_')


def capture_screenshot(url, output_dir):
    options = webdriver.FirefoxOptions()
    options.add_argument("--headless")

    service = FirefoxService(executable_path=GeckoDriverManager().install())
    driver = webdriver.Firefox(service=service, options=options)
    driver.get(url)

    try:
        details_elements = WebDriverWait(driver, 10).until(
            EC.presence_of_all_elements_located((By.CSS_SELECTOR, "details"))
        )

        for index, detail in enumerate(details_elements, start=1):
            summary = detail.find_element(By.TAG_NAME, "summary")
            if 'fail' in summary.get_attribute("class"):
                WebDriverWait(driver, 10).until(EC.element_to_be_clickable(summary))
                summary.click()

                pre_element = WebDriverWait(driver, 10).until(
                    EC.visibility_of(detail.find_element(By.TAG_NAME, "pre"))
                )

                summary_text = sanitize_filename(summary.text)
                screenshot_path = os.path.join(output_dir, f"{summary_text}_screenshot_{index}.png")

                screenshot = pre_element.screenshot_as_png
                screenshot = Image.open(BytesIO(screenshot))
                cropped_screenshot = screenshot.crop((0, 1, screenshot.width - 20, screenshot.height))
                cropped_screenshot.save(screenshot_path)

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        driver.quit()


# ═══════════════════════════════════════════════════════════════════════════════
# Check dispatch table builder
# ═══════════════════════════════════════════════════════════════════════════════

def build_check_functions(session, results, filepath, regions):
    return {
        "2.4":   lambda: check_2_4(session, results, filepath),
        "2.5":   lambda: check_2_5(session, results, filepath),
        "2.6":   lambda: check_2_6(session, results, filepath),
        "2.7":   lambda: check_2_7(session, results, filepath),
        "2.8":   lambda: check_2_8(session, results, filepath),
        "2.9":   lambda: check_2_9(session, results, filepath),
        "2.10":  lambda: check_2_10(session, results, filepath),
        "2.11":  lambda: check_2_11(session, results, filepath),
        "2.12":  lambda: check_2_12(session, results, filepath),
        "2.13":  lambda: check_2_13(session, results, filepath),
        "2.14":  lambda: check_2_14(session, results, filepath),
        "2.15":  lambda: check_2_15(session, results, filepath),
        "2.16":  lambda: check_2_16(session, results, filepath),
        "2.17":  lambda: check_2_17(session, results, filepath),
        "2.18":  lambda: check_2_18(session, results, filepath, regions),
        "2.19":  lambda: check_2_19(session, results, filepath),
        "2.20":  lambda: check_2_20(session, results, filepath),
        "2.21":  lambda: check_2_21(session, results, filepath),
        "3.1.1": lambda: check_3_1_1(session, results, filepath),
        "3.1.2": lambda: check_3_1_2(session, results, filepath),
        "3.1.4": lambda: check_3_1_4(session, results, filepath),
        "3.2.1": lambda: check_3_2_1(session, results, filepath, regions),
        "3.2.2": lambda: check_3_2_2(session, results, filepath, regions),
        "3.2.3": lambda: check_3_2_3(session, results, filepath, regions),
        "3.2.4": lambda: check_3_2_4(session, results, filepath, regions),
        "3.3.1": lambda: check_3_3_1(session, results, filepath, regions),
        "4.1":   lambda: check_4_1(session, results, filepath, regions),
        "4.2":   lambda: check_4_2(session, results, filepath),
        "4.3":   lambda: check_4_3(session, results, filepath, regions),
        "4.4":   lambda: check_4_4(session, results, filepath),
        "4.5":   lambda: check_4_5(session, results, filepath),
        "4.6":   lambda: check_4_6(session, results, filepath),
        "4.7":   lambda: check_4_7(session, results, filepath),
        "4.8":   lambda: check_4_8(session, results, filepath),
        "4.9":   lambda: check_4_9(session, results, filepath),
        "4.10":  lambda: check_4_10(session, results, filepath, regions),
        "5.1":   lambda: check_5_1(session, results, filepath, regions),
        "5.16":  lambda: check_5_16(session, results, filepath),
        "6.1.1": lambda: check_6_1_1(session, results, filepath, regions),
        "6.2":   lambda: check_6_2(session, results, filepath),
        "6.3":   lambda: check_6_3(session, results, filepath),
        "6.4":   lambda: check_6_4(session, results, filepath),
        "6.5":   lambda: check_6_5(session, results, filepath),
        "6.6":   lambda: check_6_6(session, results, filepath),
        "6.7":   lambda: check_6_7(session, results, filepath),
        "6.8":   lambda: check_6_8(session, results, filepath, regions),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Per-account audit runner
# ═══════════════════════════════════════════════════════════════════════════════

def run_audit_for_account(session, account_label):
    """Run all checks for one account and produce output files."""
    global _current_account_id
    results = {}
    regions = get_regions(session)

    # Set the module-level account identifier used in the asset field of every finding
    try:
        _current_account_id = session.client('sts').get_caller_identity()['Account']
    except Exception:
        _current_account_id = account_label

    # Determine output directory
    output_dir = os.path.join(os.getcwd(), account_label)
    os.makedirs(output_dir, exist_ok=True)
    results_json_path = os.path.join(output_dir, "results.json")
    results_html_path = os.path.join(output_dir, "results.html")
    screenshots_dir = os.path.join(output_dir, "screenshots")

    print(f"\n{'='*60}")
    print(f"  Auditing account: {account_label}")
    print(f"  Output directory: {output_dir}")
    print(f"{'='*60}")

    check_functions = build_check_functions(session, results, results_json_path, regions)

    if args.check:
        if args.check in check_functions:
            print(f"Performing Check {args.check}")
            check_functions[args.check]()
        else:
            print(f"Invalid check number: {args.check}")
            return
    else:
        for check_number, fn in check_functions.items():
            print(f"  Performing Check {check_number}")
            fn()

    # Write HTML
    html_data = generate_html(results)
    with open(results_html_path, 'w') as f:
        f.write(html_data)
    print(f"  HTML report written: {results_html_path}")

    # Screenshots
    if args.screenshot:
        print(f"  Capturing screenshots for {account_label}...")
        os.makedirs(screenshots_dir, exist_ok=True)
        capture_screenshot(f"file:///{results_html_path}", screenshots_dir)

    print(f"  Scan complete for {account_label}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# main()
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    base_session = get_base_session()

    # ── Validate multi-account args ──────────────────────────────────────────
    if args.accounts and not args.role:
        print("ERROR: --accounts requires --role to be specified.")
        sys.exit(1)
    if args.role and not args.accounts:
        print("ERROR: --role requires --accounts to be specified.")
        sys.exit(1)

    # ── html-only mode ───────────────────────────────────────────────────────
    if args.html_only:
        # Regenerate from existing results.json files in account subdirectories,
        # or from results.json in cwd if no accounts provided.
        targets = []
        if args.accounts:
            for acct in args.accounts.split(","):
                acct = acct.strip()
                acct_dir = os.path.join(os.getcwd(), acct)
                json_path = os.path.join(acct_dir, "results.json")
                html_path = os.path.join(acct_dir, "results.html")
                targets.append((acct, acct_dir, json_path, html_path))
        else:
            label = args.profile if args.profile != 'default' else "default_account"
            acct_dir = os.path.join(os.getcwd(), label)
            targets.append((label, acct_dir,
                            os.path.join(acct_dir, "results.json"),
                            os.path.join(acct_dir, "results.html")))

        for label, acct_dir, json_path, html_path in targets:
            if os.path.exists(json_path):
                with open(json_path, 'r') as f:
                    results = json.load(f)
                html_data = generate_html(results)
                with open(html_path, 'w') as f:
                    f.write(html_data)
                print(f"HTML regenerated for {label}: {html_path}")
                if args.screenshot:
                    screenshots_dir = os.path.join(acct_dir, "screenshots")
                    os.makedirs(screenshots_dir, exist_ok=True)
                    capture_screenshot(f"file:///{html_path}", screenshots_dir)
            else:
                print(f"ERROR: {json_path} not found. Run checks first.")
        return

    # ── Multi-account mode ───────────────────────────────────────────────────
    if args.accounts and args.role:
        sts_identity = base_session.client('sts').get_caller_identity()
        print(f"Caller ARN: {sts_identity['Arn']}")
        print(f"Accounts to audit: {args.accounts}")
        print(f"Role to assume: {args.role}")

        for account_id in args.accounts.split(","):
            account_id = account_id.strip()
            role_arn = args.role.replace("{account}", account_id)
            # If role doesn't contain an account ID, build the full ARN
            if not role_arn.startswith("arn:"):
                role_arn = f"arn:aws:iam::{account_id}:role/{args.role}"
            try:
                assumed_session = assume_role_session(base_session, role_arn, account_id)
                run_audit_for_account(assumed_session, account_id)
            except Exception as e:
                print(f"ERROR: Could not assume role for account {account_id}: {e}")
                logger.error(f"Failed to assume role for {account_id}: {e}")
        return

    # ── Single-account mode ──────────────────────────────────────────────────
    sts_identity = base_session.client('sts').get_caller_identity()
    print(f"Running with ARN: {sts_identity['Arn']}")
    label = args.profile if args.profile != 'default' else sts_identity['Account']
    run_audit_for_account(base_session, label)


if __name__ == "__main__":
    main()
