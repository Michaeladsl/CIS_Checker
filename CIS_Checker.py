#!/bin/python3
# CIS 2.0.0 Check for AWS
# Author: Michael Raines

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



parser = argparse.ArgumentParser(description="Run AWS security compliance checks.")
parser.add_argument("--check", help="Specify the check to run, e.g., 1.4.")
parser.add_argument("--profile", default="default", help="Specify the AWS profile to use (default: 'default').")
parser.add_argument("--regions", type=str, help="Comma-separated list of AWS regions.")
parser.add_argument("--html-only", action="store_true", help="Regenerate the HTML report without running checks.")
args = parser.parse_args()

profile_name = args.profile

session = boto3.Session(profile_name=profile_name)



DEFAULT_REGIONS = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]

if args.regions:
    regions = args.regions.split(",")
else:
    try:
        regions = [region['RegionName'] for region in session.client('ec2').describe_regions()['Regions']]
    except botocore.exceptions.ClientError as e:
        print(f"Error fetching AWS regions dynamically: {e}")
        print(f"Falling back to default regions: {', '.join(DEFAULT_REGIONS)}")
        regions = DEFAULT_REGIONS



'''# Old Argparse, no --profile
if len(sys.argv) > 1:
    profile_name = sys.argv[1]
else:
    profile_name = 'default'

session = boto3.Session(profile_name=profile_name)
'''




sts_client = session.client('sts')
caller_identity = sts_client.get_caller_identity()
arn = caller_identity["Arn"]
print(f"Running script with ARN: {arn}")

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




# ORIGINAL WRITE FUNCTION - WORKING
def write_results_to_file(results):
    def datetime_handler(x):
        if isinstance(x, datetime.datetime):
            return x.isoformat()
        raise TypeError("Unknown type")

    with open("results.json", "w") as outfile:
        json.dump(results, outfile, indent=4, default=datetime_handler)



explanation_1_4 = "The root account should not have any access keys associated with it."
explanation_1_5 = "If AccountMFAEnabled contains a value of 0, MFA is not enabled for the root user."
explanation_1_6 = "If VirtualMFA contains ARN with the name 'root' in it, virtual MFA is used."
explanation_1_7 = "There is no described time to be under but is set to fail if the root user has been used within 90 days."
explanation_1_8 = "MinimumPasswordLength should be 14 or greater."
explanation_1_9 = "PasswordReusePrevention should be 24 or higher."
explanation_1_10 = "If HasConsolePassword is true, MFAActive must also be true."
explanation_1_11 = "If AccessKeyLastUsedDate is null, the key may have been created at the same time as the account."
explanation_1_12 = "Users where LastUsedDate has a value of 45 days or greater should be disabled."
explanation_1_13 = "Users should only have one active access key."
explanation_1_14 = "CreateDate should not contain a value greater than 90 days."
explanation_1_15 = "Users should not have attached policies."
explanation_1_16 = "Users should follow the concept of least privilege and should not receive full admin privileges"
explanation_1_17 = "If PolicyRoles returns an empty value, a role has not been set."
explanation_1_18 = "An IAM instance role should be applied to every instance."
explanation_1_19 = "Expired certificates should be removed from IAM to avoid accidental use."
explanation_1_20 = "Access Analyzer should be enabled in all regions."
explanation_1_21 = "IAM users should be managed through an identity provider."
explanation_1_22 = "Roles_With_AWSCloudShellFullAccess should be empty to ensure users do not have full access to cloud shell."
explanation_2_1_1 = "Effect should be set to deny and aws:SecureTransport should be false."
explanation_2_1_2 = "MFADelete should be enabled for all S3 buckets."
explanation_2_1_4 = "A public access block should be present and not set to false."
explanation_2_2_1 = "StorageEncrypted should return a value of true to ensure storage buckets are encrypted at rest."
explanation_2_2_2 = "AutoMinorVersionUpgrade should return a value of true to ensure minor version upgrades are automated."
explanation_2_2_3 = "The PubliclyAccessible flag should be set false to ensure RDS instances are not publically accessible."
explanation_2_3_1 = "Each EFS filesystem should be encrypted."
explanation_3_1 = "CloudTrails should be enabled for all regions."
explanation_3_2 = "CloudTrail Log File Validation should be enabled."
explanation_3_3 = "Recording should not return a valur of false"
explanation_3_4 = "LoggingEnabled should not return a null value."
explanation_3_5 = "KmsKeyId should return the arn of the kms access key."
explanation_3_6 = "KeyRotationEnabled should return a value of true."
explanation_3_7 = "Every VPC ID returned does not have flow logging enabled."
explanation_3_8 = "HasS3WriteEvents should have a value of true."
explanation_3_9 = "HasS3ReadEvents should have a value of true."
explanation_4_1 = ""
explanation_4_16 = "AWS Security hub should be enabled."
explanation_5_1_1 = "EbsEncryptionByDefault should be set to true."
explanation_5_1 = ""
explanation_5_2 = ""
explanation_5_3 = ""
explanation_5_4 = "This should be disabled to encourage security group deveilopment with least privilege in mind."
explanation_5_5 = ""
explanation_5_6 = ""
explanation_5_7 = ""


iam = session.client('iam')

def check_root_access_keys_and_update_results(session, results, explanation_1_4):
    """
    Checks for root access keys and updates the results dictionary.
    """
    iam = session.client('iam')
    account_summary = iam.get_account_summary()
    keys_present = account_summary.get('SummaryMap', {}).get('AccountAccessKeysPresent', 0)

    if keys_present:
        results["1.4"] = {
            "description": "Ensure no 'root' user account access key exists",
            "result": {
                "message": "Root access keys detected!",
                "AccountAccessKeysPresent": keys_present
            },
            "explanation": explanation_1_4,
            "status": "FAIL"
        }
    else:
        results["1.4"] = {
            "description": "Ensure no 'root' user account access key exists",
            "result": "No root access keys found.",
            "explanation": explanation_1_4,
            "status": "PASS"
        }

    write_results_to_file(results)



def check_root_user_mfa(session, results, explanation_1_5):

    iam_client = session.client('iam')
    account_summary = iam_client.get_account_summary()
    mfa_enabled_value = account_summary['SummaryMap']['AccountMFAEnabled']

    results["1.5"] = {
        "description": "Ensure MFA is enabled for the 'root' user account",
        "result": {
            "AccountMFAEnabled": mfa_enabled_value,
            "message": "MFA is enabled for the root user account." if mfa_enabled_value == 1 else "MFA is not enabled for the root user account!"
        },
        "explanation": explanation_1_5,
        "status": "PASS" if mfa_enabled_value == 1 else "FAIL"
    }

    write_results_to_file(results)



def check_root_virtual_mfa(session, results):
    """
    Checks if a hardware MFA device is enabled for the root user and updates the results dictionary.
    """
    iam_client = session.client('iam')

    try:
        virtual_mfas = iam_client.list_virtual_mfa_devices()
        root_has_mfa = any('root' in mfa['SerialNumber'] for mfa in virtual_mfas.get('VirtualMFADevices', []))

        results["1.6"] = {
            "description": "Ensure hardware MFA is enabled for the 'root' user account",
            "result": {
                "root_has_mfa": root_has_mfa,
                "virtual_mfas": virtual_mfas.get('VirtualMFADevices', [])
            },
            "status": "FAIL" if root_has_mfa else "PASS"
        }

    except Exception as e:
        logger.error(f"Error in Root Virtual MFA check: {str(e)}")
        results["1.6"] = {
            "description": "Ensure hardware MFA is enabled for the 'root' user account",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }

    write_results_to_file(results)




def check_root_user_last_activity_and_update_results(session, results, explanation_1_7):
    """
    Checks the last activity of the root user and updates the results dictionary.
    """
    client = session.client('iam')
    root_user_activity = {
        "LastUsedDate": "Never Used",
        "LastUsedService": "N/A",
        "LastUsedRegion": "N/A"
    }

    try:
        response = client.get_account_summary()
        summary_map = response['SummaryMap']

        # Check if the root user was ever used
        if 'RootUserLastUsedDate' in summary_map:
            last_used_date = summary_map['RootUserLastUsedDate']
            if last_used_date:
                root_user_activity['LastUsedDate'] = last_used_date.strftime('%Y-%m-%d %H:%M:%S')
                root_user_activity['LastUsedService'] = summary_map.get('RootUserLastUsedService', 'N/A')
                root_user_activity['LastUsedRegion'] = summary_map.get('RootUserLastUsedRegion', 'N/A')

        # Determine status
        if root_user_activity["LastUsedDate"] == "Never Used":
            status = "PASS"
        else:
            last_used_datetime = datetime.strptime(root_user_activity["LastUsedDate"], '%Y-%m-%d %H:%M:%S')
            status = "PASS" if (datetime.utcnow() - last_used_datetime).days > 90 else "FAIL"

    except Exception as e:
        print(f"Error fetching root user last activity details: {str(e)}")
        root_user_activity["Error"] = str(e)
        status = "ERROR"

    results["1.7"] = {
        "description": "Eliminate use of the 'root' user for administrative and daily tasks",
        "result": root_user_activity,
        "explanation": explanation_1_7,
        "status": status
    }

    write_results_to_file(results)


def check_password_policy_and_update_results(session, results, explanation_1_8):
    """
    Checks the IAM password policy minimum length and updates the results dictionary.
    """
    client = session.client('iam')
    password_policy_details = None

    try:
        password_policy = client.get_account_password_policy()
        if 'MinimumPasswordLength' in password_policy['PasswordPolicy']:
            password_policy_details = {
                "MinimumPasswordLength": password_policy['PasswordPolicy']['MinimumPasswordLength']
            }
    except Exception as e:
        print(f"Error fetching password policy details: {str(e)}")
        password_policy_details = {"Error": str(e)}

    results["1.8"] = {
        "description": "Ensure IAM password policy requires minimum length of 14 or greater",
        "result": password_policy_details,
        "explanation": explanation_1_8,
        "status": "PASS" if password_policy_details and password_policy_details.get("MinimumPasswordLength", 0) >= 14 else "FAIL"
    }

    write_results_to_file(results)




def check_password_reuse_prevention_and_update_results(session, results, explanation_1_9):
    """
    Checks IAM password policy for password reuse prevention and updates the results dictionary.
    """
    iam_client = session.client('iam')

    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy', {})
        reuse_prevention_value = password_policy.get('PasswordReusePrevention', 0)

        results["1.9"] = {
            "description": "Ensure IAM password policy prevents password reuse.",
            "result": password_policy,
            "explanation": explanation_1_9,
            "status": "PASS" if reuse_prevention_value and reuse_prevention_value >= 24 else "FAIL"
        }

    except Exception as e:
        logger.error(f"Error in 1.9 check: {str(e)}")
        results["1.9"] = {
            "description": "Ensure IAM password policy prevents password reuse.",
            "result": f"Error occurred during check: {str(e)}",
            "explanation": explanation_1_9,
            "status": "ERROR"
        }

    write_results_to_file(results)


def check_mfa_on_users_and_update_results(session, results, explanation_1_10):
    """
    Checks if MFA is enabled for all IAM users with console access and updates the results dictionary.
    """
    client = session.client('iam')
    paginator = client.get_paginator('list_users')
    non_compliant_users = []

    try:
        for page in paginator.paginate():
            for user in page['Users']:
                login_profile_exists = False
                mfa_active = False

                try:
                    client.get_login_profile(UserName=user['UserName'])
                    login_profile_exists = True
                except:
                    login_profile_exists = False

                mfa_devices = client.list_mfa_devices(UserName=user['UserName'])
                if mfa_devices['MFADevices']:
                    mfa_active = True

                if login_profile_exists and not mfa_active:
                    non_compliant_users.append({
                        "User": user['UserName'],
                        "HasConsolePassword": login_profile_exists,
                        "MFAActive": mfa_active
                    })

        results["1.10"] = {
            "description": "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
            "result": non_compliant_users,
            "explanation": explanation_1_10,
            "status": "PASS" if not non_compliant_users else "FAIL"
        }

    except Exception as e:
        logger.error(f"Error in 1.10 check: {str(e)}")
        results["1.10"] = {
            "description": "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
            "result": f"Error occurred during check: {str(e)}",
            "explanation": explanation_1_10,
            "status": "ERROR"
        }

    write_results_to_file(results)



def check_initial_user_setup_violations_and_update_results(session, results, explanation_1_11):
    """
    Checks for violations of access key setups during initial user creation and updates the results dictionary.
    """
    client = session.client('iam')
    violating_users = []

    try:
        users = client.list_users()

        for user in users['Users']:
            username = user['UserName']
            login_profile_exists = True

            try:
                client.get_login_profile(UserName=username)
            except client.exceptions.NoSuchEntityException:
                login_profile_exists = False

            if login_profile_exists:
                access_keys = client.list_access_keys(UserName=username)
                for key_metadata in access_keys['AccessKeyMetadata']:
                    if key_metadata['Status'] == 'Active':
                        access_key_id = key_metadata['AccessKeyId']
                        key_last_used_info = client.get_access_key_last_used(AccessKeyId=access_key_id)
                        last_used_date = key_last_used_info.get('AccessKeyLastUsed', {}).get('LastUsedDate')

                        if not last_used_date:
                            violating_users.append({
                                "UserName": username,
                                "password_enabled": login_profile_exists,
                                "AccessKeyId": access_key_id,
                                "CreateDate": str(key_metadata['CreateDate']),
                                "AccessKeyLastUsedDate": None
                            })

        results["1.11"] = {
            "description": "Do not setup access keys during initial user setup for all IAM users that have a console password",
            "result": violating_users if violating_users else "All users comply.",
            "explanation": explanation_1_11,
            "status": "PASS" if not violating_users else "FAIL"
        }

    except Exception as e:
        logger.error(f"Error in 1.11 check: {str(e)}")
        results["1.11"] = {
            "description": "Do not setup access keys during initial user setup for all IAM users that have a console password",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }

    write_results_to_file(results)




def check_credentials_unused_and_update_results(session, results, explanation_1_12):
    """
    Checks for IAM credentials unused for 45 days or more and updates the results dictionary.
    """
    client = session.client('iam')
    non_compliant_users = []

    try:
        users = client.list_users()

        for user in users['Users']:
            access_keys = client.list_access_keys(UserName=user['UserName'])

            for key in access_keys['AccessKeyMetadata']:
                last_used_info = client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                last_used_date = last_used_info.get('AccessKeyLastUsed', {}).get('LastUsedDate', key['CreateDate'])

                days_since_last_use = (datetime.datetime.now(datetime.timezone.utc) - last_used_date).days

                if days_since_last_use > 45:
                    non_compliant_users.append({
                        "User": user['UserName'],
                        "LastUsedDate": last_used_date.strftime('%Y-%m-%d %H:%M:%S UTC')
                    })
                    break  # Stop checking other keys for this user

        results["1.12"] = {
            "description": "Ensure credentials unused for 45 days or greater are disabled",
            "result": non_compliant_users,
            "explanation": explanation_1_12,
            "status": "PASS" if not non_compliant_users else "FAIL"
        }

    except Exception as e:
        logger.error(f"Error in 1.12 check: {str(e)}")
        results["1.12"] = {
            "description": "Ensure credentials unused for 45 days or greater are disabled",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }

    write_results_to_file(results)



def check_single_active_access_key_and_update_results(session, results, explanation_1_13):
    """
    Checks that there is only one active access key for each IAM user and updates the results dictionary.
    """
    client = session.client('iam')
    non_compliant_users = []

    try:
        users = client.list_users()

        for user in users['Users']:
            access_keys = client.list_access_keys(UserName=user['UserName'])
            active_keys = [key['AccessKeyId'] for key in access_keys['AccessKeyMetadata'] if key['Status'] == 'Active']

            if len(active_keys) > 1:
                non_compliant_users.append({
                    "User": user['UserName'],
                    "AccessKeyIds": active_keys
                })

        results["1.13"] = {
            "description": "Ensure there is only one active access key available for any single IAM user",
            "result": non_compliant_users,
            "explanation": explanation_1_13,
            "status": "PASS" if not non_compliant_users else "FAIL"
        }

    except Exception as e:
        logger.error(f"Error in 1.13 check: {str(e)}")
        results["1.13"] = {
            "description": "Ensure there is only one active access key available for any single IAM user",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }

    write_results_to_file(results)



def check_access_key_rotation_and_update_results(session, results, explanation_1_14):
    """
    Checks that IAM access keys are rotated every 90 days or less and updates the results dictionary.
    """
    client = session.client('iam')
    non_compliant_keys = []

    try:
        users = client.list_users()

        for user in users['Users']:
            access_keys = client.list_access_keys(UserName=user['UserName'])

            for key in access_keys['AccessKeyMetadata']:
                days_old = (datetime.datetime.now(datetime.timezone.utc) - key['CreateDate']).days
                if days_old > 90:
                    non_compliant_keys.append({
                        "User": user['UserName'],
                        "AccessKeyId": key['AccessKeyId'],
                        "CreateDate": key['CreateDate'].strftime('%Y-%m-%d %H:%M:%S UTC')
                    })

        results["1.14"] = {
            "description": "Ensure access keys are rotated every 90 days or less",
            "result": non_compliant_keys,
            "explanation": explanation_1_14,
            "status": "PASS" if not non_compliant_keys else "FAIL"
        }

    except Exception as e:
        logger.error(f"Error in 1.14 check: {str(e)}")
        results["1.14"] = {
            "description": "Ensure access keys are rotated every 90 days or less",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }

    write_results_to_file(results)



def check_permissions_through_groups_and_update_results(session, results, explanation_1_15):
    """
    Checks that IAM users receive permissions only through groups and updates the results dictionary.
    """
    client = session.client('iam')
    non_compliant_users = []

    try:
        users = client.list_users()

        for user in users['Users']:
            attached_policies = client.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
            inline_policies = client.list_user_policies(UserName=user['UserName'])['PolicyNames']

            if attached_policies or inline_policies:
                non_compliant_users.append({
                    "User": user['UserName'],
                    "AttachedPolicies": [policy['PolicyName'] for policy in attached_policies],
                    "InlinePolicies": inline_policies
                })

        results["1.15"] = {
            "description": "Ensure IAM Users Receive Permissions Only Through Groups",
            "result": non_compliant_users,
            "explanation": explanation_1_15,
            "status": "PASS" if not non_compliant_users else "FAIL"
        }

    except Exception as e:
        logger.error(f"Error in 1.15 check: {str(e)}")
        results["1.15"] = {
            "description": "Ensure IAM Users Receive Permissions Only Through Groups",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }

    write_results_to_file(results)


def check_no_full_admin_policies_and_update_results(session, results, explanation_1_16):
    """
    Checks for policies that grant full administrative privileges and updates the results dictionary.
    """
    client = session.client('iam')
    full_admin_policies = []

    try:
        paginator = client.get_paginator('list_policies')

        for page in paginator.paginate(Scope='All'):
            for policy in page['Policies']:
                policy_version = client.get_policy_version(
                    PolicyArn=policy['Arn'],
                    VersionId=policy['DefaultVersionId']
                )
                if 'Statement' in policy_version['PolicyVersion']['Document']:
                    statements = policy_version['PolicyVersion']['Document']['Statement']

                    if isinstance(statements, dict):
                        statements = [statements]

                    for statement in statements:
                        if (statement.get('Effect') == 'Allow' and
                                statement.get('Action') == '*' and
                                statement.get('Resource') == '*'):
                            users = client.list_entities_for_policy(PolicyArn=policy['Arn'], EntityFilter='User')['PolicyUsers']
                            roles = client.list_entities_for_policy(PolicyArn=policy['Arn'], EntityFilter='Role')['PolicyRoles']
                            groups = client.list_entities_for_policy(PolicyArn=policy['Arn'], EntityFilter='Group')['PolicyGroups']

                            full_admin_policies.append({
                                "PolicyName": policy['PolicyName'],
                                "PolicyArn": policy['Arn'],
                                "Users": [user['UserName'] for user in users],
                                "Roles": [role['RoleName'] for role in roles],
                                "Groups": [group['GroupName'] for group in groups]
                            })
                            break

        results["1.16"] = {
            "description": "Ensure no policies grant full administrative privileges.",
            "result": full_admin_policies if full_admin_policies else "No policies found with full administrative privileges.",
            "explanation": explanation_1_16,
            "status": "PASS" if not full_admin_policies else "FAIL"
        }

    except Exception as e:
        logger.error(f"Error in 1.16 check: {str(e)}")
        results["1.16"] = {
            "description": "Ensure no policies grant full administrative privileges.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }

    write_results_to_file(results)






''' # WITHOUT PAG
def check_1_16_no_full_admin_policies():
    client = session.client('iam')
    policies = client.list_policies(Scope='All')
    full_admin_policies = []

    for policy in policies['Policies']:
        policy_version = client.get_policy_version(
            PolicyArn=policy['Arn'], 
            VersionId=policy['DefaultVersionId']
        )
        if 'Statement' in policy_version['PolicyVersion']['Document']:
            statements = policy_version['PolicyVersion']['Document']['Statement']

            if isinstance(statements, dict):
                statements = [statements]

            for statement in statements:
                if (statement.get('Effect') == 'Allow' and
                    statement.get('Action') == '*' and
                    statement.get('Resource') == '*'):
                    
                    users = client.list_entities_for_policy(PolicyArn=policy['Arn'], EntityFilter='User')
                    roles = client.list_entities_for_policy(PolicyArn=policy['Arn'], EntityFilter='Role')
                    groups = client.list_entities_for_policy(PolicyArn=policy['Arn'], EntityFilter='Group')
                    
                    full_admin_policies.append({
                        "PolicyName": policy['PolicyName'],
                        "PolicyArn": policy['Arn'],
                        "Entities": {
                            "Users": [user['UserName'] for user in users['PolicyUsers']],
                            "Roles": [role['RoleName'] for role in roles['PolicyRoles']],
                            "Groups": [group['GroupName'] for group in groups['PolicyGroups']]
                        }
                    })
                    break 

    return full_admin_policies
'''










def check_support_role_with_policy():
    client = session.client('iam')

    try:
        aws_policies = client.list_policies(Scope='AWS')['Policies']
        for policy in aws_policies:
            if policy['PolicyName'] == 'AWSSupportAccess':
                entities = client.list_entities_for_policy(PolicyArn=policy['Arn'])
                return {
                    "PolicyName": policy['PolicyName'],
                    "PolicyId": policy['PolicyId'],
                    "PolicyArn": policy['Arn'],
                    "PolicyRoles": [role['RoleName'] for role in entities.get('PolicyRoles', [])],
                    "PolicyUsers": [user['UserName'] for user in entities.get('PolicyUsers', [])],
                    "PolicyGroups": [group['GroupName'] for group in entities.get('PolicyGroups', [])]
                }

        local_policies = client.list_policies(Scope='Local')['Policies']
        for policy in local_policies:
            if policy['PolicyName'] == 'AWSSupportAccess':
                entities = client.list_entities_for_policy(PolicyArn=policy['Arn'])
                return {
                    "PolicyName": policy['PolicyName'],
                    "PolicyId": policy['PolicyId'],
                    "PolicyArn": policy['Arn'],
                    "PolicyRoles": [role['RoleName'] for role in entities.get('PolicyRoles', [])],
                    "PolicyUsers": [user['UserName'] for user in entities.get('PolicyUsers', [])],
                    "PolicyGroups": [group['GroupName'] for group in entities.get('PolicyGroups', [])]
                }

        return {"PolicyName": "AWSSupportAccess", "PolicyArn": "Not Found", "PolicyRoles": [], "PolicyUsers": [], "PolicyGroups": []}
    except Exception as e:
        return {"Error": str(e)}



def check_support_role_with_policy_and_update_results(session, results, explanation_1_17):
    """
    Checks for a support role with the 'AWSSupportAccess' policy and updates the results dictionary.
    """
    client = session.client('iam')

    try:
        aws_policies = client.list_policies(Scope='AWS')['Policies']
        for policy in aws_policies:
            if policy['PolicyName'] == 'AWSSupportAccess':
                entities = client.list_entities_for_policy(PolicyArn=policy['Arn'])
                results["1.17"] = {
                    "description": "Ensure a support role has been created to manage incidents with AWS Support",
                    "result": {
                        "PolicyName": policy['PolicyName'],
                        "PolicyId": policy['PolicyId'],
                        "PolicyArn": policy['Arn'],
                        "PolicyRoles": [role['RoleName'] for role in entities.get('PolicyRoles', [])],
                        "PolicyUsers": [user['UserName'] for user in entities.get('PolicyUsers', [])],
                        "PolicyGroups": [group['GroupName'] for group in entities.get('PolicyGroups', [])]
                    },
                    "explanation": explanation_1_17,
                    "status": "PASS" if entities.get('PolicyRoles') else "FAIL"
                }
                write_results_to_file(results)
                return

        local_policies = client.list_policies(Scope='Local')['Policies']
        for policy in local_policies:
            if policy['PolicyName'] == 'AWSSupportAccess':
                entities = client.list_entities_for_policy(PolicyArn=policy['Arn'])
                results["1.17"] = {
                    "description": "Ensure a support role has been created to manage incidents with AWS Support",
                    "result": {
                        "PolicyName": policy['PolicyName'],
                        "PolicyId": policy['PolicyId'],
                        "PolicyArn": policy['Arn'],
                        "PolicyRoles": [role['RoleName'] for role in entities.get('PolicyRoles', [])],
                        "PolicyUsers": [user['UserName'] for user in entities.get('PolicyUsers', [])],
                        "PolicyGroups": [group['GroupName'] for group in entities.get('PolicyGroups', [])]
                    },
                    "explanation": explanation_1_17,
                    "status": "PASS" if entities.get('PolicyRoles') else "FAIL"
                }
                write_results_to_file(results)
                return

        results["1.17"] = {
            "description": "Ensure a support role has been created to manage incidents with AWS Support",
            "result": "AWSSupportAccess policy not found.",
            "explanation": explanation_1_17,
            "status": "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error during check 1.17: {str(e)}")
        results["1.17"] = {
            "description": "Ensure a support role has been created to manage incidents with AWS Support",
            "result": f"Error during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)





def check_iam_instance_roles_and_update_results(session, results):
    """
    Checks for instances with no IAM roles and updates the results dictionary.
    """
    ec2_client = session.client('ec2')

    try:
        instances = ec2_client.describe_instances()
        instance_details = []

        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                instance_state = instance['State']['Name']
                launch_time = instance['LaunchTime']
                iam_role = instance['IamInstanceProfile']['Arn'] if 'IamInstanceProfile' in instance else "No IAM Role"

                instance_name = None
                for tag in instance.get('Tags', []):
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                        break

                instance_details.append({
                    "InstanceId": instance_id,
                    "InstanceName": instance_name,
                    "IAMRole": iam_role,
                    "State": instance_state,
                    "LaunchTime": launch_time
                })

        instances_without_roles = [detail for detail in instance_details if detail['IAMRole'] == "No IAM Role"]

        results["1.18"] = {
            "description": "Ensure IAM instance roles are used for AWS resource access from instances",
            "result": instances_without_roles,
            "status": "PASS" if not instances_without_roles else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error during check 1.18: {str(e)}")
        results["1.18"] = {
            "description": "Ensure IAM instance roles are used for AWS resource access from instances",
            "result": f"Error occurred: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)




def check_expired_ssl_certificates_and_update_results(session, results, explanation_1_19):
    """
    Checks for expired SSL/TLS certificates stored in AWS IAM and updates the results dictionary.
    """
    iam_client = session.client('iam')
    expired_certificates = []

    try:
        certificates = iam_client.list_server_certificates()

        for certificate in certificates['ServerCertificateMetadataList']:
            expiration_date = certificate['Expiration']

            if expiration_date < datetime.datetime.now(expiration_date.tzinfo):
                expired_certificates.append({
                    "ServerCertificateName": certificate['ServerCertificateName'],
                    "Arn": certificate['Arn'],
                    "UploadDate": certificate['UploadDate'],
                    "Expiration": expiration_date
                })

        results["1.19"] = {
            "description": "Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed",
            "result": expired_certificates,
            "explanation": explanation_1_19,
            "status": "PASS" if not expired_certificates else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error during check 1.19: {str(e)}")
        results["1.19"] = {
            "description": "Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed",
            "result": f"Error occurred: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)




def check_access_analyzer_all_regions_and_update_results(session, results, explanation_1_20, regions):
    """
    Checks for AWS Access Analyzer configuration in all regions and updates the results dictionary.
    """
    sts_client = session.client('sts')
    account_id = sts_client.get_caller_identity()["Account"]
    analyzer_violations = []

    try:
        for region in regions:
            access_analyzer_client = session.client('accessanalyzer', region_name=region)
            paginator = access_analyzer_client.get_paginator('list_analyzers')

            try:
                for page in paginator.paginate():
                    if not page.get('analyzers'):
                        analyzer_violations.append({
                            'AccountId': account_id,
                            'Region': region,
                            'Status': 'Access Analyzer not enabled'
                        })
            except botocore.exceptions.ClientError as e:
                logger.error(f"Error checking AWS Access Analyzer in region {region}: {e}")
                analyzer_violations.append({
                    'AccountId': account_id,
                    'Region': region,
                    'Status': f"Error checking Access Analyzer: {str(e)}"
                })

        if analyzer_violations:
            results["1.20"] = {
                "description": "Ensure AWS Access Analyzer is enabled in all regions",
                "result": analyzer_violations,
                "explanation": explanation_1_20,
                "status": "FAIL"
            }
        else:
            results["1.20"] = {
                "description": "Ensure AWS Access Analyzer is enabled in all regions",
                "result": "AWS Access Analyzer is enabled in all regions.",
                "explanation": explanation_1_20,
                "status": "PASS"
            }

        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 1.20 check: {str(e)}")
        results["1.20"] = {
            "description": "Ensure AWS Access Analyzer is enabled in all regions",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)





organizations = session.client('organizations')

def check_centralized_iam_management_and_update_results(session, results, explanation_1_21):
    """
    Checks for centralized IAM management via identity federation or AWS Organizations and updates the results dictionary.
    """
    iam_client = session.client('iam')

    try:
        identity_providers = iam_client.list_saml_providers()['SAMLProviderList']

        try:
            org_client = session.client('organizations')
            org_details = org_client.describe_organization()
            organizations_status = {
                "Available": True,
                "MasterAccountId": org_details['Organization']['MasterAccountId'],
                "MasterAccountEmail": org_details['Organization']['MasterAccountEmail']
            }
        except Exception as e:
            logger.error(f"Error accessing AWS Organizations: {str(e)}")
            organizations_status = {"Available": False}

        results["1.21"] = {
            "description": "Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments",
            "result": {
                "Identity_Providers": [idp['Arn'] for idp in identity_providers],
                "AWS_Organizations_Status": organizations_status
            },
            "explanation": explanation_1_21,
            "status": "PASS" if identity_providers or organizations_status['Available'] else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 1.21 check: {str(e)}")
        results["1.21"] = {
            "description": "Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)



def check_cloudshell_full_access_restriction_and_update_results(session, results, explanation_1_22):
    """
    Checks for users, roles, or groups with AWSCloudShellFullAccess and updates the results dictionary.
    """
    iam_client = session.client('iam')

    def has_policy(attached_policies, policy_name):
        return any(policy['PolicyName'] == policy_name for policy in attached_policies)

    try:
        users_with_policy = []
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                attached_policies = iam_client.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
                if has_policy(attached_policies, 'AWSCloudShellFullAccess'):
                    users_with_policy.append(user['UserName'])

        roles_with_policy = []
        paginator = iam_client.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                attached_policies = iam_client.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']
                if has_policy(attached_policies, 'AWSCloudShellFullAccess'):
                    roles_with_policy.append(role['RoleName'])

        groups_with_policy = []
        paginator = iam_client.get_paginator('list_groups')
        for page in paginator.paginate():
            for group in page['Groups']:
                attached_policies = iam_client.list_attached_group_policies(GroupName=group['GroupName'])['AttachedPolicies']
                if has_policy(attached_policies, 'AWSCloudShellFullAccess'):
                    groups_with_policy.append(group['GroupName'])

        results["1.22"] = {
            "description": "Ensure access to AWSCloudShellFullAccess is restricted",
            "result": {
                "Users_With_AWSCloudShellFullAccess": users_with_policy,
                "Roles_With_AWSCloudShellFullAccess": roles_with_policy,
                "Groups_With_AWSCloudShellFullAccess": groups_with_policy
            },
            "explanation": explanation_1_22,
            "status": "PASS" if not users_with_policy and not roles_with_policy and not groups_with_policy else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 1.22 check: {str(e)}")
        results["1.22"] = {
            "description": "Ensure access to AWSCloudShellFullAccess is restricted",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)



s3 = session.client('s3')
from botocore.exceptions import ClientError

def check_deny_http_requests_and_update_results(session, results, explanation_2_1_1):
    """
    Checks if S3 buckets deny HTTP requests when not using Secure Transport and updates the results dictionary.
    """
    s3_client = session.client('s3')
    insecure_buckets = []

    try:
        all_buckets = s3_client.list_buckets()['Buckets']
        for bucket in tqdm(all_buckets, desc="Checking S3 Buckets"):
            bucket_name = bucket['Name']
            bucket_details = {'BucketName': bucket_name}

            try:
                bucket_policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                bucket_policy = json.loads(bucket_policy_response['Policy'])
                bucket_details['PolicyStatements'] = bucket_policy.get('Statement', [])

                secure_transport_statements = [
                    statement for statement in bucket_details['PolicyStatements']
                    if statement.get('Effect') == 'Deny' and statement.get('Condition', {}).get('Bool', {}).get('aws:SecureTransport') == 'false'
                ]

                if not secure_transport_statements:
                    insecure_buckets.append(bucket_details)

            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    bucket_details['FailureReason'] = 'No bucket policy exists'
                else:
                    bucket_details['FailureReason'] = str(e)
                insecure_buckets.append(bucket_details)

        results["2.1.1"] = {
            "description": "Ensure that S3 buckets deny HTTP requests when not using Secure Transport.",
            "result": insecure_buckets if insecure_buckets else "All buckets are secure or have no bucket policy.",
            "explanation": explanation_2_1_1,
            "status": "FAIL" if insecure_buckets else "PASS"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 2.1.1 check: {str(e)}")
        results["2.1.1"] = {
            "description": "Ensure that S3 buckets deny HTTP requests when not using Secure Transport.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)


def check_mfa_delete_enabled_and_update_results(session, results, explanation_2_1_2):
    """
    Checks if S3 buckets have MFA Delete enabled and updates the results dictionary.
    """
    s3_client = session.client('s3')
    bucket_details = []

    try:
        buckets = s3_client.list_buckets()['Buckets']
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                versioning_status = versioning.get('Status')
                mfa_delete = versioning.get('MFADelete')

                if versioning_status == 'Enabled' and mfa_delete != 'Enabled':
                    bucket_details.append({
                        'BucketName': bucket_name,
                        'VersioningStatus': versioning_status,
                        'MFADelete': mfa_delete or "Disabled"
                    })

            except ClientError as e:
                bucket_details.append({
                    'BucketName': bucket_name,
                    'Error': str(e)
                })

        results["2.1.2"] = {
            "description": "Ensure that S3 Buckets have MFA Delete enabled.",
            "result": bucket_details if bucket_details else "All S3 Buckets have MFA Delete enabled or no versioning-enabled buckets without MFA Delete.",
            "explanation": explanation_2_1_2,
            "status": "FAIL" if any('Error' not in bucket for bucket in bucket_details) else "PASS"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 2.1.2 check: {str(e)}")
        results["2.1.2"] = {
            "description": "Ensure that S3 Buckets have MFA Delete enabled.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)





#2.1.3 is manual and requires amazon macie

def check_s3_bucket_public_access_and_update_results(session, results, explanation_2_1_4):
    """
    Checks if S3 buckets are configured with 'Block public access (bucket settings)' and updates the results dictionary.
    """
    s3_client = session.client('s3')
    non_compliant_buckets = []

    try:
        all_buckets = s3_client.list_buckets()

        for bucket in all_buckets['Buckets']:
            bucket_name = bucket['Name']

            # Get the bucket's region
            try:
                bucket_location = s3_client.get_bucket_location(Bucket=bucket_name)
                region = bucket_location.get('LocationConstraint') or "us-east-1"
            except Exception as e:
                logger.warning(f"Error fetching location for bucket {bucket_name}: {str(e)}")
                region = "Unknown"

            try:
                # Get the public access block configuration
                response = s3_client.get_public_access_block(Bucket=bucket_name)
                settings = response['PublicAccessBlockConfiguration']

                # Check if all public access settings are enabled
                if not all([
                    settings.get('BlockPublicAcls', False),
                    settings.get('IgnorePublicAcls', False),
                    settings.get('BlockPublicPolicy', False),
                    settings.get('RestrictPublicBuckets', False)
                ]):
                    non_compliant_buckets.append({
                        "BucketName": bucket_name,
                        "Region": region,
                        "Settings": settings
                    })

            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'NoSuchPublicAccessBlockConfiguration':
                    non_compliant_buckets.append({
                        "BucketName": bucket_name,
                        "Region": region,
                        "Error": "No public access block configuration found."
                    })
                else:
                    non_compliant_buckets.append({
                        "BucketName": bucket_name,
                        "Region": region,
                        "Error": str(e)
                    })
            except Exception as e:
                non_compliant_buckets.append({
                    "BucketName": bucket_name,
                    "Region": region,
                    "Error": str(e)
                })

        results["2.1.4"] = {
            "description": "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'.",
            "result": non_compliant_buckets if non_compliant_buckets else "All buckets have public access blocked.",
            "explanation": explanation_2_1_4,
            "status": "PASS" if not non_compliant_buckets else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 2.1.4 check: {str(e)}")
        results["2.1.4"] = {
            "description": "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)



rds = session.client('rds')


def check_rds_encryption_at_rest_and_update_results(session, results, explanation_2_2_1, regions):
    """
    Checks if RDS instances have encryption-at-rest enabled and updates the results dictionary.
    """
    unencrypted_rds_details = []

    try:
        for region in regions:
            region_rds_client = session.client('rds', region_name=region)
            paginator = region_rds_client.get_paginator('describe_db_instances')

            for page in paginator.paginate():
                for instance in page['DBInstances']:
                    storage_encrypted = instance.get('StorageEncrypted')
                    if not storage_encrypted:
                        unencrypted_rds_details.append({
                            'Region': region,
                            'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                            'StorageEncrypted': storage_encrypted
                        })

        if unencrypted_rds_details:
            results["2.2.1"] = {
                "description": "Ensure that encryption-at-rest is enabled for RDS Instances",
                "result": unencrypted_rds_details,
                "explanation": explanation_2_2_1,
                "status": "FAIL"
            }
        else:
            results["2.2.1"] = {
                "description": "Ensure that encryption-at-rest is enabled for RDS Instances",
                "result": "All RDS instances across all regions are encrypted",
                "explanation": explanation_2_2_1,
                "status": "PASS"
            }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 2.2.1 check: {str(e)}")
        results["2.2.1"] = {
            "description": "Ensure that encryption-at-rest is enabled for RDS Instances",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)




def check_rds_auto_minor_upgrade_and_update_results(session, results, explanation_2_2_2, regions):
    """
    Checks if RDS instances have Auto Minor Version Upgrade enabled and updates the results dictionary.
    """
    non_compliant_details = []

    try:
        for region in regions:
            regional_rds_client = session.client('rds', region_name=region)
            paginator = regional_rds_client.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for instance in page['DBInstances']:
                    auto_minor_version_upgrade = instance.get('AutoMinorVersionUpgrade')
                    if auto_minor_version_upgrade is False:
                        non_compliant_details.append({
                            'Region': region,
                            'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                            'AutoMinorVersionUpgrade': auto_minor_version_upgrade
                        })

        if non_compliant_details:
            results["2.2.2"] = {
                "description": "Ensure RDS instances have Auto Minor Version Upgrade enabled.",
                "result": non_compliant_details,
                "explanation": explanation_2_2_2,
                "status": "FAIL"
            }
        else:
            results["2.2.2"] = {
                "description": "Ensure RDS instances have Auto Minor Version Upgrade enabled.",
                "result": "All RDS instances have Auto Minor Version Upgrade enabled.",
                "explanation": explanation_2_2_2,
                "status": "PASS"
            }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 2.2.2 check: {str(e)}")
        results["2.2.2"] = {
            "description": "Ensure RDS instances have Auto Minor Version Upgrade enabled.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)


def check_rds_public_access_and_update_results(session, results, explanation_2_2_3, regions):
    """
    Checks if any RDS instances have public access enabled and updates the results dictionary.
    """
    public_access_rds_instances = []

    try:
        for region in regions:
            region_rds_client = session.client('rds', region_name=region)
            paginator = region_rds_client.get_paginator('describe_db_instances')

            for page in paginator.paginate():
                for instance in page['DBInstances']:
                    if instance.get('PubliclyAccessible', False):
                        public_access_rds_instances.append({
                            'Region': region,
                            'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                            'PubliclyAccessible': instance['PubliclyAccessible']
                        })

        if public_access_rds_instances:
            results["2.2.3"] = {
                "description": "Ensure that public access is not given to RDS instances.",
                "result": public_access_rds_instances,
                "explanation": explanation_2_2_3,
                "status": "FAIL"
            }
        else:
            results["2.2.3"] = {
                "description": "Ensure that public access is not given to RDS instances.",
                "result": "No RDS instances with public access found.",
                "explanation": explanation_2_2_3,
                "status": "PASS"
            }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 2.2.3 check: {str(e)}")
        results["2.2.3"] = {
            "description": "Ensure that public access is not given to RDS instances.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)



def check_efs_encryption_and_update_results(session, results, explanation_2_3_1, regions):
    """
    Checks if EFS file systems have encryption enabled and updates the results dictionary.
    """
    unencrypted_file_systems = {}

    try:
        for region in regions:
            region_efs_client = session.client('efs', region_name=region)

            paginator = region_efs_client.get_paginator('describe_file_systems')
            for page in paginator.paginate():
                for fs in page['FileSystems']:
                    if not fs.get('Encrypted', False):
                        if region not in unencrypted_file_systems:
                            unencrypted_file_systems[region] = []
                        unencrypted_file_systems[region].append({
                            "FileSystemId": fs['FileSystemId'],
                            "Encrypted": fs.get('Encrypted', False)
                        })

        if unencrypted_file_systems:
            formatted_results = []
            for region, fs_details in unencrypted_file_systems.items():
                for fs in fs_details:
                    formatted_results.append(f"Region: {region}, FileSystemId: {fs['FileSystemId']}, Encrypted: {fs['Encrypted']}")
            results["2.3.1"] = {
                "description": "Ensure that encryption is enabled for EFS file systems",
                "result": formatted_results,
                "explanation": explanation_2_3_1,
                "status": "FAIL"
            }
        else:
            results["2.3.1"] = {
                "description": "Ensure that encryption is enabled for EFS file systems",
                "result": "Encryption is enabled for all EFS file systems across all regions.",
                "explanation": explanation_2_3_1,
                "status": "PASS"
            }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 2.3.1 check: {str(e)}")
        results["2.3.1"] = {
            "description": "Ensure that encryption is enabled for EFS file systems",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)



def check_cloudtrail_all_regions_and_update_results(session, results, explanation_3_1, regions):
    """
    Checks if CloudTrail is enabled and logging in all regions and updates the results dictionary.
    """
    regions_without_cloudtrail = []

    try:
        for region in regions:
            region_cloudtrail_client = session.client('cloudtrail', region_name=region)

            trails = region_cloudtrail_client.describe_trails()
            if trails['trailList']:
                trail_status = [region_cloudtrail_client.get_trail_status(Name=trail['Name']) for trail in trails['trailList']]
                if not any(ts.get('IsLogging') and ts.get('IncludeGlobalServiceEvents') for ts in trail_status):
                    regions_without_cloudtrail.append(region)
            else:
                regions_without_cloudtrail.append(region)

        results["3.1"] = {
            "description": "Ensure CloudTrail is enabled in all regions",
            "result": regions_without_cloudtrail if regions_without_cloudtrail else "CloudTrail is enabled in all regions",
            "explanation": explanation_3_1,
            "status": "PASS" if not regions_without_cloudtrail else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 3.1 check: {str(e)}")
        results["3.1"] = {
            "description": "Ensure CloudTrail is enabled in all regions",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)



def check_cloudtrail_log_file_validation_and_update_results(session, results, explanation_3_2):
    """
    Checks if CloudTrail log file validation is enabled and updates the results dictionary.
    """
    cloudtrail_client = session.client('cloudtrail')
    trails_without_validation = []

    try:
        trails = cloudtrail_client.describe_trails()
        for trail in trails['trailList']:
            if not trail.get('LogFileValidationEnabled', False):
                trails_without_validation.append({
                    "TrailName": trail['Name'],
                    "LogFileValidationEnabled": trail.get('LogFileValidationEnabled', False)
                })

        if trails_without_validation:
            results["3.2"] = {
                "description": "Ensure CloudTrail log file validation is enabled.",
                "result": trails_without_validation,
                "explanation": explanation_3_2,
                "status": "FAIL"
            }
        else:
            results["3.2"] = {
                "description": "Ensure CloudTrail log file validation is enabled.",
                "result": "All trails have log file validation enabled.",
                "explanation": explanation_3_2,
                "status": "PASS"
            }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 3.2 check: {str(e)}")
        results["3.2"] = {
            "description": "Ensure CloudTrail log file validation is enabled.",
            "result": [{"error": f"Error occurred during check: {str(e)}"}],
            "status": "ERROR"
        }
        write_results_to_file(results)



def check_aws_config_all_regions_and_update_results(session, results, explanation_3_3, regions):
    """
    Checks if AWS Config is enabled in all regions and updates the results dictionary.
    """
    region_statuses = []

    try:
        for region in regions:
            region_client = session.client('config', region_name=region)
            try:
                status = region_client.describe_configuration_recorders()['ConfigurationRecorders'][0]['recording']
                region_statuses.append({
                    "region": region,
                    "recording": status
                })
            except Exception:
                region_statuses.append({
                    "region": region,
                    "recording": False
                })

        non_configured_regions = [info for info in region_statuses if not info.get('recording')]

        results["3.3"] = {
            "description": "Ensure AWS Config is enabled in all regions.",
            "result": region_statuses,
            "explanation": explanation_3_3,
            "status": "PASS" if not non_configured_regions else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 3.3 check: {str(e)}")
        results["3.3"] = {
            "description": "Ensure AWS Config is enabled in all regions.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)



def check_s3_bucket_logging_and_update_results(session, results, explanation_3_4):
    """
    Checks if logging is enabled for S3 buckets used by CloudTrail and updates the results dictionary.
    """
    cloudtrail_client = session.client('cloudtrail')
    s3_client = session.client('s3')
    bucket_logging_details = []

    try:
        trails = cloudtrail_client.describe_trails()['trailList']

        for trail in trails:
            bucket_name = trail['S3BucketName']

            try:
                bucket_logging = s3_client.get_bucket_logging(Bucket=bucket_name)
                logging_status = bucket_logging.get('LoggingEnabled', None)
            except Exception as e:
                logging_status = str(e)

            bucket_logging_details.append({
                'BucketName': bucket_name,
                'LoggingEnabled': logging_status
            })

        buckets_without_logging = [
            detail for detail in bucket_logging_details 
            if not detail.get('LoggingEnabled', False) or "Error" in str(detail['LoggingEnabled'])
        ]

        results["3.4"] = {
            "description": "Ensure S3 bucket logging is enabled.",
            "result": bucket_logging_details,
            "explanation": explanation_3_4,
            "status": "PASS" if not buckets_without_logging else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 3.4 check: {str(e)}")
        results["3.4"] = {
            "description": "Ensure S3 bucket logging is enabled.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)


def check_cloudtrail_kms_encryption_and_update_results(session, results, explanation_3_5):
    """
    Checks if CloudTrail is encrypted with KMS CMKs and updates the results dictionary.
    """
    cloudtrail_client = session.client('cloudtrail')
    trail_encryption_details = []

    try:
        trails = cloudtrail_client.describe_trails()['trailList']

        for trail in trails:
            trail_name = trail['Name']
            kms_key_id = trail.get('KmsKeyId', None)

            trail_encryption_details.append({
                'TrailName': trail_name,
                'KmsKeyId': kms_key_id
            })

        trails_without_kms_encryption = [
            detail for detail in trail_encryption_details 
            if not detail.get('KmsKeyId')
        ]

        results["3.5"] = {
            "description": "Ensure CloudTrail is encrypted with KMS CMKs.",
            "result": trail_encryption_details,
            "explanation": explanation_3_5,
            "status": "PASS" if not trails_without_kms_encryption else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 3.5 check: {str(e)}")
        results["3.5"] = {
            "description": "Ensure CloudTrail is encrypted with KMS CMKs.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)



def check_kms_key_rotation_and_update_results(session, results, explanation_3_6):
    """
    Checks if KMS key rotation is enabled for customer-managed keys and updates the results dictionary.
    """
    kms_client = session.client('kms')
    cmk_rotation_details = []

    try:
        paginator = kms_client.get_paginator('list_keys')
        for page in paginator.paginate():
            for key in page['Keys']:
                key_metadata = kms_client.describe_key(KeyId=key['KeyId'])
                key_type = key_metadata['KeyMetadata']['KeySpec']
                key_manager = key_metadata['KeyMetadata']['KeyManager']

                if key_type == 'SYMMETRIC_DEFAULT' and key_manager == 'CUSTOMER':
                    rotation_status = kms_client.get_key_rotation_status(KeyId=key['KeyId'])
                    cmk_rotation_details.append({
                        'KeyId': key['KeyId'],
                        'KeyRotationEnabled': rotation_status['KeyRotationEnabled']
                    })

        cmk_ids_without_rotation = [detail for detail in cmk_rotation_details if not detail.get('KeyRotationEnabled')]

        results["3.6"] = {
            "description": "Ensure rotation for customer-created KMS keys is enabled.",
            "result": cmk_rotation_details,
            "explanation": explanation_3_6,
            "status": "PASS" if not cmk_ids_without_rotation else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 3.6 check: {str(e)}")
        results["3.6"] = {
            "description": "Ensure rotation for customer-created KMS keys is enabled.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)


def check_vpc_flow_logs_and_update_results(session, results, explanation_3_7):
    """
    Checks if VPC flow logging is enabled in all VPCs and updates the results dictionary.
    """
    ec2_client = session.client('ec2')

    try:
        vpcs = ec2_client.describe_vpcs()['Vpcs']
        all_vpc_ids = [vpc['VpcId'] for vpc in vpcs]

        flow_logs = ec2_client.describe_flow_logs()['FlowLogs']
        vpc_ids_with_flow_logs = [flow_log['ResourceId'] for flow_log in flow_logs]

        vpcs_without_flow_logs = [vpc_id for vpc_id in all_vpc_ids if vpc_id not in vpc_ids_with_flow_logs]

        if vpcs_without_flow_logs:
            formatted_details = [{"VPC": vpc} for vpc in vpcs_without_flow_logs]
            results["3.7"] = {
                "description": "Ensure VPC flow logging is enabled in all VPCs",
                "result": formatted_details,
                "explanation": explanation_3_7,
                "status": "FAIL"
            }
        else:
            results["3.7"] = {
                "description": "Ensure VPC flow logging is enabled in all VPCs",
                "result": "Flow logging is enabled for all VPCs",
                "explanation": explanation_3_7,
                "status": "PASS"
            }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 3.7 check: {str(e)}")
        results["3.7"] = {
            "description": "Ensure VPC flow logging is enabled in all VPCs",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)


def check_object_level_logging_write_events_and_update_results(session, results, explanation_3_8):
    """
    Checks if object-level logging for write events is enabled on S3 buckets and updates the results dictionary.
    """
    cloudtrail_client = session.client('cloudtrail')
    trail_details = []

    try:
        # Step 1: List all trails
        all_trails = cloudtrail_client.list_trails()['Trails']

        if not all_trails:
            results["3.8"] = {
                "description": "Ensure that object-level logging for write events is enabled for S3 buckets.",
                "result": "No CloudTrail trails are configured.",
                "status": "FAIL"
            }
            write_results_to_file(results)
            return

        for trail_summary in all_trails:
            trail_arn = trail_summary['TrailARN']
            trail_name = trail_summary['Name']
            trail_region = trail_summary['HomeRegion']
            trail_is_multi_region = False
            write_events_enabled = False

            try:
                # Step 3: Check if the trail is a multi-region trail
                trail_config = cloudtrail_client.get_trail(Name=trail_name)
                trail_is_multi_region = trail_config.get('Trail', {}).get('IsMultiRegionTrail', False)

                # Step 5: Get event selectors and check for S3 data event logging
                event_selectors = cloudtrail_client.get_event_selectors(TrailName=trail_name)

                s3_data_event_selectors = [
                    selector for selector in event_selectors.get('EventSelectors', [])
                    if any(resource for resource in selector.get('DataResources', [])
                           if resource.get('Type') == 'AWS::S3::Object')
                ]

                # Check if any of the selectors enable write events or all events
                for selector in s3_data_event_selectors:
                    if selector.get('ReadWriteType') in ['WriteOnly', 'All']:
                        write_events_enabled = True
                        break

                trail_details.append({
                    "TrailName": trail_name,
                    "TrailARN": trail_arn,
                    "HomeRegion": trail_region,
                    "IsMultiRegionTrail": trail_is_multi_region,
                    "HasS3WriteEvents": write_events_enabled,
                    "Compliant": trail_is_multi_region and write_events_enabled
                })

            except Exception as e:
                # Capture details for errors during individual trail checks
                trail_details.append({
                    "TrailName": trail_name,
                    "Error": str(e)
                })

        # Step 8: Filter non-compliant trails
        non_compliant_trails = [
            trail for trail in trail_details
            if not trail.get("Compliant", False)
        ]

        results["3.8"] = {
            "description": "Ensure that object-level logging for write events is enabled for S3 buckets.",
            "result": {
                "TrailDetails": trail_details,
                "NonCompliantTrails": non_compliant_trails
            },
            "explanation": explanation_3_8,
            "status": "PASS" if not non_compliant_trails else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 3.8 check: {str(e)}")
        results["3.8"] = {
            "description": "Ensure that object-level logging for write events is enabled for S3 buckets.",
            "result": {
                "Error": str(e)
            },
            "status": "ERROR"
        }
        write_results_to_file(results)



def check_object_level_logging_read_events_and_update_results(session, results, explanation_3_9):
    """
    Checks if object-level logging for read events is enabled on S3 buckets and updates the results dictionary.
    """
    cloudtrail_client = session.client('cloudtrail')
    trail_details = []

    try:
        # Step 1: List all trails
        all_trails = cloudtrail_client.describe_trails()['trailList']

        if not all_trails:
            results["3.9"] = {
                "description": "Ensure that object-level logging for read events is enabled for S3 buckets.",
                "result": "No CloudTrail trails are configured.",
                "status": "FAIL"
            }
            write_results_to_file(results)
            return

        for trail_summary in all_trails:
            trail_arn = trail_summary['TrailARN']
            trail_name = trail_summary['Name']
            trail_region = trail_summary['HomeRegion']
            read_events_enabled = False

            try:
                # Step 3: Get event selectors for the trail
                event_selectors = cloudtrail_client.get_event_selectors(TrailName=trail_name)

                # Step 4: Check for S3 data resources with ReadOnly or All
                s3_data_event_selectors = [
                    selector for selector in event_selectors.get('EventSelectors', [])
                    if any(resource for resource in selector.get('DataResources', [])
                           if resource.get('Type') == 'AWS::S3::Object')
                ]

                for selector in s3_data_event_selectors:
                    if selector.get('ReadWriteType') in ['ReadOnly', 'All']:
                        read_events_enabled = True
                        break

                # Append trail details
                trail_details.append({
                    "TrailName": trail_name,
                    "TrailARN": trail_arn,
                    "HomeRegion": trail_region,
                    "HasS3ReadEvents": read_events_enabled,
                    "Compliant": read_events_enabled
                })

            except Exception as e:
                # Capture details for errors during individual trail checks
                trail_details.append({
                    "TrailName": trail_name,
                    "Error": str(e)
                })

        # Step 6: Filter non-compliant trails
        non_compliant_trails = [
            trail for trail in trail_details
            if not trail.get("Compliant", False)
        ]

        results["3.9"] = {
            "description": "Ensure that object-level logging for read events is enabled for S3 buckets.",
            "result": {
                "TrailDetails": trail_details,
                "NonCompliantTrails": non_compliant_trails
            },
            "explanation": explanation_3_9,
            "status": "PASS" if not non_compliant_trails else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 3.9 check: {str(e)}")
        results["3.9"] = {
            "description": "Ensure that object-level logging for read events is enabled for S3 buckets.",
            "result": {
                "Error": str(e)
            },
            "status": "ERROR"
        }
        write_results_to_file(results)





# SKIPPED 4.x MONITOR SECTION

def check_unauthorized_api_calls_and_update_results(session, results, explanation_4_1, regions):
    """
    Checks if unauthorized API calls are monitored as per CIS Benchmark 4.1 and updates the results dictionary.
    """
    try:
        for region in regions:
            cloudtrail_client = session.client('cloudtrail', region_name=region)
            logs_client = session.client('logs', region_name=region)
            cloudwatch_client = session.client('cloudwatch', region_name=region)
            sns_client = session.client('sns', region_name=region)

            # Step 1: Identify active multi-region trails
            trails = cloudtrail_client.describe_trails()['trailList']
            multi_region_trail = None

            for trail in trails:
                if trail.get('IsMultiRegionTrail') and region == trail['HomeRegion']:
                    trail_status = cloudtrail_client.get_trail_status(Name=trail['Name'])

                    # Check if IsLogging is TRUE
                    if not trail_status.get('IsLogging', False):
                        results["4.1"] = {
                            "description": "Ensure unauthorized API calls are monitored.",
                            "result": {
                                "message": f"Non-compliance in {region}: Multi-region CloudTrail trail exists but IsLogging is set to FALSE.",
                                "trail_details": {
                                    "Name": trail['Name'],
                                    "CloudWatchLogsLogGroupArn": trail.get('CloudWatchLogsLogGroupArn', "Not Configured"),
                                    "IsMultiRegionTrail": trail.get('IsMultiRegionTrail', False),
                                    "IsLogging": trail_status.get('IsLogging', False)
                                }
                            },
                            "status": "FAIL"
                        }
                        write_results_to_file(results)
                        return  # Exit further checks for this region
                    
                    # If IsLogging is true, proceed
                    multi_region_trail = trail
                    trail_log_group_name = multi_region_trail['CloudWatchLogsLogGroupArn'].split(':')[-1].split('*')[0]
                    break

            if not multi_region_trail:
                continue  # No active multi-region trail in this region

            # Step 2: Verify event selectors capture management events
            event_selectors = cloudtrail_client.get_event_selectors(TrailName=multi_region_trail['Name'])
            management_events = any(
                selector.get('IncludeManagementEvents') and selector.get('ReadWriteType') == 'All'
                for selector in event_selectors['EventSelectors']
            )

            if not management_events:
                results["4.1"] = {
                    "description": "Ensure unauthorized API calls are monitored.",
                    "result": {
                        "message": f"No compliance in {region}: Multi-region CloudTrail trail does not capture all management events.",
                        "trail_details": {
                            "Name": multi_region_trail['Name'],
                            "CloudWatchLogsLogGroupArn": multi_region_trail.get('CloudWatchLogsLogGroupArn', "Not Configured"),
                            "IsMultiRegionTrail": multi_region_trail.get('IsMultiRegionTrail', False),
                            "EventSelectors": event_selectors
                        }
                    },
                    "status": "FAIL"
                }
                write_results_to_file(results)
                return

            # Step 3: Verify metric filters
            metric_filters = logs_client.describe_metric_filters(logGroupName=trail_log_group_name)['metricFilters']
            unauthorized_metric_name = None

            for filter in metric_filters:
                if filter['filterPattern'] == '{ ($.errorCode ="*UnauthorizedOperation") || ($.errorCode ="AccessDenied*") && ($.sourceIPAddress!="delivery.logs.amazonaws.com") && ($.eventName!="HeadBucket") }':
                    unauthorized_metric_name = filter['metricTransformations'][0]['metricName']
                    break

            if not unauthorized_metric_name:
                results["4.1"] = {
                    "description": "Ensure unauthorized API calls are monitored.",
                    "result": {
                        "message": f"No compliance in {region}: Required metric filter for unauthorized API calls not found.",
                        "trail_details": {
                            "Name": multi_region_trail['Name'],
                            "CloudWatchLogsLogGroupArn": multi_region_trail.get('CloudWatchLogsLogGroupArn', "Not Configured"),
                            "IsMultiRegionTrail": multi_region_trail.get('IsMultiRegionTrail', False),
                            "MetricFilters": metric_filters
                        }
                    },
                    "status": "FAIL"
                }
                write_results_to_file(results)
                return

            # Step 4: Verify CloudWatch alarms
            alarms = cloudwatch_client.describe_alarms(MetricName=unauthorized_metric_name)['MetricAlarms']
            sns_topic_arn = None

            for alarm in alarms:
                sns_topic_arn = alarm['AlarmActions'][0] if alarm['AlarmActions'] else None
                break

            if not sns_topic_arn:
                results["4.1"] = {
                    "description": "Ensure unauthorized API calls are monitored.",
                    "result": {
                        "message": f"No compliance in {region}: No CloudWatch alarms found for unauthorized API calls metric.",
                        "trail_details": {
                            "Name": multi_region_trail['Name'],
                            "CloudWatchLogsLogGroupArn": multi_region_trail.get('CloudWatchLogsLogGroupArn', "Not Configured"),
                            "IsMultiRegionTrail": multi_region_trail.get('IsMultiRegionTrail', False),
                            "MetricName": unauthorized_metric_name,
                            "Alarms": alarms
                        }
                    },
                    "status": "FAIL"
                }
                write_results_to_file(results)
                return

            # Step 5: Verify SNS topic subscriptions
            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)['Subscriptions']
            valid_subscription = any(sub['SubscriptionArn'] for sub in subscriptions)

            if not valid_subscription:
                results["4.1"] = {
                    "description": "Ensure unauthorized API calls are monitored.",
                    "result": {
                        "message": f"No compliance in {region}: No active subscribers found for the SNS topic.",
                        "trail_details": {
                            "Name": multi_region_trail['Name'],
                            "CloudWatchLogsLogGroupArn": multi_region_trail.get('CloudWatchLogsLogGroupArn', "Not Configured"),
                            "IsMultiRegionTrail": multi_region_trail.get('IsMultiRegionTrail', False),
                            "SNSSubscriptions": subscriptions
                        }
                    },
                    "status": "FAIL"
                }
                write_results_to_file(results)
                return

        # If all regions are compliant
        results["4.1"] = {
            "description": "Ensure unauthorized API calls are monitored.",
            "result": "Account is compliant with CIS Benchmark 4.1 across all regions.",
            "explanation": explanation_4_1,
            "status": "PASS"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 4.1 check: {str(e)}")
        results["4.1"] = {
            "description": "Ensure unauthorized API calls are monitored.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)




def check_security_hub_enabled_and_update_results(session, results, explanation_4_16):
    """
    Checks if AWS Security Hub is enabled and updates the results dictionary.
    """
    securityhub_client = session.client('securityhub')

    try:
        response = securityhub_client.describe_hub()
        results["4.16"] = {
            "description": "Ensure AWS Security Hub is enabled.",
            "result": "AWS Security Hub is enabled.",
            "explanation": explanation_4_16,
            "status": "PASS"
        }
        write_results_to_file(results)
    except securityhub_client.exceptions.InvalidAccessException:
        results["4.16"] = {
            "description": "Ensure AWS Security Hub is enabled.",
            "result": "AWS Security Hub is not enabled.",
            "explanation": explanation_4_16,
            "status": "FAIL"
        }
        write_results_to_file(results)
    except Exception as e:
        logger.error(f"Error in 4.16 check: {str(e)}")
        results["4.16"] = {
            "description": "Ensure AWS Security Hub is enabled.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)


def check_ebs_encryption_by_default_and_update_results(session, results, explanation_5_1_1, regions):
    """
    Checks if EBS encryption is enabled by default in all regions and updates the results dictionary.
    """
    non_compliant_regions = []

    try:
        for region in regions:
            ec2_client = session.client('ec2', region_name=region)
            try:
                response = ec2_client.get_ebs_encryption_by_default()
                if not response['EbsEncryptionByDefault']:
                    non_compliant_regions.append({
                        "region": region,
                        "EbsEncryptionByDefault": response['EbsEncryptionByDefault']
                    })
            except Exception as e:
                logger.warning(f"Error checking region {region}: {e}")
                continue

        results["5.1.1"] = {
            "description": "Ensure EBS Volume Encryption is Enabled in all Regions.",
            "result": non_compliant_regions if non_compliant_regions else "All regions have EBS encryption enabled by default.",
            "explanation": explanation_5_1_1,
            "status": "PASS" if not non_compliant_regions else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 5.1.1 check: {str(e)}")
        results["5.1.1"] = {
            "description": "Ensure EBS Volume Encryption is Enabled in all Regions.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)



def check_nacls_ingress_ports_and_update_results(session, results, explanation_5_2):
    """
    Checks if NACLs allow ingress from 0.0.0.0/0 to TCP/UDP ports 22, 3389, or all protocols, and updates results.
    """
    ec2_client = session.client('ec2')
    violating_nacl_entries = []

    try:
        paginator = ec2_client.get_paginator('describe_network_acls')
        for page in paginator.paginate():
            for nacl in page['NetworkAcls']:
                for entry in nacl['Entries']:
                    if (entry.get('Egress', True) == False and
                        entry.get('CidrBlock') == '0.0.0.0/0' and
                        entry.get('RuleAction', '').lower() == 'allow' and
                        entry.get('Protocol') in ['6', '17', '-1']):

                        if 'PortRange' in entry:
                            if (entry['PortRange']['From'] <= 22 <= entry['PortRange']['To'] or
                                entry['PortRange']['From'] <= 3389 <= entry['PortRange']['To']):
                                violating_nacl_entries.append({
                                    'NACL ID': nacl['NetworkAclId'],
                                    'Rule Number': entry['RuleNumber'],
                                    'Port From': entry['PortRange']['From'],
                                    'Port To': entry['PortRange']['To'],
                                    'Traffic Type': 'Ingress',
                                    'CidrBlock': entry['CidrBlock']
                                })
                        elif entry.get('Protocol') == '-1':
                            violating_nacl_entries.append({
                                'NACL ID': nacl['NetworkAclId'],
                                'Rule Number': entry['RuleNumber'],
                                'Protocol': '-1 (All protocols)',
                                'Traffic Type': 'Ingress',
                                'CidrBlock': entry['CidrBlock']
                            })

        results["5.2"] = {
            "description": "Ensure VPC Network ACLs do not allow ingress from 0.0.0.0/0 to TCP/UDP ports 22, 3389 or all protocols.",
            "result": violating_nacl_entries if violating_nacl_entries else "No violating NACL entries found for ingress.",
            "explanation": explanation_5_2,
            "status": "PASS" if not violating_nacl_entries else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 5.2 check: {str(e)}")
        results["5.2"] = {
            "description": "Ensure VPC Network ACLs do not allow ingress from 0.0.0.0/0 to TCP/UDP ports 22, 3389 or all protocols.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)



def check_sgs_ingress_ports_and_update_results(session, results, explanation_5_3):
    """
    Checks if security groups allow ingress from 0.0.0.0/0 to administrative ports (e.g., 22, 3389) and updates results.
    """
    ec2_client = session.client('ec2')
    violating_sg_entries = []
    admin_ports = [22, 3389, -1, 0]

    try:
        paginator = ec2_client.get_paginator('describe_security_groups')
        for page in paginator.paginate():
            for sg in page['SecurityGroups']:
                for permission in sg['IpPermissions']:
                    if 'FromPort' in permission and 'ToPort' in permission:
                        for ip_range in permission['IpRanges']:
                            if ip_range.get('CidrIp') == '0.0.0.0/0' and (permission['FromPort'] in admin_ports or permission['ToPort'] in admin_ports):
                                violating_sg_entries.append({
                                    'Security Group ID': sg['GroupId'],
                                    'Port Range': f"{permission['FromPort']}-{permission['ToPort']}",
                                    'Protocol': permission.get('IpProtocol'),
                                    'Ingress': True,
                                    'Allowed CIDR': ip_range['CidrIp']
                                })

        results["5.3"] = {
            "description": "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports.",
            "result": violating_sg_entries if violating_sg_entries else "No security groups violate this policy.",
            "explanation": explanation_5_3,
            "status": "PASS" if not violating_sg_entries else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 5.3 check: {str(e)}")
        results["5.3"] = {
            "description": "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)




def check_sgs_ipv6_ingress_ports_and_update_results(session, results, explanation_5_4):
    """
    Checks if security groups allow ingress from ::/0 to administrative ports (IPv6) and updates results.
    """
    ec2_client = session.client('ec2')
    violating_sg_entries = []
    admin_ports = [22, 3389, -1, 0]

    try:
        paginator = ec2_client.get_paginator('describe_security_groups')
        for page in paginator.paginate():
            for sg in page['SecurityGroups']:
                for permission in sg['IpPermissions']:
                    for ipv6_range in permission.get('Ipv6Ranges', []):
                        if ipv6_range['CidrIpv6'] == '::/0':
                            port_range = range(permission.get('FromPort', 0), permission.get('ToPort', 0) + 1)
                            if any(port in admin_ports for port in port_range):
                                violating_sg_entries.append({
                                    'Security Group ID': sg['GroupId'],
                                    'Ingress Permission': permission
                                })

        results["5.4"] = {
            "description": "Ensure no security groups allow ingress from ::/0 to remote server administration ports (IPv6).",
            "result": violating_sg_entries if violating_sg_entries else "No violating security groups found.",
            "explanation": explanation_5_4,
            "status": "PASS" if not violating_sg_entries else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 5.4 check: {str(e)}")
        results["5.4"] = {
            "description": "Ensure no security groups allow ingress from ::/0 to remote server administration ports (IPv6).",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)



def check_default_sgs_restrict_all_traffic_and_update_results(session, results, explanation_5_5):
    """
    Checks if default security groups restrict all traffic and updates the results dictionary.
    """
    ec2_client = session.client('ec2')
    violating_sgs = []

    try:
        vpcs_paginator = ec2_client.get_paginator('describe_vpcs')
        for vpcs_page in vpcs_paginator.paginate():
            for vpc in vpcs_page['Vpcs']:
                default_sg_id = None
                sgs_paginator = ec2_client.get_paginator('describe_security_groups')
                for sgs_page in sgs_paginator.paginate(Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}]):
                    for sg in sgs_page['SecurityGroups']:
                        if sg['GroupName'] == 'default':
                            default_sg_id = sg['GroupId']
                            break

                if default_sg_id:
                    sg_details = ec2_client.describe_security_groups(GroupIds=[default_sg_id])
                    for sg in sg_details['SecurityGroups']:
                        if sg['IpPermissions']:
                            violating_sgs.append({
                                'VPC_ID': vpc['VpcId'],
                                'SecurityGroup_ID': sg['GroupId'],
                                'Violation': 'Unrestricted Ingress',
                                'Proof': 'Default security group has unrestricted ingress rules.',
                                'Ingress_Rules': sg['IpPermissions']
                            })
                        if sg['IpPermissionsEgress']:
                            violating_sgs.append({
                                'VPC_ID': vpc['VpcId'],
                                'SecurityGroup_ID': sg['GroupId'],
                                'Violation': 'Unrestricted Egress',
                                'Proof': 'Default security group has unrestricted egress rules.',
                                'Egress_Rules': sg['IpPermissionsEgress']
                            })

        results["5.5"] = {
            "description": "Ensure default security groups restrict all traffic.",
            "result": violating_sgs if violating_sgs else "All default security groups restrict all traffic.",
            "explanation": explanation_5_5,
            "status": "PASS" if not violating_sgs else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 5.5 check: {str(e)}")
        results["5.5"] = {
            "description": "Ensure default security groups restrict all traffic.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)



def check_vpc_peering_least_access_and_update_results(session, results, explanation_5_6):
    """
    Ensures routing tables for VPC peering connections follow the "least access" principle and updates results.
    """
    ec2_client = session.client('ec2')
    peering_violations = []

    try:
        # Retrieve all route tables
        route_tables = []
        route_tables_paginator = ec2_client.get_paginator('describe_route_tables')
        for route_tables_page in route_tables_paginator.paginate():
            route_tables.extend(route_tables_page['RouteTables'])

        # Check VPC peering connections
        peering_paginator = ec2_client.get_paginator('describe_vpc_peering_connections')
        for peering_page in peering_paginator.paginate():
            for connection in peering_page['VpcPeeringConnections']:
                peering_connection_id = connection['VpcPeeringConnectionId']

                for route_table in route_tables:
                    for route in route_table['Routes']:
                        if route.get('VpcPeeringConnectionId') == peering_connection_id:
                            if route.get('DestinationCidrBlock') == '0.0.0.0/0' or route.get('DestinationIpv6CidrBlock') == '::/0':
                                peering_violations.append({
                                    'PeeringConnectionId': peering_connection_id,
                                    'RouteTableId': route_table['RouteTableId'],
                                    'Route': route
                                })

        results["5.6"] = {
            "description": "Ensure routing tables for VPC peering are \"least access\".",
            "result": peering_violations if peering_violations else "All VPC peering connections are secure.",
            "explanation": explanation_5_6,
            "status": "PASS" if not peering_violations else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 5.6 check: {str(e)}")
        results["5.6"] = {
            "description": "Ensure routing tables for VPC peering are \"least access\".",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)


def check_ec2_imdsv2_and_update_results(session, results, explanation_5_7):
    """
    Ensures all EC2 instances use IMDSv2 and updates results.
    """
    ec2_client = session.client('ec2')
    imds_violations = []

    try:
        paginator = ec2_client.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    metadata_options = instance.get('MetadataOptions', {})
                    http_tokens = metadata_options.get('HttpTokens', '')

                    if http_tokens != 'required':
                        imds_violations.append({
                            'InstanceId': instance_id,
                            'HttpTokensValue': http_tokens
                        })

        results["5.7"] = {
            "description": "Ensure EC2 instances use IMDSv2.",
            "result": imds_violations if imds_violations else "All EC2 instances use IMDSv2.",
            "explanation": explanation_5_7,
            "status": "PASS" if not imds_violations else "FAIL"
        }
        write_results_to_file(results)

    except Exception as e:
        logger.error(f"Error in 5.7 check: {str(e)}")
        results["5.7"] = {
            "description": "Ensure EC2 instances use IMDSv2.",
            "result": f"Error occurred during check: {str(e)}",
            "status": "ERROR"
        }
        write_results_to_file(results)



def datetime_handler(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    raise TypeError("Type not serializable")


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
        result_content = json.dumps(value.get('result'), indent=4, default=datetime_handler) if isinstance(value.get('result'), (dict, list)) else value.get('result')
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




# Screenshots

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
                cropped_screenshot = screenshot.crop((0, 1, screenshot.width - 20, screenshot.height))  # Adjust crop as needed
                cropped_screenshot.save(screenshot_path)

                #print(f"Screenshot captured: {screenshot_path}")

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        driver.quit()

logging.basicConfig(filename='CIS_checker.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG)
logger = logging.getLogger()
results = {}



# ORIGINAL WRITE FUNCTION - WORKING
def write_results_to_file(results):
    def datetime_handler(x):
        if isinstance(x, datetime.datetime):
            return x.isoformat()
        raise TypeError("Unknown type")

    with open("results.json", "w") as outfile:
        json.dump(results, outfile, indent=4, default=datetime_handler)



print(" ")
print("Scan Complete")
print(" ")

def move_to_output(src_path, dest_directory):
    """
    Moves a file or directory to the specified destination directory.
    """
    if os.path.exists(src_path):
        dest_path = os.path.join(dest_directory, os.path.basename(src_path))
        shutil.move(src_path, dest_path)
    else:
        print(f"Source path does not exist: {src_path}")

check_functions = {
    "1.4": lambda: check_root_access_keys_and_update_results(session, results, explanation_1_4),
    "1.5": lambda: check_root_user_mfa(session, results, explanation_1_5),
    "1.6": lambda: check_root_virtual_mfa(session, results),
    "1.7": lambda: check_root_user_last_activity_and_update_results(session, results, explanation_1_7),
    "1.8": lambda: check_password_policy_and_update_results(session, results, explanation_1_8),
    "1.9": lambda: check_password_reuse_prevention_and_update_results(session, results, explanation_1_9),
    "1.10": lambda: check_mfa_on_users_and_update_results(session, results, explanation_1_10),
    "1.11": lambda: check_initial_user_setup_violations_and_update_results(session, results, explanation_1_11),
    "1.12": lambda: check_credentials_unused_and_update_results(session, results, explanation_1_12),
    "1.13": lambda: check_single_active_access_key_and_update_results(session, results, explanation_1_13),
    "1.14": lambda: check_access_key_rotation_and_update_results(session, results, explanation_1_14),
    "1.15": lambda: check_permissions_through_groups_and_update_results(session, results, explanation_1_15),
    "1.16": lambda: check_no_full_admin_policies_and_update_results(session, results, explanation_1_16),
    "1.17": lambda: check_support_role_with_policy_and_update_results(session, results, explanation_1_17),
    "1.18": lambda: check_iam_instance_roles_and_update_results(session, results),
    "1.19": lambda: check_expired_ssl_certificates_and_update_results(session, results, explanation_1_19),
    "1.20": lambda: check_access_analyzer_all_regions_and_update_results(session, results, explanation_1_20, regions),
    "1.21": lambda: check_centralized_iam_management_and_update_results(session, results, explanation_1_21),
    "1.22": lambda: check_cloudshell_full_access_restriction_and_update_results(session, results, explanation_1_22),
    "2.1.1": lambda: check_deny_http_requests_and_update_results(session, results, explanation_2_1_1),
    "2.1.2": lambda: check_mfa_delete_enabled_and_update_results(session, results, explanation_2_1_2),
    "2.1.4": lambda: check_s3_bucket_public_access_and_update_results(session, results, explanation_2_1_4),
    "2.2.1": lambda: check_rds_encryption_at_rest_and_update_results(session, results, explanation_2_2_1, regions),
    "2.2.2": lambda: check_rds_auto_minor_upgrade_and_update_results(session, results, explanation_2_2_2, regions),
    "2.2.3": lambda: check_rds_public_access_and_update_results(session, results, explanation_2_2_3, regions),
    "2.3.1": lambda: check_efs_encryption_and_update_results(session, results, explanation_2_3_1, regions),
    "3.1": lambda: check_cloudtrail_all_regions_and_update_results(session, results, explanation_3_1, regions),
    "3.2": lambda: check_cloudtrail_log_file_validation_and_update_results(session, results, explanation_3_2),
    "3.3": lambda: check_aws_config_all_regions_and_update_results(session, results, explanation_3_3, regions),
    "3.4": lambda: check_s3_bucket_logging_and_update_results(session, results, explanation_3_4),
    "3.5": lambda: check_cloudtrail_kms_encryption_and_update_results(session, results, explanation_3_5),
    "3.6": lambda: check_kms_key_rotation_and_update_results(session, results, explanation_3_6),
    "3.7": lambda: check_vpc_flow_logs_and_update_results(session, results, explanation_3_7),
    "3.8": lambda: check_object_level_logging_write_events_and_update_results(session, results, explanation_3_8),
    "3.9": lambda: check_object_level_logging_read_events_and_update_results(session, results, explanation_3_9),
    "4.1": lambda: check_unauthorized_api_calls_and_update_results(session, results, explanation_4_1, regions),
    "4.16": lambda: check_security_hub_enabled_and_update_results(session, results, explanation_4_16),
    "5.1.1": lambda: check_ebs_encryption_by_default_and_update_results(session, results, explanation_5_1_1, regions),
    "5.2": lambda: check_nacls_ingress_ports_and_update_results(session, results, explanation_5_2),
    "5.3": lambda: check_sgs_ingress_ports_and_update_results(session, results, explanation_5_3),
    "5.4": lambda: check_sgs_ipv6_ingress_ports_and_update_results(session, results, explanation_5_4),
    "5.5": lambda: check_default_sgs_restrict_all_traffic_and_update_results(session, results, explanation_5_5),
    "5.6": lambda: check_vpc_peering_least_access_and_update_results(session, results, explanation_5_6),
    "5.7": lambda: check_ec2_imdsv2_and_update_results(session, results, explanation_5_7),
}

def main():
    if args.html_only:
        if os.path.exists("results.json"):
            with open("results.json", "r") as f:
                results = json.load(f)
            # Regenerate HTML from existing results.json
            html_data = generate_html(results)
            with open('results.html', 'w') as f:
                f.write(html_data)
            print("HTML report regenerated: results.html")
        else:
            print("Error: results.json file not found. Run the script without --html-only first.")
        return

    profile_name = args.profile
    session = boto3.Session(profile_name=profile_name)

    DEFAULT_REGIONS = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]

    if args.regions:
        regions = args.regions.split(",")
    else:
        try:
            regions = [region['RegionName'] for region in session.client('ec2').describe_regions()['Regions']]
        except botocore.exceptions.ClientError as e:
            print(f"Error fetching AWS regions dynamically: {e}")
            print(f"Falling back to default regions: {', '.join(DEFAULT_REGIONS)}")
            regions = DEFAULT_REGIONS

    if args.check:
        if args.check in check_functions:
            print(f"Performing Check for {args.check}")
            check_functions[args.check]()
        else:
            print(f"Invalid check number: {args.check}")
            sys.exit(1)
    else:
        for check_number, check_function in check_functions.items():
            print(f"Performing Check for {check_number}")
            check_function()

    html_data = generate_html(results)
    with open('results.html', 'w') as f:
        f.write(html_data)
    print("HTML Created")

    print("Capturing Screenshots")
    current_dir = os.getcwd()
    html_file_path = os.path.join(current_dir, "results.html")
    output_directory = os.path.join(current_dir, "screenshots")

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    capture_screenshot(f"file:///{html_file_path}", output_directory)

    profile_name = args.profile if args.profile != 'default' and len(args.profile) > 1 else "AWSResults"
    output_directory = os.path.join(os.getcwd(), profile_name)

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    items_to_move = [
        os.path.join(os.getcwd(), 'results.json'),
        os.path.join(os.getcwd(), 'results.html'),
        os.path.join(os.getcwd(), 'screenshots')
    ]

    for item in items_to_move:
        move_to_output(item, output_directory)

    print("CIS Check Complete")

if __name__ == "__main__":
    main()
