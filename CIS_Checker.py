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
from tqdm import tqdm
from PIL import Image
from io import BytesIO
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.firefox import GeckoDriverManager


parser = argparse.ArgumentParser(description="AWS CIS Benchmark Checker")
parser.add_argument('--profile', default='default', help='Specify the AWS profile to use (default: "default")')
args = parser.parse_args()

profile_name = args.profile

session = boto3.Session(profile_name=profile_name)


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
explanation_4_16 = "AWS Security hub should be enabled."
explanation_5_1_1 = "EbsEncryptionByDefault should be set to true."
explanation_5_1 = ""
explanation_5_2 = ""
explanation_5_3 = ""
explanation_5_4 = "This should be disabled to encourage security group deveilopment with least privilege in mind."
explanation_5_5 = ""
explanation_5_6 = ""


iam = session.client('iam')

def check_root_access_keys():
    iam = session.client('iam')
    
    account_summary = iam.get_account_summary()
    keys_present = account_summary.get('SummaryMap', {}).get('AccountAccessKeysPresent', 0)

    if keys_present:
    
        return {
            "message": "Root access keys detected!",
            "AccountAccessKeysPresent": keys_present
        }
    else:
        return None


def check_1_5_root_user_mfa_enabled():
    iam_client = session.client('iam')
    
    account_summary = iam_client.get_account_summary()
    mfa_enabled_value = account_summary['SummaryMap']['AccountMFAEnabled']

    detail = {
        'AccountMFAEnabled': mfa_enabled_value,
        'message': 'MFA is enabled for the root user account.' if mfa_enabled_value == 1 else 'MFA is not enabled for the root user account!'
    }

    return detail


def check_root_virtual_mfa():
    iam_client = session.client('iam')
    root_has_mfa = False

    try:
        virtual_mfas = iam_client.list_virtual_mfa_devices()

        for mfa in virtual_mfas.get('VirtualMFADevices', []):
            if 'root' in mfa['SerialNumber']:
                root_has_mfa = True
                break

        return {
            "root_has_mfa": root_has_mfa,
            "virtual_mfas": virtual_mfas.get('VirtualMFADevices', [])
        }

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def check_root_user_last_activity():
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
            
    except Exception as e:
        print(f"Error fetching root user last activity details: {str(e)}")

    return root_user_activity



def check_1_8_password_policy_length():
    client = session.client('iam')
    
    try:
        password_policy = client.get_account_password_policy()
        
        if 'MinimumPasswordLength' in password_policy['PasswordPolicy']:
            return {
                "MinimumPasswordLength": password_policy['PasswordPolicy']['MinimumPasswordLength']
            }
    except Exception as e:
        print(f"Error fetching password policy details: {str(e)}")
    
    return None



def check_1_9_iam_password_reuse_prevention():
    iam_client = session.client('iam')
    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy', {})
       
        return password_policy
    except Exception as e:
        return {"Error": str(e)}



def check_1_10_mfa_on_users():
    client = session.client('iam')
    paginator = client.get_paginator('list_users')
    non_compliant_users = []

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

    return non_compliant_users



def check_initial_user_setup_violations():
    client = session.client('iam')

    users = client.list_users()
    violating_users = []

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

    return violating_users



def check_1_12_credentials_unused():
    client = session.client('iam')
    users = client.list_users()
    non_compliant_users = []

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
                break  
    return non_compliant_users


def check_1_13_single_active_access_key():
    client = session.client('iam')
    users = client.list_users()
    non_compliant_users = []

    for user in users['Users']:
        access_keys = client.list_access_keys(UserName=user['UserName'])
        active_keys = [key['AccessKeyId'] for key in access_keys['AccessKeyMetadata'] if key['Status'] == 'Active']

        if len(active_keys) > 1:
            non_compliant_users.append({
                "User": user['UserName'],
                "AccessKeyIds": active_keys
            })

    return non_compliant_users


def check_1_14_rotate_access_keys():
    client = session.client('iam')
    users = client.list_users()
    non_compliant_keys = []

    for user in users['Users']:
        access_keys = client.list_access_keys(UserName=user['UserName'])
        
        for key in access_keys['AccessKeyMetadata']:
            days_old = (datetime.datetime.now(datetime.timezone.utc) - key['CreateDate']).days
            if days_old > 90:
                non_compliant_keys.append({
                    "User": user['UserName'],
                    "AccessKeyId": key['AccessKeyId'],
                    "CreateDate": key['CreateDate']
                })

    return non_compliant_keys


def check_1_15_permissions_through_groups():
    client = session.client('iam')
    users = client.list_users()
    non_compliant_users = []

    for user in users['Users']:
        attached_policies = client.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
        inline_policies = client.list_user_policies(UserName=user['UserName'])['PolicyNames']

        if attached_policies or inline_policies:
            non_compliant_users.append({
                "User": user['UserName'],
                "AttachedPolicies": [policy['PolicyName'] for policy in attached_policies],
                "InlinePolicies": inline_policies
            })

    return non_compliant_users




def check_1_16_no_full_admin_policies():
    client = session.client('iam')
    paginator = client.get_paginator('list_policies')
    full_admin_policies = []

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

    return full_admin_policies







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



ec2 = session.client('ec2')

def check_1_18_iam_instance_roles():
    ec2_client = boto3.client('ec2')
    instances = ec2_client.describe_instances()
    instance_details = []

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_state = instance['State']['Name']
            launch_time = instance['LaunchTime']
            iam_role = instance['IamInstanceProfile']['Arn'] if 'IamInstanceProfile' in instance else "No IAM Role"
            
            instance_name = None
            for tag in instance['Tags']:
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

    return instance_details


def check_expired_ssl_certificates():
    iam_client = session.client('iam')
    certificates = iam_client.list_server_certificates()
    expired_certificates = []

    for certificate in certificates['ServerCertificateMetadataList']:
        expiration_date = certificate['Expiration']
        
        if expiration_date < datetime.datetime.now(expiration_date.tzinfo):
            expired_certificates.append({
                "ServerCertificateName": certificate['ServerCertificateName'],
                "Arn": certificate['Arn'],
                "UploadDate": certificate['UploadDate'],
                "Expiration": expiration_date
            })

    return expired_certificates



accessanalyzer = session.client('accessanalyzer')

def check_1_20_aws_access_analyzer_all_regions():
    sts_client = session.client('sts')
    account_id = sts_client.get_caller_identity()["Account"]

    try:
        regions = [region['RegionName'] for region in session.client('ec2').describe_regions()['Regions']]
    except botocore.exceptions.ClientError as e:
        print(f"Error fetching AWS regions: {e}")
        return []

    analyzer_violations = []

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
            print(f"Error checking AWS Access Analyzer in region {region}: {e}")

    return analyzer_violations





organizations = session.client('organizations')

def check_1_21_centralized_iam_management():
    iam_client = session.client('iam')
    
    identity_providers = iam_client.list_saml_providers()['SAMLProviderList']

    try:
        org_client = session.client('organizations')
        org_details = org_client.describe_organization()
        organizations_status = {
            "Available": True,
            "MasterAccountId": org_details['Organization']['MasterAccountId'],
            "MasterAccountEmail": org_details['Organization']['MasterAccountEmail']
        }
    except:
        organizations_status = {
            "Available": False
        }

    return {
        "Identity_Providers": [idp['Arn'] for idp in identity_providers],
        "AWS_Organizations_Status": organizations_status
    }


def check_1_22_cloudshell_full_access_restriction():
    iam_client = session.client('iam')

    def has_policy(attached_policies, policy_name):
        return any(policy['PolicyName'] == policy_name for policy in attached_policies)

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

    return {
        "Users_With_AWSCloudShellFullAccess": users_with_policy,
        "Roles_With_AWSCloudShellFullAccess": roles_with_policy,
        "Groups_With_AWSCloudShellFullAccess": groups_with_policy
    }


s3 = session.client('s3')
from botocore.exceptions import ClientError

def check_2_1_1_deny_http_requests():
    s3_client = session.client('s3')
    all_buckets = s3_client.list_buckets()['Buckets']
    insecure_buckets = []

    for bucket in tqdm(all_buckets, desc="This Can Take a While"):
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

    return insecure_buckets


def check_2_1_2_mfa_delete_enabled():
    s3_client = session.client('s3')
    bucket_details = []

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

    return bucket_details




#2.1.3 is manual and requires amazon macie

def check_s3_bucket_public_access():
    s3_client = session.client('s3')
    all_buckets = s3_client.list_buckets()
    non_compliant_buckets = []

    for bucket in all_buckets['Buckets']:
        bucket_name = bucket['Name']
        
        bucket_location = s3_client.get_bucket_location(Bucket=bucket_name)
        region = bucket_location['LocationConstraint']
        if not region:
            region = "us-east-1"
            
        try:
            response = s3_client.get_public_access_block(Bucket=bucket_name)
            settings = response['PublicAccessBlockConfiguration']
            
            if not all([settings['BlockPublicAcls'], 
                        settings['IgnorePublicAcls'], 
                        settings['BlockPublicPolicy'], 
                        settings['RestrictPublicBuckets']]):
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

    return non_compliant_buckets


rds = session.client('rds')


def check_2_2_1_rds_encryption_at_rest():
    ec2_client = session.client('ec2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    
    unencrypted_rds_details = []
    
    for region in regions:
        region_rds_client = session.client('rds', region_name=region)
        paginator = region_rds_client.get_paginator('describe_db_instances')

        for page in paginator.paginate():
            for instance in page['DBInstances']:
                storage_encrypted = instance.get('StorageEncrypted')
                if storage_encrypted is False:
                    unencrypted_rds_details.append({
                        'Region': region,
                        'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                        'StorageEncrypted': storage_encrypted
                    })
    
    return unencrypted_rds_details


def check_2_2_2_rds_auto_minor_upgrade():
    ec2_client = session.client('ec2')
    rds_client = session.client('rds')

    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    non_compliant_details = []

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

    return non_compliant_details


def check_2_2_3_rds_public_access():
    ec2_client = session.client('ec2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    public_access_rds_instances = []

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

    return public_access_rds_instances


def check_2_3_1_efs_encryption():
    efs_client = session.client('efs')
    regions = [region['RegionName'] for region in session.client('ec2').describe_regions()['Regions']]
    
    unencrypted_file_systems = {}

    for region in regions:
        region_efs_client = session.client('efs', region_name=region)

        try:
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

        except Exception as e:
            print(f"Error checking EFS encryption in region {region}: {e}")
            continue

    return unencrypted_file_systems


def check_3_1_cloudtrail_all_regions():
    cloudtrail_client = session.client('cloudtrail')
    regions = [region['RegionName'] for region in session.client('ec2').describe_regions()['Regions']]
    
    regions_without_cloudtrail = []
    
    for region in regions:
        region_cloudtrail_client = session.client('cloudtrail', region_name=region)
        
        try:
            trails = region_cloudtrail_client.describe_trails()
            if trails['trailList']:
                trail_status = [region_cloudtrail_client.get_trail_status(Name=trail['Name']) for trail in trails['trailList']]
                if not any(ts['IsLogging'] and ts['IncludeGlobalServiceEvents'] for ts in trail_status):
                    regions_without_cloudtrail.append(region)
            else:
                regions_without_cloudtrail.append(region)
        
        except Exception as e:
            # Handling the exception silently
            pass
    
    return regions_without_cloudtrail


def check_3_2_cloudtrail_log_file_validation():
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
                
    except Exception as e:
        print(f"Error checking CloudTrail log file validation: {e}")
    
    return trails_without_validation

def check_3_3_aws_config_all_regions():
    client = session.client('config')
    regions = [region['RegionName'] for region in session.client('ec2').describe_regions()['Regions']]
    
    region_statuses = []
    for region in regions:
        region_client = session.client('config', region_name=region)
        try:
            status = region_client.describe_configuration_recorders()['ConfigurationRecorders'][0]['recording']
            region_statuses.append({
                "region": region,
                "recording": status
            })
        except:
            region_statuses.append({
                "region": region,
                "recording": False
            })
    
    return region_statuses

def check_3_4_s3_bucket_logging():
    cloudtrail_client = session.client('cloudtrail')
    s3_client = session.client('s3')
    
    trails = cloudtrail_client.describe_trails()['trailList']
    
    bucket_logging_details = []
    
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

    return bucket_logging_details

def check_3_5_cloudtrail_kms_encryption():
    cloudtrail_client = session.client('cloudtrail')
    
    trails = cloudtrail_client.describe_trails()['trailList']
    
    trail_encryption_details = []
    
    for trail in trails:
        trail_name = trail['Name']
        kms_key_id = trail.get('KmsKeyId', None)
        
        trail_encryption_details.append({
            'TrailName': trail_name,
            'KmsKeyId': kms_key_id
        })

    return trail_encryption_details

def check_3_6_kms_key_rotation():
    kms_client = session.client('kms')
    
    paginator = kms_client.get_paginator('list_keys')
    
    cmk_rotation_details = []
    
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

    return cmk_rotation_details

def check_3_7_vpc_flow_logs():
    ec2_client = session.client('ec2')
    vpcs_without_flow_logs = []

    vpcs = ec2_client.describe_vpcs()['Vpcs']
    all_vpc_ids = [vpc['VpcId'] for vpc in vpcs]

    flow_logs = ec2_client.describe_flow_logs()['FlowLogs']
    vpc_ids_with_flow_logs = [flow_log['ResourceId'] for flow_log in flow_logs]

    for vpc_id in all_vpc_ids:
        if vpc_id not in vpc_ids_with_flow_logs:
            vpcs_without_flow_logs.append(vpc_id)

    return vpcs_without_flow_logs

def check_3_8_object_level_logging():
    cloudtrail_client = session.client('cloudtrail')
    all_trails = cloudtrail_client.list_trails()['Trails']
    trail_details = []

    if not all_trails:
        trail_details.append({
            'Error': 'No CloudTrail trails are configured.'
        })
        return trail_details

    for trail_summary in all_trails:
        trail_arn = trail_summary['TrailARN']
        try:
            trail = cloudtrail_client.get_trail(Name=trail_arn)
            trail_status = cloudtrail_client.get_trail_status(Name=trail_arn)

            is_multi_region_trail = trail.get('Trail', {}).get('IsMultiRegionTrail')
            event_selectors = cloudtrail_client.get_event_selectors(TrailName=trail_arn)

            s3_data_event_selectors = [
                selector for selector in event_selectors['EventSelectors']
                if any(resource for resource in selector['DataResources'] if resource['Type'] == 'AWS::S3::Object')
            ]

            for selector in s3_data_event_selectors:
                write_events_enabled = 'WriteOnly' in selector.get('ReadWriteType') or 'All' in selector.get('ReadWriteType')

                trail_detail = {
                    'TrailName': trail_summary['Name'],
                    'HomeRegion': trail_summary['HomeRegion'],
                    'IsMultiRegionTrail': is_multi_region_trail,
                    'HasS3WriteEvents': write_events_enabled,
                    'HasS3ReadEvents': 'ReadOnly' in selector.get('ReadWriteType') or 'All' in selector.get('ReadWriteType'),
                    'Compliant': write_events_enabled and is_multi_region_trail
                }
                trail_details.append(trail_detail)

        except ClientError as e:
            trail_details.append({
                'TrailName': trail_summary['Name'],
                'Error': str(e)
            })

    return trail_details

def check_3_9_object_level_logging_for_read_events():
    cloudtrail_client = session.client('cloudtrail')
    all_trails = cloudtrail_client.list_trails()['Trails']
    trail_details = []

    if not all_trails: 
        trail_details.append({
            'Error': 'No CloudTrail trails are configured.'
        })
        return trail_details

    for trail_summary in all_trails:
        trail_arn = trail_summary['TrailARN']
        try:
            trail = cloudtrail_client.get_trail(Name=trail_arn)
            event_selectors = cloudtrail_client.get_event_selectors(TrailName=trail_arn)

            for selector in event_selectors['EventSelectors']:
                for resource in selector.get('DataResources', []):
                    if resource['Type'] == 'AWS::S3::Object':
                        read_events_enabled = 'ReadOnly' in selector.get('ReadWriteType') or 'All' in selector.get('ReadWriteType')

                        trail_detail = {
                            'TrailName': trail_summary['Name'],
                            'HomeRegion': trail_summary['HomeRegion'],
                            'HasS3ReadEvents': read_events_enabled,
                            'Compliant': read_events_enabled
                        }
                        trail_details.append(trail_detail)

        except ClientError as e:
            trail_details.append({
                'TrailName': trail_summary['Name'],
                'Error': str(e)
            })

    return trail_details



# SKIPPED 4.x MONITOR SECTION

def check_4_1_unauthorized_api_calls_monitored():
    cloudtrail_client = boto3.client('cloudtrail')
    logs_client = boto3.client('logs')
    cloudwatch_client = boto3.client('cloudwatch')
    sns_client = boto3.client('sns')

    # Step 1: List all CloudTrail trails and identify active multi-region trails
    trails = cloudtrail_client.describe_trails()['trailList']
    multi_region_trail = None

    for trail in trails:
        if trail['IsMultiRegionTrail']:
            trail_status = cloudtrail_client.get_trail_status(Name=trail['Name'])
            if trail_status['IsLogging']:
                multi_region_trail = trail
                trail_log_group_name = multi_region_trail['CloudWatchLogsLogGroupArn'].split(':')[-1].split('*')[0]
                break

    if not multi_region_trail:
        return "No active multi-region CloudTrail trail found."

    # Step 2: Check event selectors for management events
    event_selectors = cloudtrail_client.get_event_selectors(TrailName=multi_region_trail['Name'])
    management_events = any(
        selector.get('IncludeManagementEvents') and selector.get('ReadWriteType') == 'All'
        for selector in event_selectors['EventSelectors']
    )

    if not management_events:
        return "Multi-region CloudTrail trail does not capture all management events."

    # Step 3: Describe metric filters
    metric_filters = logs_client.describe_metric_filters(logGroupName=trail_log_group_name)['metricFilters']
    unauthorized_metric_name = None

    for filter in metric_filters:
        if filter[
            'filterPattern'] == '{ ($.errorCode ="*UnauthorizedOperation") || ($.errorCode ="AccessDenied*") && ($.sourceIPAddress!="delivery.logs.amazonaws.com") && ($.eventName!="HeadBucket") }':
            unauthorized_metric_name = filter['metricTransformations'][0]['metricName']
            break

    if not unauthorized_metric_name:
        return "Required metric filter for unauthorized API calls not found."

    # Step 4: Describe CloudWatch alarms for the unauthorized API calls metric
    alarms = cloudwatch_client.describe_alarms(MetricName=unauthorized_metric_name)['MetricAlarms']
    sns_topic_arn = None

    for alarm in alarms:
        sns_topic_arn = alarm['AlarmActions'][0] if alarm['AlarmActions'] else None
        break

    if not sns_topic_arn:
        return "No CloudWatch alarms found for unauthorized API calls metric."

    # Step 5: Ensure there is at least one active subscriber to the SNS topic
    subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)['Subscriptions']
    valid_subscription = any(sub['SubscriptionArn'] for sub in subscriptions)

    if not valid_subscription:
        return "No active subscribers found for the SNS topic."

    return "Account is compliant with CIS Benchmark 4.1."


def check_4_16_security_hub_enabled():
    securityhub_client = session.client('securityhub')

    try:
        response = securityhub_client.describe_hub()
        return True
    except securityhub_client.exceptions.InvalidAccessException:
        return False
    except Exception as e:
        print(f"Error checking if Security Hub is enabled: {e}")
        return None


def check_5_1_1_ebs_encryption_by_default():
    ec2_regions = [region['RegionName'] for region in session.client('ec2').describe_regions()['Regions']]
    non_compliant_regions = []

    for region in ec2_regions:
        ec2_client = session.client('ec2', region_name=region)
        try:
            response = ec2_client.get_ebs_encryption_by_default()
            if not response['EbsEncryptionByDefault']:
                non_compliant_regions.append({
                    "region": region,
                    "EbsEncryptionByDefault": response['EbsEncryptionByDefault']
                })
        except Exception as e:
            print(f"Error checking region {region}: {e}")
            continue

    return non_compliant_regions

def check_5_2_nacls_ingress_ports():
    ec2_client = session.client('ec2')
    admin_ports = [22, 3389, -1, 0]
    violating_nacl_entries = []

    paginator = ec2_client.get_paginator('describe_network_acls')
    page_iterator = paginator.paginate()

    for page in page_iterator:
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

    return violating_nacl_entries



def check_5_3_sgs_ingress_ports():
    ec2_client = session.client('ec2')
    paginator = ec2_client.get_paginator('describe_security_groups')
    violating_sg_entries = []
    admin_ports = [22, 3389, -1, 0]

    page_iterator = paginator.paginate()
    for page in page_iterator:
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

    return violating_sg_entries




def check_5_4_sgs_ipv6_ingress_ports():
    ec2_client = session.client('ec2')
    violating_sg_entries = []
    admin_ports = [22, 3389, -1, 0]

    paginator = ec2_client.get_paginator('describe_security_groups')
    page_iterator = paginator.paginate()

    for page in page_iterator:
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

    return violating_sg_entries




def check_5_5_default_sgs_restrict_all_traffic():
    ec2_client = session.client('ec2')
    violating_sgs = []

    vpcs_paginator = ec2_client.get_paginator('describe_vpcs')
    vpcs_page_iterator = vpcs_paginator.paginate()

    for vpcs_page in vpcs_page_iterator:
        for vpc in vpcs_page['Vpcs']:
            default_sg_id = None
            sgs_paginator = ec2_client.get_paginator('describe_security_groups')
            sgs_page_iterator = sgs_paginator.paginate(Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])

            for sgs_page in sgs_page_iterator:
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
                            'Proof': 'This is the default security group for the VPC.',
                            'Ingress_Rules': sg['IpPermissions']
                        })
                    if sg['IpPermissionsEgress']:
                        violating_sgs.append({
                            'VPC_ID': vpc['VpcId'],
                            'SecurityGroup_ID': sg['GroupId'],
                            'Violation': 'Unrestricted Egress',
                            'Proof': 'This is the default security group for the VPC.',
                            'Egress_Rules': sg['IpPermissionsEgress']
                        })

    return violating_sgs




def check_5_6_vpc_peering_least_access():
    ec2_client = session.client('ec2')
    peering_violations = []


    peering_paginator = ec2_client.get_paginator('describe_vpc_peering_connections')
    peering_page_iterator = peering_paginator.paginate()

    route_tables_paginator = ec2_client.get_paginator('describe_route_tables')
    route_tables_page_iterator = route_tables_paginator.paginate()

    route_tables = []
    for route_tables_page in route_tables_page_iterator:
        route_tables.extend(route_tables_page['RouteTables'])

    for peering_page in peering_page_iterator:
        for connection in peering_page['VpcPeeringConnections']:
            peering_connection_id = connection['VpcPeeringConnectionId']

            for route_table in route_tables:
                for route in route_table['Routes']:
                    if 'VpcPeeringConnectionId' in route and route['VpcPeeringConnectionId'] == peering_connection_id:
                        if route.get('DestinationCidrBlock') == '0.0.0.0/0' or route.get('DestinationIpv6CidrBlock') == '::/0':
                            peering_violations.append({
                                'PeeringConnectionId': peering_connection_id,
                                'RouteTableId': route_table['RouteTableId'],
                                'Route': route
                            })

    return peering_violations




def check_5_7_ec2_imdsv2_only():
    ec2_client = session.client('ec2')
    imds_violations = []

    paginator = ec2_client.get_paginator('describe_instances')
    page_iterator = paginator.paginate()
    
    for page in page_iterator:
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

    return imds_violations


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








print("Performing Check for 1.4")
root_access_key_violations = check_root_access_keys()
results["1.4"] = {
    "description": "Ensure no 'root' user account access key exists",
    "result": root_access_key_violations if root_access_key_violations else "No root access keys found.",
    "explanation": explanation_1_4,
    "status": "PASS" if not root_access_key_violations else "FAIL"
}
write_results_to_file(results)


print("Performing Check for 1.5")
root_mfa_details = check_1_5_root_user_mfa_enabled()
results["1.5"] = {
    "description": "Ensure MFA is enabled for the 'root' user account",
    "result": root_mfa_details,
    "explanation": explanation_1_5,
    "status": "PASS" if root_mfa_details['AccountMFAEnabled'] == 1 else "FAIL"
}
write_results_to_file(results)



print("Performing Check for 1.6")
try:
    root_mfa_response = check_root_virtual_mfa()

    if root_mfa_response and root_mfa_response["root_has_mfa"]:
        results["1.6"] = {
            "description": "Ensure hardware MFA is enabled for the 'root' user account",
            "result": root_mfa_response["virtual_mfas"],
            "status": "FAIL"
        }
    else:
        results["1.6"] = {
            "description": "Ensure hardware MFA is enabled for the 'root' user account",
            "result": root_mfa_response["virtual_mfas"] if root_mfa_response else "Error in retrieving data",
            "status": "PASS" if root_mfa_response else "ERROR"
        }
    
    write_results_to_file(results)

except Exception as e:
    logger.error(f"Error in Root Virtual MFA check: {str(e)}")
    results["1.6"] = {
        "description": "Ensure hardware MFA is enabled for the 'root' user account",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }
    write_results_to_file(results)




print("Performing Check for 1.7")
root_user_activity = check_root_user_last_activity()

if root_user_activity["LastUsedDate"] == "Never Used":
    status = "PASS"
else:
    last_used_datetime = datetime.strptime(root_user_activity["LastUsedDate"], '%Y-%m-%d %H:%M:%S')
    status = "PASS" if (datetime.utcnow() - last_used_datetime).days > 90 else "FAIL"

results["1.7"] = {
    "description": "Eliminate use of the 'root' user for administrative and daily tasks",
    "result": root_user_activity,
    "explanation": explanation_1_7,
    "status": status
}
write_results_to_file(results)


print("Performing Check for 1.8")

password_policy_details = check_1_8_password_policy_length()
results["1.8"] = {
    "description": "Ensure IAM password policy requires minimum length of 14 or greater",
    "result": password_policy_details,
    "explanation": explanation_1_8,
    "status": "PASS" if password_policy_details and password_policy_details["MinimumPasswordLength"] >= 14 else "FAIL"
}
write_results_to_file(results)


print("Performing Check for 1.9")
try:
    password_policy = check_1_9_iam_password_reuse_prevention()

    if "Error" not in password_policy:
        reuse_prevention_value = password_policy.get('PasswordReusePrevention', 0)
        results["1.9"] = {
            "description": "Ensure IAM password policy prevents password reuse.",
            "result": password_policy,
            "explanation": explanation_1_9,
            "status": "PASS" if reuse_prevention_value and reuse_prevention_value >= 24 else "FAIL"
        }
    else:
        results["1.9"] = {
            "description": "Ensure IAM password policy prevents password reuse.",
            "result": password_policy,
            "explanation": explanation_1_9,
            "status": "ERROR"
        }
    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error in 1.9 check: {str(e)}")
    results["1.9"] = {
        "description": "Ensure IAM password policy prevents password reuse.",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }
    write_results_to_file(results)




print("Performing Check for 1.10")

mfa_details = check_1_10_mfa_on_users()
results["1.10"] = {
    "description": "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
    "result": mfa_details,
    "explanation": explanation_1_10,
    "status": "PASS" if not mfa_details else "FAIL"
}
write_results_to_file(results)

print("Performing Check for 1.11")
try:
    violating_users = check_initial_user_setup_violations()
    results["1.11"] = {
        "description": "Do not setup access keys during initial user setup for all IAM users that have a console password",
        "result": violating_users if violating_users else "All users comply.",
        "explanation": explanation_1_11,
        "status": "PASS" if not violating_users else "FAIL"
    }
    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error in 1.11 check: {str(e)}")
    results["1.11"] = {
        "description": "Do not setup access keys during initial user setup for all IAM users that have a console password",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }


print("Performing Check for 1.12")
credentials_unused_details = check_1_12_credentials_unused()
results["1.12"] = {
    "description": "Ensure credentials unused for 45 days or greater are disabled",
    "result": credentials_unused_details,
    "explanation": explanation_1_12,
    "status": "PASS" if not credentials_unused_details else "FAIL"
}
write_results_to_file(results)


print("Performing Check for 1.13")
single_active_key_details = check_1_13_single_active_access_key()
results["1.13"] = {
    "description": "Ensure there is only one active access key available for any single IAM user",
    "result": single_active_key_details,
    "explanation": explanation_1_13,
    "status": "PASS" if not single_active_key_details else "FAIL"
}
write_results_to_file(results)

print("Performing Check for 1.14")
rotate_key_details = check_1_14_rotate_access_keys()
results["1.14"] = {
    "description": "Ensure access keys are rotated every 90 days or less",
    "result": rotate_key_details,
    "explanation": explanation_1_14,
    "status": "PASS" if not rotate_key_details else "FAIL"
}
write_results_to_file(results)

print("Performing Check for 1.15")
permissions_details = check_1_15_permissions_through_groups()
results["1.15"] = {
    "description": "Ensure IAM Users Receive Permissions Only Through Groups",
    "result": permissions_details,
    "explanation": explanation_1_15,
    "status": "PASS" if not permissions_details else "FAIL"
}
write_results_to_file(results)



print("Performing Check for 1.16")
try:
    full_admin_policies_details = check_1_16_no_full_admin_policies()

    results["1.16"] = {
        "description": "Ensure no policies grant full administrative privileges.",
        "result": full_admin_policies_details if full_admin_policies_details else "No policies found with full administrative privileges.",
        "explanation": explanation_1_16,
        "status": "PASS" if not full_admin_policies_details else "FAIL"
    }
    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error in 1.16 check: {str(e)}")
    results["1.16"] = {
        "description": "Ensure no policies grant full administrative privileges.",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }
    write_results_to_file(results)




print("Performing Check for 1.17")
try:
    support_policy_data = check_support_role_with_policy()

    if "Error" in support_policy_data:
        # Handle the error case
        results["1.17"] = {
            "description": "Ensure a support role has been created to manage incidents with AWS Support",
            "result": f"Error occurred: {support_policy_data['Error']}",
            "status": "ERROR"
        }
    elif support_policy_data['PolicyArn'] != "Not Found":
        results["1.17"] = {
            "description": "Ensure a support role has been created to manage incidents with AWS Support",
            "result": support_policy_data,
            "explanation": explanation_1_17,
            "status": "PASS" if support_policy_data['PolicyRoles'] else "FAIL"
        }
    else:
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


print("Performing Check for 1.18")
try:
    instance_role_details = check_1_18_iam_instance_roles()
    instances_without_roles = [detail for detail in instance_role_details if detail['IAMRole'] == "No IAM Role"]

    results["1.18"] = {
        "description": "Ensure IAM instance roles are used for AWS resource access from instances",
        "result": instances_without_roles,
        "status": "PASS" if not instances_without_roles else "FAIL"
    }
    write_results_to_file(results)
except Exception as e:
    results["1.18"] = {
        "description": "Ensure IAM instance roles are used for AWS resource access from instances",
        "result": f"Error occurred: {str(e)}",
        "status": "ERROR"
    }





print("Performing Check for 1.19")
try:
    expired_certs = check_expired_ssl_certificates()
    results["1.19"] = {
        "description": "Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed",
        "result": expired_certs,
        "explanation": explanation_1_19,
        "status": "PASS" if not expired_certs else "FAIL"
    }
    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error during check 1.19: {str(e)}")
    results["1.19"] = {
        "description": "Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed",
        "result": f"Error occurred: {str(e)}",
        "status": "ERROR"
    }


print("Performing Check for 1.20")
try:
    analyzer_violations = check_1_20_aws_access_analyzer_all_regions()

    formatted_details = []

    if analyzer_violations:
        for violation in analyzer_violations:
            formatted_details.append({
                "Region": violation['Region'],
                "AccountId": violation['AccountId'],
                "Status": violation['Status']
            })
        
        results["1.20"] = {
            "description": "Ensure AWS Access Analyzer is enabled in all regions",
            "result": formatted_details,
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



print("Performing Check for 1.21")
try:
    centralized_iam_details = check_1_21_centralized_iam_management()
    results["1.21"] = {
        "description": "Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments",
        "result": {
            "Identity_Providers": centralized_iam_details['Identity_Providers'],
            "AWS_Organizations_Status": centralized_iam_details['AWS_Organizations_Status']
        },
        "explanation": explanation_1_21,
        "status": "PASS" if centralized_iam_details['Identity_Providers'] or centralized_iam_details['AWS_Organizations_Status']['Available'] else "FAIL"
    }
    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error in 1.21 check: {str(e)}")
    results["1.21"] = {
        "description": "Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }


print("Performing Check for 1.22")
cloudshell_access_details = check_1_22_cloudshell_full_access_restriction()
results["1.22"] = {
    "description": "Ensure access to AWSCloudShellFullAccess is restricted",
    "result": cloudshell_access_details,
    "explanation": explanation_1_22,
    "status": "PASS" if not cloudshell_access_details['Users_With_AWSCloudShellFullAccess'] and not cloudshell_access_details['Roles_With_AWSCloudShellFullAccess'] and not cloudshell_access_details['Groups_With_AWSCloudShellFullAccess'] else "FAIL"
}
write_results_to_file(results)


print("Performing Check for 2.1.1")
try:
    insecure_buckets = check_2_1_1_deny_http_requests()
    if insecure_buckets:
        results["2.1.1"] = {
            "description": "Ensure that S3 buckets deny HTTP requests when not using Secure Transport.",
            "result": insecure_buckets,
            "explanation": explanation_2_1_1,
            "status": "FAIL"
        }
    else:
        results["2.1.1"] = {
            "description": "Ensure that S3 buckets deny HTTP requests when not using Secure Transport.",
            "result": "All buckets are secure or have no bucket policy.",
            "explanation": explanation_2_1_1,
            "status": "PASS"
        }
    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error in 2.1.1 check: {str(e)}")
    results["2.1.1"] = {
        "description": "Ensure that S3 buckets deny HTTP requests when not using Secure Transport.",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }


print("Performing Check for 2.1.2")
try:
    mfa_check_results = check_2_1_2_mfa_delete_enabled()
    failed_buckets = [r for r in mfa_check_results if 'Error' not in r]
    
    if failed_buckets:
        results["2.1.2"] = {
            "description": "Ensure that S3 Buckets have MFA Delete enabled.",
            "result": failed_buckets,
            "explanation": explanation_2_1_2,
            "status": "FAIL"
        }
    else:
        results["2.1.2"] = {
            "description": "Ensure that S3 Buckets have MFA Delete enabled.",
            "result": "All S3 Buckets have MFA Delete enabled or no versioning enabled buckets without MFA Delete.",
            "status": "PASS"
        }
    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error in 2.1.2 check: {str(e)}")
    results["2.1.2"] = {
        "description": "Ensure that S3 Buckets have MFA Delete enabled.",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }


print("Performing Check for 2.1.4")
try:
    non_compliant_buckets = check_s3_bucket_public_access()
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

print("Performing Check for 2.2.1")
try:
    unencrypted_rds_details = check_2_2_1_rds_encryption_at_rest()
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

print("Performing Check for 2.2.2")
try:
    auto_minor_upgrade_details = check_2_2_2_rds_auto_minor_upgrade()
    if auto_minor_upgrade_details:
        results["2.2.2"] = {
            "description": "Ensure RDS instances have Auto Minor Version Upgrade enabled.",
            "result": auto_minor_upgrade_details,
            "explanation": explanation_2_2_2,
            "status": "FAIL"
        }
    else:
        results["2.2.2"] = {
            "description": "Ensure RDS instances have Auto Minor Version Upgrade enabled.",
            "result": "All RDS instances have Auto Minor Version Upgrade enabled.",
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


print("Performing Check for 2.2.3")
try:
    public_access_rds_instances = check_2_2_3_rds_public_access()
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

print("Performing Check for 2.3.1")
try:
    unencrypted_efs_by_region = check_2_3_1_efs_encryption()
    if unencrypted_efs_by_region:
        formatted_results = []
        for region, fs_details in unencrypted_efs_by_region.items():
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


print("Performing Check for 3.1")
regions_missing_cloudtrail = check_3_1_cloudtrail_all_regions()
results["3.1"] = {
    "description": "Ensure CloudTrail is enabled in all regions",
    "result": regions_missing_cloudtrail if regions_missing_cloudtrail else "CloudTrail is enabled in all regions",
    "explanation": explanation_3_1,
    "status": "PASS" if not regions_missing_cloudtrail else "FAIL"
}
write_results_to_file(results)



print("Performing Check for 3.2")
try:
    validation_violations = check_3_2_cloudtrail_log_file_validation()
    
    formatted_violations = []
    for info in validation_violations:
        formatted_violations.append({
            "TrailName": info['TrailName'],
            "LogFileValidationEnabled": info['LogFileValidationEnabled']
        })
    
    if formatted_violations:
        results["3.2"] = {
            "description": "Ensure CloudTrail log file validation is enabled.",
            "result": formatted_violations,
            "explanation": explanation_3_2,
            "status": "FAIL"
        }
    else:
        results["3.2"] = {
            "description": "Ensure CloudTrail log file validation is enabled.",
            "result": "All trails have log file validation enabled.",
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

print("Performing Check for 3.3")
try:
    config_details = check_3_3_aws_config_all_regions()

    non_configured_regions = [info for info in config_details if not info.get('recording')]

    results["3.3"] = {
        "description": "Ensure AWS Config is enabled in all regions.",
        "result": config_details,
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

print("Performing Check for 3.4")
try:
    logging_details = check_3_4_s3_bucket_logging()

    buckets_without_logging = [detail for detail in logging_details if not detail.get('LoggingEnabled', False) or "Error" in str(detail['LoggingEnabled'])]

    results["3.6"] = {
        "description": "Ensure S3 bucket logging is enabled.",
        "result": logging_details,
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

print("Performing Check for 3.5")
try:
    encryption_details = check_3_5_cloudtrail_kms_encryption()
    formatted_details = []
    for detail in encryption_details:
        formatted_details.append(f"Trail: {detail['TrailName']}, KmsKeyId: {detail['KmsKeyId']}")

    trails_without_kms_encryption = [detail for detail in encryption_details if not detail.get('KmsKeyId')]
    
    results["3.7"] = {
        "description": "Ensure CloudTrail is encrypted with KMS CMKs.",
        "result": encryption_details,
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

print("Performing Check for 3.6")
try:
    rotation_details = check_3_6_kms_key_rotation()
    
    cmk_ids_without_rotation = [detail for detail in rotation_details if not detail.get('KeyRotationEnabled')]
    
    results["3.6"] = {
        "description": "Ensure rotation for customer-created KMS keys is enabled.",
        "result": rotation_details,
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

print("Performing Check for 3.7")
try:
    vpcs_without_logs = check_3_7_vpc_flow_logs()

    if vpcs_without_logs:
        formatted_details = [{"VPC": vpc} for vpc in vpcs_without_logs]
        result_string = "Flow logging is not enabled for the following VPCs: " + ", ".join(vpcs_without_logs)
    else:
        formatted_details = "Flow logging is enabled for all VPCs"
        result_string = formatted_details

    results["3.7"] = {
        "description": "Ensure VPC flow logging is enabled in all VPCs",
        "result": formatted_details,
        "explanation": explanation_3_7,
        "status": "PASS" if not vpcs_without_logs else "FAIL"
    }
    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error in 3.7 check: {str(e)}")
    results["3.7"] = {
        "description": "Ensure that object-level logging for write events is enabled for S3 buckets.",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }

print("Performing Check for 3.8")
try:
    trail_details = check_3_8_object_level_logging()
    non_compliant_trails = [detail for detail in trail_details if not detail.get('Compliant')]
    
    if non_compliant_trails:
        results["3.8"] = {
            "description": "Ensure that object-level logging for write events is enabled for S3 buckets.",
            "result": non_compliant_trails,
            "explanation": explanation_3_8,
            "status": "FAIL"
        }
    else:
        results["3.8"] = {
            "description": "Object-level logging for write events is enabled for S3 buckets.",
            "result": trail_details,
            "explanation": explanation_3_8,
            "status": "PASS"
        }
    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error in 3.8 check: {str(e)}")
    results["3.8"] = {
        "description": "Ensure that object-level logging for write events is enabled for S3 buckets.",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }


print("Performing Check for 3.9")
try:
    trail_details = check_3_9_object_level_logging_for_read_events()
    non_compliant_trails = [detail for detail in trail_details if not detail.get('Compliant')]

    if non_compliant_trails:
        results["3.9"] = {
            "description": "Ensure that object-level logging for read events is enabled for S3 buckets.",
            "result": non_compliant_trails,
            "explanation": explanation_3_9,
            "status": "FAIL"
        }
    else:
        results["3.9"] = {
            "description": "Object-level logging for read events is enabled for S3 buckets.",
            "result": trail_details,
            "explanation": explanation_3_9,
            "status": "PASS"
        }
    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error in 3.9 check: {str(e)}")
    results["3.9"] = {
        "description": "Ensure that object-level logging for read events is enabled for S3 buckets.",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }

print("Performing Check for 4.1")
try:
    unauthorized_api_monitoring = check_4_1_unauthorized_api_calls_monitored()
    if unauthorized_api_monitoring == "Account is compliant with CIS Benchmark 4.1.":
        results["4.1"] = {
            "description": "Ensure unauthorized API calls are monitored.",
            "result": "Unauthorized API calls are monitored",
            "status": "PASS"
        }
    else:
        results["4.1"] = {
            "description": "Ensure unauthorized API calls are monitored.",
            "result": unauthorized_api_monitoring,
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

print("Performing Check for 4.16")
try:
    security_hub_status = check_4_16_security_hub_enabled()
    
    if security_hub_status is True:
        results["4.16"] = {
            "description": "Ensure AWS Security Hub is enabled.",
            "result": "AWS Security Hub is enabled.",
            "status": "PASS"
        }
    elif security_hub_status is False:
        results["4.16"] = {
            "description": "Ensure AWS Security Hub is enabled.",
            "result": "AWS Security Hub is not enabled.",
            "explanation": explanation_4_16,
            "status": "FAIL"
        }
    else:
        results["4.16"] = {
            "description": "Ensure AWS Security Hub is enabled.",
            "result": "Error occurred during check.",
            "status": "ERROR"
        }

    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error in 4.16 check: {str(e)}")
    results["4.16"] = {
        "description": "Ensure AWS Security Hub is enabled.",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }

print("Performing Check for 5.1.1")
try:
    non_compliant_regions = check_5_1_1_ebs_encryption_by_default()
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


print("Performing Check for 5.2")
try:
    nacl_violations = check_5_2_nacls_ingress_ports()
    results["5.2"] = {
        "description": "Ensure VPC Network ACLs do not allow ingress from 0.0.0.0/0 to TCP/UDP ports 22, 3389 or all protocols.",
        "result": nacl_violations if nacl_violations else "No violating NACL entries found for ingress.",
        "status": "PASS" if not nacl_violations else "FAIL"
    }
    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error in 5.2 check: {str(e)}")
    results["5.2"] = {
        "description": "Ensure VPC Network ACLs do not allow ingress from 0.0.0.0/0 to TCP/UDP ports 22, 3389 or all protocols.",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }


print("Performing Check for 5.3")
try:
    sg_violations = check_5_3_sgs_ingress_ports()
    if sg_violations:
        results["5.3"] = {
            "description": "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports.",
            "result": sg_violations,
            "status": "FAIL"
        }
    else:
        results["5.3"] = {
            "description": "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports.",
            "result": "No security groups violate this policy.",
            "status": "PASS"
        }
    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error in 5.3 check: {str(e)}")
    results["5.3"] = {
        "description": "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports.",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }



print("Performing Check for 5.4")
try:
    sg_violations_ipv6 = check_5_4_sgs_ipv6_ingress_ports()
    results["5.4"] = {
        "description": "Ensure no security groups allow ingress from ::/0 to remote server administration ports (IPv6).",
        "result": sg_violations_ipv6 if sg_violations_ipv6 else "No violating security groups found.",
        "status": "PASS" if not sg_violations_ipv6 else "FAIL"
    }
    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error in 5.4 check: {str(e)}")
    results["5.4"] = {
        "description": "Ensure no security groups allow ingress from ::/0 to remote server administration ports (IPv6).",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }



print("Performing Check for 5.5")
try:
    default_sg_violations = check_5_5_default_sgs_restrict_all_traffic()
    if default_sg_violations:
        results["5.5"] = {
            "description": "Ensure default security groups restrict all traffic.",
            "result": default_sg_violations,
            "explanation": explanation_5_4,
            "status": "FAIL"
        }
    else:
        results["5.5"] = {
            "description": "Ensure default security groups restrict all traffic.",
            "result": "All default security groups restrict all traffic.",
            "status": "PASS"
        }
    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error in 5.5 check: {str(e)}")
    results["5.5"] = {
        "description": "Ensure default security groups restrict all traffic.",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }



print("Performing Check for 5.6")
try:
    vpc_peering_violations = check_5_6_vpc_peering_least_access()
    results["5.6"] = {
        "description": "Ensure routing tables for VPC peering are \"least access\".",
        "result": vpc_peering_violations if vpc_peering_violations else "All VPC peering connections are secure.",
        "status": "PASS" if not vpc_peering_violations else "FAIL"
    }
    write_results_to_file(results)
except Exception as e:
    logger.error(f"Error in 5.5 check: {str(e)}")
    results["5.5"] = {
        "description": "Ensure VPC peering connections do not allow traffic from any source.",
        "result": f"Error occurred during check: {str(e)}",
        "status": "ERROR"
    }


print("Performing Check for 5.7")
try:
    imds_violations = check_5_7_ec2_imdsv2_only()
    results["5.7"] = {
        "description": "Ensure EC2 instances use IMDSv2.",
        "result": imds_violations if imds_violations else "All EC2 instances use IMDSv2.",
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


print(" ")
print("Scan Complete")
print(" ")


html_data = generate_html(results)
with open('results.html', 'w') as f:
    f.write(html_data)
print("HTML Created")

print(" ")
print("Capturing Screenshots")
current_dir = os.getcwd()
html_file_path = os.path.join(current_dir, "results.html")
output_directory = os.path.join(current_dir, "screenshots")

if not os.path.exists(output_directory):
    os.makedirs(output_directory)

capture_screenshot(f"file:///{html_file_path}", output_directory)

def move_to_output(src_path, dest_directory):
    if os.path.exists(src_path):
        dest_path = os.path.join(dest_directory, os.path.basename(src_path))
        shutil.move(src_path, dest_path)

profile_name = sys.argv[1] if len(sys.argv) > 1 else "AWSResults"
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

print(" ")
print("CIS Check Complete")


