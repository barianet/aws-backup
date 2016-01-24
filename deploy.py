__author__ = 'turnerj'

import boto3
import zipfile
import os
import time

region = 'us-east-1'

iam = boto3.client('iam')

policy_name = 'EBS-Backup'
policy_src = 'ebs-backup-iam-policy.json'
role_name = 'EBS-Backup-Lambda'
role_src = 'ebs-backup-iam-role-trust-policy.json'
function_name = 'EBS-Backup'
function_src_dir = 'ebs-backup-lambda'
handler = 'ebs-backup.ebs_backup_handler'
timeout = 60
memory_size = 128

# Read policy doc
with open(policy_src, 'r') as policy_file:
    policy_json_str = policy_file.read().replace('\n', '')
with open(role_src, 'r') as trust_file:
    trust_json_str = trust_file.read().replace('\n', '')

# Create/update the policy
response = iam.list_policies(Scope='Local')
ebs_policy_arn = None
for policy in response['Policies']:
    if policy['PolicyName'] == policy_name:
        ebs_policy_arn = policy['Arn']
        break

if ebs_policy_arn is not None:
    response = iam.list_policy_versions(
        PolicyArn=ebs_policy_arn)
    for version in response['Versions']:
        if version['IsDefaultVersion'] is not True:
            response = iam.delete_policy_version(
                PolicyArn=ebs_policy_arn,
                VersionId=version['VersionId'])
    response = iam.create_policy_version(
        PolicyArn=ebs_policy_arn,
        PolicyDocument=policy_json_str,
        SetAsDefault=True)
else:
    response = iam.create_policy(
        PolicyName=policy_name,
        Path='/',
        PolicyDocument=policy_json_str,
        Description='EBS backup policy')
    ebs_policy_arn = response['Policy']['Arn']

# Create/update the role
response = iam.list_roles()
ebs_role_arn = None
for role in response['Roles']:
    if role['RoleName'] == role_name:
        ebs_role_arn = role['Arn']
        response = iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=trust_json_str)
        break
if ebs_role_arn is None:
    response = iam.create_role(RoleName=role_name,
                               AssumeRolePolicyDocument=trust_json_str)
    ebs_role_arn = response['Role']['Arn']
    response = iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn=ebs_policy_arn)

#This sleep is required as AWS does not like creating the lamdba function too quickly after the role is created.
#Without this we get: "The role defined for the function cannot be assumed by Lambda."
time.sleep(3)

#Build the zip file
try:
    os.remove('built-lambda.zip')
except OSError:
    pass
zipfh = zipfile.ZipFile('built-lambda.zip', 'w')
oldcwd = os.getcwd()
os.chdir(function_src_dir)
for root, dirs, files in os.walk('.'):
    for file in files:
        zipfh.write(os.path.join(root, file))
zipfh.close()
os.chdir(oldcwd)

awslambda = boto3.client('lambda')
response = awslambda.list_functions()
function_arn = None
for function in response['Functions']:
    if function['FunctionName'] == function_name:
        function_arn = function['FunctionArn']
        with open('built-lambda.zip', "rb") as zipped_code:
            response = awslambda.update_function_code(
                FunctionName=function_name,
                ZipFile=zipped_code.read(),
                Publish=True | False)
        response = awslambda.update_function_configuration(
            FunctionName=function_name,
            Role=ebs_role_arn,
            Handler=handler,
            Description=function_name,
            Timeout=timeout,
            MemorySize=memory_size)
        break

if function_arn is None:
    with open('built-lambda.zip', "rb") as zipped_code:
        response = awslambda.create_function(
            FunctionName=function_name,
            Runtime='python2.7',
            Role=ebs_role_arn,
            Handler=handler,
            Code={
                'ZipFile': zipped_code.read()
            },
            Description=function_name,
            Timeout=timeout,
            MemorySize=memory_size,
            Publish=True)
