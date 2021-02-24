import os
from os import path
import sys
import argparse
import git
from shutil import copyfile
from shutil import which
import subprocess
import boto3
from random import randrange
import yaml
from github import Github
from jinja2 import Environment, FileSystemLoader
import base64
from botocore.exceptions import ClientError
import json
from datetime import datetime
import subprocess
import time



def main(args):

    parser = argparse.ArgumentParser(description="detection testing service based on Attack Range.")
    parser.add_argument("-tfn", "--test_file_name", required=True,
                        help="specify the test file name located in security content repository")
    parser.add_argument("-arr", "--attack_range_repo", required=False, default="splunk/attack_range",
                        help="specify the url of the atack range repository")
    parser.add_argument("-arb", "--attack_range_branch", required=False, default="develop",
                        help="specify the atack range branch")
    parser.add_argument("-scr", "--security_content_repo", required=False, default="splunk/security_content",
                        help="specify the url of the security content repository")
    parser.add_argument("-scb", "--security_content_branch", required=False, default="develop",
                        help="specify the security content branch")
    parser.add_argument("-gt", "--github_token", required=False,
                        help="specify the github token for the PR")
    parser.add_argument("-smk", "--secrets_manager_key", required=False, default="github_token",
                        help="specify the key in AWS secrets manager for your github token")
    parser.add_argument("-s3b", "--s3_bucket", required=False, default="attack-range-automated-testing",
                        help="S3 bucket to store the test data")


    args = parser.parse_args()
    test_file_name = args.test_file_name
    attack_range_repo = args.attack_range_repo
    attack_range_branch = args.attack_range_branch
    security_content_repo = args.security_content_repo
    security_content_branch = args.security_content_branch
    github_token = args.github_token
    secrets_manager_key = args.secrets_manager_key
    s3_bucket = args.s3_bucket


    test_obj = {}
    test_obj['technique'] = 'T1003.001'
    detection_obj = {}
    detection_obj['detection'] = 'Access LSASS Memory for Dump Creation'
    test_obj['results'] = [detection_obj]

    #get github token
    if github_token:
        O_AUTH_TOKEN_GITHUB = github_token
    else:
        O_AUTH_TOKEN_GITHUB = get_secret(secrets_manager_key)

    # clone repositories
    git.Repo.clone_from('https://github.com/' + attack_range_repo, "attack_range", branch=attack_range_branch)
    security_content_repo_obj = git.Repo.clone_from('https://' + O_AUTH_TOKEN_GITHUB + ':x-oauth-basic@github.com/' + security_content_repo, "security_content", branch=security_content_branch)

    sys.path.append(os.path.join(os.getcwd(),'attack_range'))
    copyfile('attack_range/attack_range.conf.template', 'attack_range/attack_range.conf')

    epoch_time = str(int(time.time()))
    ssh_key_name = 'ds-key-pair-' + epoch_time
    # create ssh keys
    ec2 = boto3.client('ec2')
    response = ec2.create_key_pair(KeyName=ssh_key_name)
    with open(ssh_key_name, "w") as ssh_key:
        ssh_key.write(response['KeyMaterial'])
    os.chmod(ssh_key_name, 0o600)
    private_key_path = str(os.getcwd() + "/" + ssh_key_name)
    


    #build new version of ESCU
    sys.path.append(os.path.join(os.getcwd(),'security_content'))
    try:
        module = __import__('contentctl')
        module.sys.argv = ['contentctl', '-p', 'security_content','generate', '-o', 'security_content/package']
        results = module.main(module.sys.argv)
    except Exception as e:
        print('Error: ' + str(e))

    with open('attack_range/attack_range.conf', 'r') as file :
      filedata = file.read()

    filedata = filedata.replace('attack_range_password = Pl3ase-k1Ll-me:p', 'attack_range_password = I-l1ke-Attack-Range!')
    filedata = filedata.replace('windows_domain_controller = 1', 'windows_domain_controller = 0')
    filedata = filedata.replace('windows_server_join_domain = 1', 'windows_server_join_domain = 0')
    filedata = filedata.replace('region = us-west-2', 'region = eu-central-1')
    filedata = filedata.replace('key_name = attack-range-key-pair', 'key_name = ' + ssh_key_name)
    filedata = filedata.replace('private_key_path = ~/.ssh/id_rsa', 'private_key_path = ' + private_key_path)
    filedata = filedata.replace('update_escu_app = 0', 'update_escu_app = 1')

    with open('attack_range/attack_range.conf', 'w') as file:
      file.write(filedata)

    # check if terraform is installed
    if which('terraform') is None:
        sys.exit(1)
    else:
        # init terraform
        os.system('cd attack_range/terraform/aws && terraform init && cd ../../..')

    module = __import__('attack_range')
    module.sys.argv = ['attack_range', '--config', 'attack_range/attack_range.conf', 'test', '--test_file', 'security_content/tests/' + test_file_name]

    execution_error = False

    try:
        results = module.main(module.sys.argv)
    except Exception as e:
        print('Error: ' + str(e))
        module.sys.argv = ['attack_range', '--config', 'attack_range/attack_range.conf', 'destroy']
        module.main(module.sys.argv)
        execution_error = True

    # delete ssh key
    response = ec2.delete_key_pair(KeyName=ssh_key_name)

    # read_test_file
    test_file = load_file('security_content/tests/' + test_file_name)

    # check if was succesful
    if not execution_error:

        # Create GitHub PR security content
        if security_content_branch == 'develop':
            branch_name = "automated_detection_testing_" + epoch_time
            security_content_repo_obj.git.checkout(security_content_branch, b=branch_name)
        else:
            branch_name = security_content_branch
            security_content_repo_obj.git.checkout(security_content_branch)

        counter = 0
        for test in results:
            if not test['detection_result']['error']:
                file_path = 'security_content/detections/' + test['detection_result']['detection_file']
                detection_obj = load_file(file_path)
                detection_obj['tags']['automated_detection_testing'] = 'passed'
                if 'attack_data' in test_file['tests'][counter]:
                    datasets = []
                    for dataset in test_file['tests'][counter]['attack_data']:
                        datasets.append(dataset['data'])
                    detection_obj['tags']['dataset'] = datasets

                with open(file_path, 'w') as f:
                    yaml.dump(detection_obj, f, sort_keys=False)

                changed_file_path = 'detections/' + test['detection_result']['detection_file']
                security_content_repo_obj.index.add([changed_file_path])
                security_content_repo_obj.index.commit('Added detection testing service results in' + test['detection_result']['detection_name'])
                counter = counter + 1


        j2_env = Environment(loader=FileSystemLoader('templates'),trim_blocks=True)
        template = j2_env.get_template('PR_template.j2')
        body = template.render(results=results)

        security_content_repo_obj.config_writer().set_value("user", "name", "Detection Testing Service").release()
        security_content_repo_obj.config_writer().set_value("user", "email", "research@splunk.com").release()
        if not security_content_branch == 'develop':
            security_content_repo_obj.remotes.origin.pull()
        security_content_repo_obj.git.push('--set-upstream', 'origin', branch_name)
        g = Github(O_AUTH_TOKEN_GITHUB)
        repo = g.get_repo("splunk/security_content")
        pull_requests = repo.get_pulls(state='open', sort='created', head=branch_name)
        for pr in pull_requests:
            if pr.head.label == str('splunk:' + branch_name):
                pr.create_issue_comment(body)
                exit(0)

        pr = repo.create_pull(title="Automated Detection Testing PR " + branch_name, body=body, head=branch_name, base="develop")


def load_file(file_path):
    with open(file_path, 'r') as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit("ERROR: reading {0}".format(file_path))
    return file


def get_secret(secret_name):

    region_name = "eu-central-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            secret_obj = json.loads(secret)

    return secret_obj['github_token']


if __name__ == "__main__":
    main(sys.argv[1:])