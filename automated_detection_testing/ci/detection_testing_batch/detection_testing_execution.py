import sys
import argparse
import shutil
import os

from modules.github_service import GithubService
from modules import aws_service, testing_service


DT_ATTACK_RANGE_STATE_STORE = "dt-attack-range-tf-state-store"
DT_ATTACK_RANGE_STATE = "dt-attack-range-state"
REGION = "eu-central-1"
NAME = "detection-testing-attack-range"


def main(args):

    parser = argparse.ArgumentParser(description="CI Detection Testing")
    parser.add_argument("-b", "--branch", required=True, help="security content branch")

    args = parser.parse_args()
    branch = args.branch

    github_service = GithubService(branch)
    test_files = github_service.get_changed_test_files()
    for test_file in test_files:
        print(test_file)

    # dt_ar = aws_service.get_ar_information_from_dynamo_db(REGION, DT_ATTACK_RANGE_STATE)
    # splunk_instance = aws_service.get_splunk_instance(REGION, dt_ar['ssh_key_name'])

    # splunk_ip = splunk_instance['NetworkInterfaces'][0]['Association']['PublicIp']
    # splunk_password = dt_ar['password']
    # ssh_key_name = dt_ar['ssh_key_name']
    # private_key = dt_ar['private_key']

    # testing_service.prepare_detection_testing(ssh_key_name, private_key, splunk_ip, splunk_password)
    # testing_service.test_detections(ssh_key_name, private_key, splunk_ip, splunk_password, test_files)

    # Get Password, private_key and key_name from DynamoDB
    # For loop
        # Detection Test


if __name__ == "__main__":
    main(sys.argv[1:])