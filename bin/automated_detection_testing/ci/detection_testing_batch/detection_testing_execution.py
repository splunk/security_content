import sys
import argparse
import shutil
import os
import time

from modules.github_service import GithubService
from modules import aws_service, testing_service


DT_ATTACK_RANGE_STATE_STORE = "dt-attack-range-tf-state-store"
DT_ATTACK_RANGE_STATE = "dt-attack-range-state"
REGION = "eu-central-1"
NAME = "detection-testing-attack-range"


def main(args):

    parser = argparse.ArgumentParser(description="CI Detection Testing")
    parser.add_argument("-b", "--branch", required=True, help="security content branch")
    parser.add_argument("-u", "--uuid", required=True, help="uuid for detection test")
    parser.add_argument("-pr", "--pr-number", required=False, help="Pull Request Number")

    args = parser.parse_args()
    branch = args.branch
    uuid_test = args.uuid
    pr_number = args.pr_number

    if pr_number:
        github_service = GithubService(branch, pr_number)
    else:
        github_service = GithubService(branch)
    test_files = github_service.get_changed_test_files()
    if len(test_files) == 0:
        print("No new detections to test.")
        aws_service.dynamo_db_nothing_to_test(REGION, uuid_test, str(int(time.time())))
        sys.exit(0)

    dt_ar = aws_service.get_ar_information_from_dynamo_db(REGION, DT_ATTACK_RANGE_STATE)
    splunk_instance = aws_service.get_splunk_instance(REGION, dt_ar['ssh_key_name'])

    splunk_ip = splunk_instance['NetworkInterfaces'][0]['Association']['PublicIp']
    splunk_password = dt_ar['password']
    ssh_key_name = dt_ar['ssh_key_name']
    private_key = dt_ar['private_key']

    testing_service.prepare_detection_testing(ssh_key_name, private_key, splunk_ip, splunk_password)
    testing_service.test_detections(ssh_key_name, private_key, splunk_ip, splunk_password, test_files, uuid_test)


if __name__ == "__main__":
    main(sys.argv[1:])