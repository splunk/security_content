import sys
import argparse
import shutil

from modules.github_service import GithubService


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

    shutil.rmtree('security_content')


if __name__ == "__main__":
    main(sys.argv[1:])