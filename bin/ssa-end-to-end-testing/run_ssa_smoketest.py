
import sys
import pytest
import argparse

from modules.github_service import GithubService

def main(args):

    # parser = argparse.ArgumentParser(description="SSA detection smoke test")
    # parser.add_argument("-t", "--token", required=True,
    #                     help="specify the scloud token")
    # parser.add_argument("-e", "--env", required=True,
    #                     help="specify the environment")
    # parser.add_argument("-s", "--tenant", required=True,
    #                     help="specify the tenant in the environment")

    # args = parser.parse_args()
    # token = args.token
    # env = args.env
    # tenant = args.tenant
    #pytest.main(["--token", token, "--env", env, "--tenant", tenant])

    github_service = GithubService('patrick_test_branch')
    test_files_ssa = github_service.get_changed_test_files_ssa()

    for test_file in test_files_ssa:
        prepare_test(test_file)

if __name__ == "__main__":
    main(sys.argv[1:])

