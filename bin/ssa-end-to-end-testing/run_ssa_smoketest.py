
import sys
import argparse

from modules.github_service import GithubService
from modules.test_ssa_detections import SSADetectionTesting

def main(args):

    parser = argparse.ArgumentParser(description="SSA detection smoke test")
    parser.add_argument("-t", "--token", required=True,
                        help="specify the scloud token")
    parser.add_argument("-e", "--env", required=True,
                        help="specify the environment")
    parser.add_argument("-s", "--tenant", required=True,
                        help="specify the tenant in the environment")

    args = parser.parse_args()
    token = args.token
    env = args.env
    tenant = args.tenant

    # test DSP pipeline
    ssa_detection_testing = SSADetectionTesting(env, tenant, token)
    test_result_passed = ssa_detection_testing.test_dsp_pipeline()

    if not test_result_passed:
        sys.exit(1)



    sys.exit(0)

    # github_service = GithubService('patrick_test_branch')
    # test_files_ssa = github_service.get_changed_test_files_ssa()

    # for test_file in test_files_ssa:
    #     prepare_test(test_file)

if __name__ == "__main__":
    main(sys.argv[1:])

