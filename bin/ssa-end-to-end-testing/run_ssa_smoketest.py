import os
import sys
import argparse
import logging

from modules.github_service import GithubService
from modules.test_ssa_detections import SSADetectionTesting
from modules.security_content_handler import prepare_test, remove_attack_data, remove_security_content


# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)


def main(args):

    parser = argparse.ArgumentParser(description="SSA detection smoke test")
    parser.add_argument("-t", "--token", required=True,
                        help="specify the scloud token")
    parser.add_argument("-e", "--env", required=True,
                        help="specify the environment")
    parser.add_argument("-s", "--tenant", required=True,
                        help="specify the tenant in the environment")
    parser.add_argument("-b", "--branch", required=True,
                        help="specify the security content branch")
    parser.add_argument("-tf", "--test_file", required=False,
                        help="specify the path to the ssa test file")
    parser.add_argument("-f", "--fast", required=False, default=False, action='store_true', 
                        help="skips testing of SSA and DSP availability")

    args = parser.parse_args()
    token = args.token
    env = args.env
    tenant = args.tenant
    branch = args.branch
    test_file = args.test_file
    fast = args.fast

    # Retrieve Security Content
    github_service = GithubService(branch)
    if test_file:
        if not os.path.isfile('security_content/tests/' + test_file):
            LOGGER.error('Can not find specified test file')
            sys.exit(1)
        test_files_ssa = [str("tests/" + test_file)]
    else:
        test_files_ssa = github_service.get_changed_test_files_ssa()
    
    LOGGER.info('changed/added GitHub files:')
    for test_file in test_files_ssa:
        LOGGER.info(test_file)

    if len(test_files_ssa) == 0:
        LOGGER.info('Nothing to test for SSA smoke test.')
        sys.exit(0)

    # test DSP and SSA pipeline
    ssa_detection_testing = SSADetectionTesting(env, tenant, token)
    if not fast:
        test_result_passed = ssa_detection_testing.test_dsp_pipeline()

        if not test_result_passed:
            sys.exit(1)

    # # test SSA detections
    test_results = []
    test_passed = True
    for test_file in test_files_ssa:
        test_obj, attack_data_folder = prepare_test(test_file)
        test_result = ssa_detection_testing.test_ssa_detections(test_obj)
        test_results.append(test_result.copy())
        remove_attack_data(attack_data_folder)

    LOGGER.info('-----------------------------------')
    LOGGER.info('------- test SSA detections -------')
    LOGGER.info('-----------------------------------')
    for test_result in test_results:
        test_passed = test_passed and test_result['result']
        LOGGER.info(test_result['msg'])
    LOGGER.info('-----------------------------------')

    remove_security_content()
    exit_code = not test_passed
    sys.exit(exit_code)



if __name__ == "__main__":
    main(sys.argv[1:])

