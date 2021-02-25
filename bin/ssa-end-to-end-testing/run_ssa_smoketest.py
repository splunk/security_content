
import sys
import pytest
import argparse
# import logging
# import os
#
# logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
# LOGGER = logging.getLogger(__name__)


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
    pytest.main(["--token", token, "--env", env, "--tenant", tenant])


if __name__ == "__main__":
    main(sys.argv[1:])

