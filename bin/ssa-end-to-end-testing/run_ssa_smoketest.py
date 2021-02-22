
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

    args = parser.parse_args()
    token = args.token
    pytest.main(["--token", token])


if __name__ == "__main__":
    main(sys.argv[1:])
