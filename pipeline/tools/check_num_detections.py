"""
A simple script for determining if there are detections to test when doing a diff-level pipeline for
MRs, and enabling/disabling downstream testing as appropriate. If no detections changed, testing is
disabled. If 1+ detections changed, it's enabled.
"""

import os
import logging
import argparse
from typing import Optional

import yaml

# Setup logging defaults
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_LOG_PATH = "trigger_pipeline.log"

# Create the share logging reference
global_logger: Optional[logging.Logger] = None


def setup_logging(
    log_path: str = DEFAULT_LOG_PATH,
    log_level: int = DEFAULT_LOG_LEVEL
) -> logging.Logger:
    """
    Creates a shared logging object for the script
    :param log_path: log file path
    :param log_level: log level
    """
    # create logging object
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)

    # create a file and console handler
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(log_level)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)

    # create a logging format
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s")
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # add the handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def get_logger() -> logging.Logger:
    """
    Get logger object (instantiate if not yet setup)
    :return logging.Logger: logger object
    """
    global global_logger
    if global_logger is None:
        global_logger = setup_logging()

    global_logger.propagate = False

    return global_logger


class ContentctlConfig:
    """Base class for manipulating contenctl existing YAML configs"""

    class InitializationError(Exception):
        """Class initialization error"""
        pass

    class ConfigKeyError(Exception):
        """Bad key access in the config"""
        pass

    def __init__(self, path: str) -> None:
        self.logger = get_logger()

        # raise if the path does not exist
        if not os.path.exists(path):
            message = f"Path '{path}' does not exist; cannot initialize"
            self.logger.error(message)
            raise ContentctlConfig.InitializationError(message)

        # raise if the given path is not a file
        if not os.path.isfile(path):
            message = f"Path '{path}' is not a file; cannot initialize"
            self.logger.error(message)
            raise ContentctlConfig.InitializationError(message)

        self.path = path
        self.config: dict
        self.__open()

    def __open(self) -> None:
        """Open the config and parse the YAML"""
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
        except OSError as e:
            self.logger.error(f"Failed to open file '{self.path}': {e}")
            raise e
        except yaml.YAMLError as e:
            self.logger.error(f"Failed to parse YAML: {e}")
            raise e

        if not isinstance(config, dict):
            msg = f"YAML config was loaded as something other than a dict: {type(config)}"
            self.logger.error(msg)
            raise ValueError(msg)

        self.config = config


def parse_args() -> argparse.Namespace:
    """
    Parse CLI args
    :returns: a Namespace object of the parsed arguments
    """
    parser = argparse.ArgumentParser(
        prog="check_num_detections",
        description=(
            "Triggers a pipeline downstream in securitycontent/security_content_automation (for the"
            " MR diff-level testing flow)."
        )
    )
    parser.add_argument(
        "-c",
        "--config",
        required=True,
        help="The contentctl test config (YAML) filepath.",
        dest="config_path"
    )
    parser.add_argument(
        "-d",
        "--dotenv",
        required=True,
        help="The output filepath for the generated dotenv file (e.g. build.env).",
        dest="dotenv_path"
    )
    return parser.parse_args()


def set_skip_testing(value: bool, path: str) -> None:
    """
    Writes a dotenv file at the provided path (or appends to the file at the provided path) with
    the env var SKIP_TESTING set to the provided value (True/False)
    :param value: a bool, the value to set the env var to
    :param path: str, the path for the dotenv file
    """
    with open(path, "a") as f:
        f.write(f"SKIP_TESTING={value}\n")


def disable_testing(path: str):
    """
    Convenience wrapper around set_skip_testing, disabling downstream testing
    :param path: str, the path for the dotenv file
    """
    set_skip_testing(value=True, path=path)


def enable_testing(path: str):
    """
    Convenience wrapper around set_skip_testing, enabling downstream testing
    :param path: str, the path for the dotenv file
    """
    set_skip_testing(value=False, path=path)


def main() -> None:
    # Setup logging
    logger = get_logger()

    # Parse the CLI args
    args = parse_args()

    # Load the test config
    contentctl_test = ContentctlConfig(args.config_path)

    # Ensure a list of detections was present
    if "detections_list" not in contentctl_test.config:
        msg = (
            "The field 'detections_list' is not specified in the provided config: "
            f"{args.config_path}"
        )
        logger.error(msg)
        raise ValueError(msg)

    # If the list of detections is empty, exit with an error
    num_detections = len(contentctl_test.config["detections_list"])
    if num_detections == 0:
        logger.info("No detections to test; telling downstream to skip testing.")
        disable_testing(args.dotenv_path)
    else:
        # If not empty, trigger testing
        logger.info(f"Found {num_detections} to test; telling downtream to proceed with testing.")
        enable_testing(args.dotenv_path)


if __name__ == "__main__":
    main()
