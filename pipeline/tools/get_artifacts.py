"""
Simple script for pulling artifacts from the downstream job triggered by a local job. Needs the
following inputs to retrieve artifacts:
- Project Access Token for the local repo
- Project Access Token for the downstream repo
- Local trigger job name
- Downstream job name to fetch artifacts from
- Local pipeline ID (will attempt to get from CI_PIPELINE_ID if not provided)
- Local repo project ID (will attempt to get from CI_PROJECT_ID if not provided)
- Job Token for the current job (will attempt to get from CI_JOB_TOKEN if not provided)
- Output path for the artifacts zip file (will write to ./artifacts.zip if not provided)
"""

import os
import logging
import argparse
import json
from urllib import parse
from typing import Optional, Union

import requests

# Setup logging defaults
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_LOG_PATH = "get_artifacts.log"

# Create the shared logging reference
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


def parse_args() -> argparse.Namespace:
    """
    Parse CLI args
    :returns: a Namespace object of the parsed arguments
    """
    parser = argparse.ArgumentParser(
        prog="get_artifacts",
        description=(
            "Pulls artifacts from a downstream job"
        )
    )
    parser.add_argument(
        "-t",
        "--trigger-job",
        required=True,
        type=str,
        help="The name of the local pipeline's trigger job.",
        dest="trigger_job_name"
    )
    parser.add_argument(
        "--pipeline-id",
        type=str,
        help=(
            "The local pipeline's ID (attempts to pull CI_PIPELINE_ID from the environment if "
            "unspecified)."
        ),
        default=os.environ.get("CI_PIPELINE_ID"),
        dest="local_pipeline_id"
    )
    parser.add_argument(
        "--project-id",
        type=str,
        help=(
            "The local pipeline's project ID (attempts to pull CI_PROJECT_ID from the environment "
            "if unspecified)."
        ),
        default=os.environ.get("CI_PROJECT_ID"),
        dest="local_project_id"
    )
    parser.add_argument(
        "--job-token",
        type=str,
        help=(
            "The local CI job's token (attempts to pull CI_JOB_TOKEN from the environment if "
            "unspecified)."
        ),
        default=os.environ.get("CI_JOB_TOKEN"),
        dest="job_token"
    )
    parser.add_argument(
        "--local-token",
        required=True,
        type=str,
        help="A project access token with read permissions for the local repo.",
        dest="local_token"
    )
    parser.add_argument(
        "--down-token",
        required=True,
        type=str,
        help="A project access token with read permissions for the target downstream repo.",
        dest="down_token"
    )
    parser.add_argument(
        "--down-job",
        required=True,
        type=str,
        help="The name of the job downstream you want to fetch artifacts from.",
        dest="down_job_name"
    )
    parser.add_argument(
        "-o",
        "--out",
        type=str,
        help="The filepath to write the retrieved artifact bundle to (default: artifacts.zip).",
        default="artifacts.zip",
        dest="out"
    )

    # Validate and return the arguments
    args = parser.parse_args()
    validate_args(args)
    return args


def validate_args(args: argparse.Namespace) -> None:
    """
    Validates the given arguments
    :param args: a Namespace representing the CLI args
    """
    # Check if we failed to pull any of the env var value from the environment
    if args.job_token is None:
        raise ValueError(
            "Could not find CI_JOB_TOKEN in the environment; please provide explicitly via "
            "--job-token"
        )
    if args.local_pipeline_id is None:
        raise ValueError(
            "Could not find CI_PIPELINE_ID in the environment; please provide explicitly via "
            "--pipeline-id"
        )
    if args.local_project_id is None:
        raise ValueError(
            "Could not find CI_PROJECT_ID in the environment; please provide explicitly via "
            "--project-id"
        )


class GitLabSession(requests.Session):
    """Simple extension of Session that is aware of Splunk's GitLab base URL"""

    def __init__(self):
        super().__init__()
        self.base_url = "https://cd.splunkdev.com/api/v4/projects/"
        self.logger = get_logger()

    def request(
            self,
            method: Union[str, bytes],
            url: Union[str, bytes],
            *args,
            **kwargs) -> requests.Response:
        """
        Extends request, using the base URL with a provided path
        :param method: a str for the HTTP method (e.g. "GET")
        :param url: a str representing the API path on top of the base URL
        :raises HTTPError: if the response code is an error
        :returns: a Response object
        """
        joined_url = parse.urljoin(self.base_url, url)
        self.logger.info(f"Requesting URL: {joined_url}")
        response = super().request(method, joined_url, *args, **kwargs)

        try:
            response.raise_for_status()
        except requests.HTTPError:
            self.logger.error(f"Receive HTTP error ({response.status_code}): {response.content!r}")
            raise

        return response

    def get_downstream_pipeline(
            self,
            local_pipeline_id: str,
            local_project_id: str,
            local_token: str,
            trigger_job_name: str
            ) -> dict:
        """
        Retrieve metadata about the downstream pipeline
        :param local_pipeline_id: the local pipeline ID
        :param local_project_id: the local project ID
        :param local_token: a token for the local project w/ read permissions
        :param trigger_job_name: the local trigger job name
        :raises HTTPError: if the response code is an error
        :returns: a dict representing the downstream pipeline
        """
        # Construct API path
        api_path = f"{local_project_id}/pipelines/{local_pipeline_id}/bridges"

        # Request the trigger jobs
        response = self.get(
            api_path,
            headers={
                "PRIVATE-TOKEN": local_token
            }
        )

        # Try to unpack the response into JSON
        try:
            trigger_jobs = json.loads(response.content)
        except json.JSONDecodeError:
            self.logger.error(
                "Failed to decode response from bridges API into JSON: {response.content!r}"
            )
            raise

        # Look for the specified trigger job name in the trigger jobs
        downstream_pipeline = None
        for job in trigger_jobs:
            if job["name"] == trigger_job_name:
                # If we've found the right trigger job, grab the downstream pipeline
                downstream_pipeline = job["downstream_pipeline"]

        # If we didn't find it, log and raise
        if downstream_pipeline is None:
            msg = (
                f"Could not find the specified trigger job in the JSON response: {trigger_job_name}"
            )
            self.logger.error(msg)
            raise ValueError(msg)

        # If the downstream_pipeline is not a dict, log and raise
        if not isinstance(downstream_pipeline, dict):
            msg = (
                f"The downstream_pipeline field was of type {type(downstream_pipeline)}; "
                "expected dict"
            )
            self.logger.error(msg)
            raise ValueError(msg)

        self.logger.info(
            f"Downstream project: {downstream_pipeline['project_id']} | "
            f"Downstream pipeline: {downstream_pipeline['id']}"
        )
        return downstream_pipeline

    # NOTE: currently, a project access token is treated like a user of the repo it has access to;
    # as a result, it *should* have access to any repos that repo has access to (e.g.
    # security_content_automation). If this changes, or if the current private scoping of the SCA
    # repo poses issues, I can add another token for the downstream repo. Also, scope tokens for
    # read-only (I think they need Developer access for pipeline data)
    # This should also be configured w/ a token rotation stage:
    # https://docs.gitlab.com/ee/api/project_access_tokens.html#:~:text=Rotate%20a%20project%20access%20token,-History&text=Revokes%20the%20previous%20token%20and,year%20from%20the%20rotation%20date.
    # https://docs.gitlab.com/ee/api/project_level_variables.html#update-a-variable
    def get_downstream_job(
            self,
            downstream_project_id: str,
            downstream_pipeline_id: str,
            downstream_job_name: str,
            downstream_token: str
            ) -> dict:
        """
        Retrieve metadata about a downstream job
        :param downstream_project_id: the downstream project ID
        :param downstream_pipeline_id: the downstream pipeline ID
        :param downstream_job_name: the downstream job name
        :param downstream_token: a token for the downstream project w/ read permissions
        :raises HTTPError: if the response code is an error
        :returns: a dict representing the downstream job
        """
        # Construct API path
        api_path = f"{downstream_project_id}/pipelines/{downstream_pipeline_id}/jobs"

        # Request the downstream jobs
        response = self.get(
            api_path,
            headers={
                "PRIVATE-TOKEN": downstream_token
            }
        )

        # Decode the JSON response; log and raise if there are issues
        try:
            downstream_jobs = json.loads(response.content)
        except json.JSONDecodeError:
            self.logger.error(
                "Failed to decode response from jobs API into JSON: {response.content!r}"
            )
            raise

        # Try to find the downstream job with the specified name
        downstream_job = None
        for job in downstream_jobs:
            if job["name"] == downstream_job_name:
                downstream_job = job

        # Log and raise if we couldn't find it
        if downstream_job is None:
            msg = (
                f"Could not find the specified downstream job in the JSON response: {downstream_job_name}"
            )
            self.logger.error(msg)
            raise ValueError(msg)

        # Log and raise if it's not a dict
        if not isinstance(downstream_job, dict):
            msg = (
                f"The {downstream_job_name} field was of type {type(downstream_job)}; "
                "expected dict"
            )
            self.logger.error(msg)
            raise ValueError(msg)

        self.logger.info(f"Downstream job: {downstream_job['name']} ({downstream_job['id']})")
        return downstream_job

    def get_artifacts(
            self,
            downstream_project_id: str,
            downstream_job_id: str,
            job_token: str,
            out: str
            ) -> None:
        """
        Retrieve artifacts from a downstream job and write to disk
        :param downstream_project_id: the downstream project ID
        :param downstream_job_id: the downstream job ID
        :param job_token: a job token for the current job
        :param out: the filepath to write the artifacts ZIP to
        :raises HTTPError: if the response code is an error
        """
        # Construct API path
        api_path = f"{downstream_project_id}/jobs/{downstream_job_id}/artifacts"

        # Request the downstream job's artifacts
        response = self.get(
            api_path,
            data={
                "job_token": job_token
            }
        )

        # Write the response to disk
        with open(out, "wb") as f:
            f.write(response.content)
        self.logger.info(f"Wrote artifacts to disk at: {out}")


def main():
    # Parse the arguments
    args = parse_args()

    # Instantiate the session
    session = GitLabSession()

    # Get the downstream pipeline
    downstream_pipeline = session.get_downstream_pipeline(
        args.local_pipeline_id,
        args.local_project_id,
        args.local_token,
        args.trigger_job_name
    )

    # Get the downstream job
    downstream_job = session.get_downstream_job(
        downstream_pipeline["project_id"],
        downstream_pipeline["id"],
        args.down_job_name,
        args.down_token
    )

    # Get the artifacts
    session.get_artifacts(
        downstream_pipeline["project_id"],
        downstream_job["id"],
        args.job_token,
        args.out
    )


if __name__ == "__main__":
    main()
