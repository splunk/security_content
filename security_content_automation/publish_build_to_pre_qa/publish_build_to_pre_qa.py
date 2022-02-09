import os
import json
import subprocess
from base64 import b64encode, b64decode
import logging
import time
import re
import argparse

import requests

from constant import RetryConstant, JfrogArtifactoryConstant

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("publish_build_to_pre_qa.log")],
)


class PublishArtifactory:
    def __init__(self, release_id, artifactory_list):
        # Tag version
        self.release_id = release_id
        # Jfrog artifactory endpoint
        self.endpoint = JfrogArtifactoryConstant.JFROG_ENDPOINT
        # Jfrog artifactory repository
        self.repository = JfrogArtifactoryConstant.JFROG_REPOSITORY
        # Pre-QA directory name
        self.pre_qa_repository_dir_name = JfrogArtifactoryConstant.PRE_QA_DIR
        # Pre-QA artifactory endpoint
        self.pre_qa_endpoint = f"{self.endpoint}/artifactory/{self.repository}"
        # Pre-QA artifactory API endpoint
        self.pre_qa_api_endpoint = (
            f"{self.endpoint}/artifactory/api/storage/{self.repository}"
        )
        # Artifactory name list, will push to Pre-QA
        self.artifactory_files = artifactory_list
        # Github tags API endpoint for download assets
        self.git_tags_api_endpoint = (
            f"https://api.github.com/repos/splunk/security_content/releases/tags/"
            f"{self.release_id}"
        )
        # Max artifact in builds directory
        self.max_artifacts_in_build_dir = 5

    def __fetch_and_download_artifactory_from_git(self):
        """
        Download build from github tags assets
        :return: Downloaded build list
        """
        token = b64encode(
            str.encode(
                f"{os.environ.get('GIT_USERNAME')}:{b64decode(os.environ.get('GIT_ACCESS_TOKEN')).decode()}"
            )
        ).decode("ascii")
        headers = {
            "accept": "application/vnd.github.v3+json",
            "Authorization": f"Basic %s" % token,
        }
        try:
            # Git API fetch tag asset details
            response = requests.get(f"{self.git_tags_api_endpoint}", headers=headers)

            if response.status_code == 200:
                response_content = json.loads(response.content)
                logging.debug(
                    f"Response status code - {response.status_code}, Response content - {response_content}, "
                    f"Request endpoint- {self.git_tags_api_endpoint}"
                )
            else:
                raise Exception(response.content)
        except Exception as error:
            error_message = f"Error while fetching Git file content: {self.git_tags_api_endpoint}, Reason: {error}"
            logging.error(error_message)
            raise type(error)(error_message) from error

        artifactory_list = {}
        for asset in response_content["assets"]:
            if asset["name"].split("-v")[0] in self.artifactory_files:
                artifactory_list[asset["name"]] = asset["url"]

        logging.debug(f"Artifactory list - {artifactory_list}")

        # Download build from github
        for assets_name, assets_url in artifactory_list.items():
            download_url = f"curl -vLJO -H 'Authorization: Basic {token}' -H 'Accept: application/octet-stream' {assets_url}"
            status, output = subprocess.getstatusoutput(download_url)
            logging.debug(
                f"Download URL - {download_url}, status - {status}, output-{output}"
            )
            if status == 0:
                logging.debug(
                    f"{assets_name} build successfully downloaded from github"
                )
            else:
                error_message = (
                    f"Error occur while downloading build from github, Reason: {output}"
                )
                logging.error(error_message)
                raise Exception(error_message)

        return artifactory_list.keys()

    def __delete_exiting_artifactory_from_pre_qa(self, artifactory):
        """
        Delete the existing build from JFROG artifactory latest directory and builds directory of given product
        :param artifactory: Product name
        :return: None
        """
        # Delete the existing build from product latest directory
        pre_qa_latest_endpoint = f"{self.pre_qa_endpoint}/{self.pre_qa_repository_dir_name}/{artifactory}/latest"
        delete_pre_qa_latest_response = requests.request(
            "DELETE",
            pre_qa_latest_endpoint,
            auth=(
                os.environ.get("JFROG_ARTIFACTORY_USERNAME"),
                b64decode(os.environ.get("JFROG_ARTIFACTORY_PASSWORD")).decode(),
            ),
        )
        if delete_pre_qa_latest_response.status_code == 204:
            logging.info(
                f"{pre_qa_latest_endpoint} Successfully delete existing build from jfrog artifactory"
            )
        elif delete_pre_qa_latest_response.status_code == 404:
            logging.info(f"{pre_qa_latest_endpoint} Nothing to delete")
        else:
            error_message = (
                f"Error occur while deleting build from jfrog artifactory latest dir, endpoint: {pre_qa_latest_endpoint}"
                f", Reason: {delete_pre_qa_latest_response.content}"
            )
            logging.error(error_message)
            raise Exception(error_message)

        # Get artifact details from product builds directory
        pre_qa_builds_endpoint = f"{self.pre_qa_api_endpoint}/{self.pre_qa_repository_dir_name}/{artifactory}/builds/"
        response = requests.request(
            "GET",
            pre_qa_builds_endpoint,
            auth=(
                os.environ.get("JFROG_ARTIFACTORY_USERNAME"),
                b64decode(os.environ.get("JFROG_ARTIFACTORY_PASSWORD")).decode(),
            ),
        )

        logging.debug(
            f"Response status code - {response.status_code}, Response content - {response.content}, "
            f"Request endpoint- {self.pre_qa_endpoint}"
        )

        if response.status_code == 200:
            artifactory_list = json.loads(response.content).get("children")
            delete_artifact_count = len(artifactory_list) - (
                self.max_artifacts_in_build_dir - 1
            )
            if delete_artifact_count > 0:
                temp_artifactory_dict = {}

                for obj in artifactory_list:
                    temp_artifactory_dict[
                        re.search("\d+(\.\d+){2,}", obj["uri"]).group()
                    ] = obj["uri"]

                # Sort the artifactory list
                sorted_temp_artifactory_dict = dict(
                    sorted(temp_artifactory_dict.items())
                )

                delete_artifactory_dict = {
                    obj: sorted_temp_artifactory_dict[obj]
                    for obj in list(sorted_temp_artifactory_dict)[
                        :delete_artifact_count
                    ]
                }

                delete_artifactory_list = list(delete_artifactory_dict.values())

                # Delete older build from product builds directory
                for obj in delete_artifactory_list:
                    url = f"{self.pre_qa_endpoint}/{self.pre_qa_repository_dir_name}/{artifactory}/builds{obj}"
                    delete_response = requests.request(
                        "DELETE",
                        url,
                        auth=(
                            os.environ.get("JFROG_ARTIFACTORY_USERNAME"),
                            b64decode(
                                os.environ.get("JFROG_ARTIFACTORY_PASSWORD")
                            ).decode(),
                        ),
                    )
                    if delete_response.status_code == 204:
                        logging.info(
                            f"{url} Successfully delete existing build from jfrog artifactory"
                        )
                        return
                    else:
                        error_message = (
                            f"Error occur while deleting build from jfrog artifactory builds directory, "
                            f"Reason: {delete_response.content}, endpoint: {url}"
                        )
                        logging.error(error_message)
                        raise Exception(error_message)

    @staticmethod
    def __publish_single_artifactory_to_pre_qa(artifactory, endpoint):
        """
        Deploy build to jfrog artifactory server
        :param artifactory: Local downloaded  artifactory path
        :param endpoint: Jfrog artifactory path where we deploy the artifactory
        :return: None
        """
        retries = 0
        while retries < RetryConstant.RETRY_COUNT:
            deploy_url = (
                f"curl -u '{os.environ.get('JFROG_ARTIFACTORY_USERNAME')}:"
                f"{b64decode(os.environ.get('JFROG_ARTIFACTORY_PASSWORD')).decode()}' -H 'Connection: "
                f"keep-alive' --compressed -v --keepalive-time 2000 -X PUT {endpoint} -T {artifactory}"
            )

            status, output = subprocess.getstatusoutput(deploy_url)
            logging.debug(
                f"Deploy URL - {deploy_url}, status - {status}, output-{output}"
            )
            if status == 0:
                logging.debug(f"{artifactory} build deploy successfully to {endpoint}")
                break
            else:
                error_message = (
                    f"Error occur while deploy build to pre-qa, Reason: {output}"
                )
                logging.error(error_message)
                time.sleep(RetryConstant.RETRY_INTERVAL)
                retries = retries + 1

        if retries == RetryConstant.RETRY_COUNT:
            error_message = (
                "Max retries occur while deploying build to jfrog artifactory"
            )
            raise Exception(error_message)

    def __publish_artifactory_to_pre_qa(self, artifactory_list):
        """
        Deploy build to jfrog artifactory server and delete the existing builds
        :param artifactory_list: The list of locally downloaded artifactory
        :return: None
        """
        for artifactory in artifactory_list:
            try:
                # product directory name
                current_artifactory_dir_name = (
                    artifactory.replace("_", "-")
                    .lower()
                    .split(re.search("-v\d+(\.\d+){2,}", artifactory).group())[0]
                )

                # Delete existing builds from product latest and builds directory
                self.__delete_exiting_artifactory_from_pre_qa(
                    current_artifactory_dir_name
                )

                # Push build to product builds directory
                builds_endpoint = (
                    f"{self.pre_qa_endpoint}/{self.pre_qa_repository_dir_name}/"
                    f"{current_artifactory_dir_name}/builds/{artifactory}"
                )
                self.__publish_single_artifactory_to_pre_qa(
                    artifactory, builds_endpoint
                )

                # Push build to product latest directory
                latest_endpoint = (
                    f"{self.pre_qa_endpoint}/{self.pre_qa_repository_dir_name}/"
                    f"{current_artifactory_dir_name}/latest/{artifactory}"
                )
                self.__publish_single_artifactory_to_pre_qa(
                    artifactory, latest_endpoint
                )
            except Exception as error:
                error_message = f"Error occur while publishing build to PRE-QA artifactory, reason: {error}"
                raise Exception(error_message)

    @staticmethod
    def __remove_downloaded_file(artifactory_list):
        """
        Delete Github downloaded build
        :param artifactory_list: List of artifactory
        :return: None
        """
        for file in artifactory_list:
            os.remove(file)
            logging.info(f"{file} successfully delete github downloaded build")

    def main(self):
        """
        Wrapper method of above listed method
        :return: None
        """
        artifactory_list = self.__fetch_and_download_artifactory_from_git()
        self.__publish_artifactory_to_pre_qa(artifactory_list)
        self.__remove_downloaded_file(artifactory_list)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Github version Tag")
    parser.add_argument(
        "--version",
        dest="version",
        type=str,
        help="Security content repo new releases tag version number",
        required=True,
    )
    parser.add_argument(
        "--builds",
        dest="builds",
        nargs="+",
        type=str,
        help="List of builds, need to fetch from Security content "
        "github assets and deploy to Pre-QA directory of artifactory",
        required=True,
    )
    args = parser.parse_args()
    # Validate tag version
    if (
        args.version
        and bool(re.search("v\d+(\.\d+){2,}", args.version))
        and args.builds
    ):
        PublishArtifactory(args.version, args.builds).main()
    else:
        raise Exception(
            f"Github release tagged version is not correct, Tag version: {args.version}"
        )
