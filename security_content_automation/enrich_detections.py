# 1. Take github token, branch_name from user to raise a PR for enriched detection of security_content repo
# 2. Iterate through each detection file
# 3. For each detection iterate through ta_cim_mapping report
# 4. map detection file and ta_cim_mapping reports and finalise the TA required for particular detection
# 5. Add the list of TA's in detection file
# 6. Create a new branch and raise an MR for it

import os
import git
import sys
import shutil
import yaml
import json
import time
import argparse
import logging
import io
import re
from github import Github


def fetch_ta_cim_mapping_report(file_name):
    try:
        with open(file_name) as file_content:
            cim_field_report = json.load(file_content)
            return cim_field_report
    except Exception as error:
        error_message = f"Unexpected error occurred while reading file. Error: {error}"
        logging.error(error_message)


def load_file(file_path):
    
        try:
            with open(file_path, "r", encoding="utf-8") as stream:
                file = list(yaml.safe_load_all(stream))[0]
                return file
        except yaml.YAMLError as exc:
            sys.exit("ERROR: reading {0}".format(file_path))
        


def map_required_fields(cim_summary, datamodel, required_fields):
    datasets_fields = {}
    add_addon = True
    flag = 0
    for item in required_fields:
        if re.match("^[A-Za-z0-9_.]*$", item):
            if item == "_time" or item == "_times":
                continue
            else:
                dataset_field = item.split(".")
                length = len(dataset_field)
                if length == 1:
                    dataset = datamodel[0]
                    field = dataset_field[0]
                else:
                    dataset = dataset_field[length - 2]
                    field = dataset_field[length - 1]
                if dataset not in datasets_fields:
                    datasets_fields[dataset] = []
                datasets_fields[dataset].append(field)

    for dataset in datasets_fields:
        add_addon = False
        mapping_set = datamodel[0] + ":" + dataset
        for item in cim_summary:
            if mapping_set in item:
                for eventtype in cim_summary[item].values():
                    for e_type in eventtype:
                        cim_fields = e_type.get("fields", [])
                        if set(datasets_fields[dataset]).issubset(set(cim_fields)):
                            add_addon = True

    return add_addon


def is_valid_detection_file(filepath) -> bool:
    """
    check if detection file have valid analytic type and have valid
    data-model name.
    :param detection_test_path: detection test path i.e. security_content/tests/cloud
    :param test_file: detection test file name
    :param detection_products: detection tag product list for which detection test will filterised
    :return: boolean
    """
    detection_analytic_type = ["ttp", "anomaly"]
    detection_with_valid_analytic_type = False
    detection_with_valid_datamodel = False
    detection_file_path = load_file(filepath)

    if detection_file_path.get("type", "").lower() in detection_analytic_type:
        detection_with_valid_analytic_type = True

    if detection_file_path.get("datamodel", []):
        detection_with_valid_datamodel = True

    return detection_with_valid_analytic_type & detection_with_valid_datamodel


def enrich_detection_file(file, ta_list, keyname):
    # file_path = 'security_content/detections/' + test['detection_result']['detection_file']
    detection_obj = load_file(file)
    detection_obj["tags"][keyname] = ta_list

    with open(file, "w") as f:
        yaml.dump(detection_obj, f, sort_keys=False, allow_unicode=True)


def main():

    parser = argparse.ArgumentParser(
        description="Enrich detections with relevant TA names"
    )
    parser.add_argument(
        "-scr",
        "--security_content_repo",
        required=False,
        default="kirtankhatana-crest/security_content",
        help="specify the url of the security content repository",
    )
    parser.add_argument(
        "-scb",
        "--security_content_branch",
        required=False,
        default="develop",
        help="specify the security content branch",
    )
    parser.add_argument(
        "-gt",
        "--github_token",
        required=False,
        default=os.environ.get("GIT_TOKEN"),
        help="specify the github token for the PR",
    )

    args = parser.parse_args()
    security_content_repo = args.security_content_repo
    security_content_branch = args.security_content_branch
    github_token = args.github_token
    g = Github(github_token)
    detection_types = ["cloud", "endpoint", "network"]

    # clone security content repository
    # security_content_repo_obj = git.Repo.clone_from(
    #     "https://"
    #     + github_token
    #     + ":x-oauth-basic@github.com/"
    #     + security_content_repo,
    #     "security_content",
    #     branch=security_content_branch,
    # )

    # # clone ta cim field reports repository
    # ta_cim_field_reports_obj = git.Repo.clone_from(
    #     "https://"
    #     + github_token
    #     + ":x-oauth-basic@github.com/"
    #     + "splunk/ta-cim-field-reports",
    #     "ta_cim_mapping_reports",
    #     branch="feat/cim-field-mapping",
    # )

    # iterate for every detection types
    detection_ta_mapping = {}
    for detection_type in detection_types:

        for subdir, _, files in os.walk(f"security_content/tests/{detection_type}"):
            print(subdir)
            for file in files:
                filepath = subdir + os.sep + file
                supported_ta_list = []
                tas_with_data_list = []
                detection_obj = load_file(filepath)
                source_type = (
                    detection_obj.get("tests")[0]
                    .get("attack_data")[0]
                    .get("sourcetype")
                )
                detection_file_name = (
                    detection_obj.get("tests")[0]
                    .get("file")
                    .rsplit("/", 1)[1]
                    .strip(".yml")
                )
                filepath = "security_content/detections/" + detection_obj.get("tests")[
                    0
                ].get("file")
                try:
                    fo = open(filepath)
                except FileNotFoundError:
                    continue

                
                if is_valid_detection_file(filepath):
                    for ta_cim_mapping_file in os.listdir(
                        "./ta_cim_mapping_reports/ta_cim_mapping/cim_mapping_reports/latest/"
                    ):

                        ta_cim_map = fetch_ta_cim_mapping_report(
                            "./ta_cim_mapping_reports/ta_cim_mapping/cim_mapping_reports/latest/"
                            + ta_cim_mapping_file
                        )

                        detection_obj = load_file(filepath)
                        required_fields = detection_obj.get("tags", {}).get(
                            "required_fields"
                        )
                        datamodel = detection_obj.get("datamodel", [])
                        result = map_required_fields(
                            ta_cim_map["cimsummary"], datamodel, required_fields
                        )
                        cim_version = ta_cim_map["cim_version"]

                        if result:
                            supported_ta_list.append(
                                ta_cim_map.get("ta_name").get("name")
                            )
                            ta_sourcetype = ta_cim_map["sourcetypes"]
                            if source_type in ta_sourcetype:
                                tas_with_data_list.append(
                                    ta_cim_map.get("ta_name").get("name")
                                )
                            detection_ta_mapping[detection_file_name] = {}

                    if supported_ta_list:
                        keyname = "supported_tas"
                        print(filepath)
                        enrich_detection_file(filepath, cim_version, "cim_version")
                        enrich_detection_file(filepath, supported_ta_list, keyname)
                        detection_ta_mapping[detection_file_name][
                            "cim_version"
                        ] = cim_version
                        detection_ta_mapping[detection_file_name][
                            keyname
                        ] = supported_ta_list

                    if tas_with_data_list:
                        keyname = "tas_with_data"
                        enrich_detection_file(filepath, tas_with_data_list, keyname)
                        detection_ta_mapping[detection_file_name][
                            keyname
                        ] = tas_with_data_list

                    # security_content_repo_obj.index.add(
                    #     [filepath.strip("security_content/")]
                    # )

    print("done")
    with io.open(
        r"./security_content_automation/detection_ta_mapping.yml", "w", encoding="utf8"
    ) as outfile:
        yaml.safe_dump(
            detection_ta_mapping, outfile, default_flow_style=False, allow_unicode=True
        )

    # security_content_repo_obj.index.commit(
    #     "Updated detection files with supported TA list."
    # )

    # epoch_time = str(int(time.time()))
    # branch_name = "security_content_automation_" + epoch_time
    # security_content_repo_obj.git.checkout("-b", branch_name)

    # security_content_repo_obj.git.push("--set-upstream", "origin", branch_name)
    # repo = g.get_repo("kirtankhatana-crest/security_content")

    # pr = repo.create_pull(
    #     title="Enrich Detection PR " + branch_name,
    #     body="This is a dummy PR",
    #     head=branch_name,
    #     base="develop",
    # )

    # try:
    #     shutil.rmtree("./security_content")
    #     shutil.rmtree("./ta_cim_mapping_reports")
    # except OSError as e:
    #     print("Error: %s - %s." % (e.filename, e.strerror))


if __name__ == "__main__":
    main()
