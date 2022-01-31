import base64
import io
import json
import logging
import os
import re
import shutil
import sys
import time
import csv

import git
import yaml
from github import Github


def fetch_ta_cim_mapping_report(file_name):
    try:
        with open(file_name) as file_content:
            cim_field_report = json.load(file_content)
            return cim_field_report
    except Exception as error:
        error_message = "Unexpected error occurred while reading file."
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
    add_addon = False
    flag = 0
    for item in required_fields:
        # Only required field with valid format will be mapped
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
    detection_obj = load_file(file)
    detection_obj["tags"][keyname] = ta_list

    with open(file, "w") as f:
        yaml.dump(detection_obj, f, sort_keys=False, allow_unicode=True)


def main():

    security_content_repo = "splunk/security_content"
    security_content_branch = "develop"

    ta_cim_field_reports_repo = "splunk/ta-cim-field-reports"
    ta_cim_field_reports_branch = "main"

    # Decodin GITHUB_ACCESS_TOKEN from base64
    git_token_base64_bytes = os.environ.get("GITHUB_ACCESS_TOKEN").encode('ascii')
    git_token_bytes = base64.b64decode(git_token_base64_bytes)
    github_token = git_token_bytes.decode('ascii') 

    g = Github(github_token)
    detection_types = ["cloud", "endpoint", "network"]
    cim_report_path = (
        "ta_cim_mapping_reports/ta_cim_mapping/cim_mapping_reports/latest/"
    )
    detection_ta_mapping = {}

    # clone security content repository
    security_content_repo_obj = git.Repo.clone_from(
        "https://"
        + github_token
        + ":x-oauth-basic@github.com/"
        + security_content_repo,
        "security_content",
        branch=security_content_branch,
    )

    # clone ta cim field reports repository
    ta_cim_field_reports_obj = git.Repo.clone_from(
        "https://"
        + github_token
        + ":x-oauth-basic@github.com/"
        + ta_cim_field_reports_repo,
        "ta_cim_mapping_reports",
        branch=ta_cim_field_reports_branch,
    )

    # iterate for every detection types
    for detection_type in detection_types:

        for subdir, _, files in os.walk(f"security_content/tests/{detection_type}"):

            for file in files:
                filepath = subdir + os.sep + file
                recommended_ta_list = []
                tas_with_data_list = []
                detection_obj = load_file(filepath)
                source_types = []
                for data in detection_obj.get("tests")[0].get("attack_data"):
                    source_types.append(data.get("sourcetype"))

                detection_file_name = (
                    detection_obj.get("tests")[0]
                    .get("file")
                    .rsplit("/", 1)[1]
                    .strip(".yml")
                )
                filepath = "security_content/detections/" + detection_obj.get("tests")[
                    0
                ].get("file")
                if not os.path.isfile(filepath):
                    continue

                if is_valid_detection_file(filepath):
                    for ta_cim_mapping_file in os.listdir(cim_report_path):

                        ta_cim_map = fetch_ta_cim_mapping_report(
                            cim_report_path + ta_cim_mapping_file
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
                            recommended_ta_list.append(
                                ta_cim_map.get("ta_name").get("name")
                            )
                            ta_sourcetype = ta_cim_map["sourcetypes"]
                            for source_type in source_types:

                                if (
                                    source_type in ta_sourcetype
                                    and ta_cim_map.get("ta_name").get("name")
                                    not in tas_with_data_list
                                ):
                                    tas_with_data_list.append(
                                        ta_cim_map.get("ta_name").get("name")
                                    )
                            detection_ta_mapping[detection_file_name] = {}

                    if recommended_ta_list:
                        keyname = "tas_with_cim_mapping"
                        enrich_detection_file(filepath, cim_version, "cim_version")
                        enrich_detection_file(filepath, recommended_ta_list, keyname)
                        detection_ta_mapping[detection_file_name][
                            "cim_version"
                        ] = cim_version
                        detection_ta_mapping[detection_file_name][
                            keyname
                        ] = recommended_ta_list

                    if tas_with_data_list:
                        keyname = "supported_tas"
                        enrich_detection_file(filepath, tas_with_data_list, keyname)
                        detection_ta_mapping[detection_file_name][
                            keyname
                        ] = tas_with_data_list

                    security_content_repo_obj.index.add(
                        [filepath.strip("security_content/")]
                    )
    # Generating detection_ta_mapping CSV report
    try:
        with open(r"./security_content/security_content_automation/detection_ta_mapping.csv", 'w+', newline='') as csv_file:
            fieldnames = ['detection_name', 'cim_version', 'supported_tas', 'tas_with_cim_mapping']
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for detection_name, detection_content in detection_ta_mapping.items():
                detection_content.update({
                    'tas_with_cim_mapping': ', '.join(detection_content["tas_with_cim_mapping"]) if detection_content.get(
                        'tas_with_cim_mapping') else '',
                    'supported_tas': ', '.join(detection_content["supported_tas"]) if detection_content.get(
                        'supported_tas') else '',
                    'detection_name': detection_name
                })
                writer.writerow(detection_content)
    except Exception as error:
        error_message = f"Unexpected error occurred while generating detection_ta_mapping CSV report, {error}"
        logging.error(error_message)
    security_content_repo_obj.index.add(
        ["security_content_automation/detection_ta_mapping.csv"]
    )

    with io.open(
        r"./security_content/security_content_automation/detection_ta_mapping.yml",
        "w",
        encoding="utf8",
    ) as outfile:
        yaml.safe_dump(
            detection_ta_mapping, outfile, default_flow_style=False, allow_unicode=True
        )
    security_content_repo_obj.index.add(
        ["security_content_automation/detection_ta_mapping.yml"]
    )
    security_content_repo_obj.index.commit(
        "Updated detection files with recommended TA list."
    )

    epoch_time = str(int(time.time()))
    branch_name = "security_content_automation_" + epoch_time
    security_content_repo_obj.git.checkout("-b", branch_name)
    security_content_repo_obj.git.push("--set-upstream", "origin", branch_name)
    repo = g.get_repo("splunk/security_content")

    pr = repo.create_pull(
        title="Enrich Detection PR " + branch_name,
        body="Enriched the detections with recommended TAs",
        head=branch_name,
        base="develop",
    )

    try:
        shutil.rmtree("./security_content")
        shutil.rmtree("./ta_cim_mapping_reports")
    except OSError as e:
        error_message = "Unexpected error occurred while deleting files."
        logging.error(error_message)


if __name__ == "__main__":
    main()
