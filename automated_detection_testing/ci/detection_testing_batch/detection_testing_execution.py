import argparse
import copy
import csv
import json
import os
from posixpath import basename
import queue
import random
import secrets
import shutil
import string
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from datetime import datetime, timedelta
from tempfile import mkdtemp
from timeit import default_timer as timer
from typing import Union

import docker
import requests.packages.urllib3
from docker.client import DockerClient
from requests import get
from modules import new_arguments2
from modules.validate_args import validate_and_write
from modules import container_manager

import modules.new_arguments2
from modules import aws_service, testing_service, validate_args
from modules.github_service import GithubService
from modules.validate_args import validate

SPLUNK_CONTAINER_APPS_DIR = "/opt/splunk/etc/apps"
index_file_local_path = "indexes.conf.tar"
index_file_container_path = os.path.join(SPLUNK_CONTAINER_APPS_DIR, "search")

# Should be the last one we copy.
datamodel_file_local_path = "datamodels.conf.tar"
datamodel_file_container_path = os.path.join(
    SPLUNK_CONTAINER_APPS_DIR, "Splunk_SA_CIM")


MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING = 2


def copy_local_apps_to_directory(apps: dict[str, dict], target_directory) -> None:
    for key, item in apps.items():
        source_path = os.path.abspath(os.path.expanduser(item['local_path']))
        base_name = os.path.basename(source_path)
        dest_path = os.path.join(target_directory, base_name)

        try:
            shutil.copy(source_path, dest_path)
            item['local_path'] = dest_path
        except shutil.SameFileError as e:
            # Same file, not a real error.  The copy just doesn't happen
            print("err:%s" % (str(e)))
            pass
        except Exception as e:
            print("Error copying ESCU Package [%s] to [%s]: [%s].\n\tQuitting..." % (
                source_path, dest_path, str(e)), file=sys.stderr)
            sys.exit(1)


def ensure_security_content(branch: str, commit_hash: str, pr_number: Union[int, None], persist_security_content: bool) -> GithubService:
    if persist_security_content is True and os.path.exists("security_content"):
        print("****** You chose --persist_security_content and the security_content directory exists. "
              "We will not check out the repo again. Please be aware, this could cause issues if you're "
              "out of date. ******")
        github_service = GithubService(
            branch, commit_hash, existing_directory=persist_security_content)

    else:
        if persist_security_content is True and not os.path.exists("security_content"):
            print("Error - you chose --persist_security_content but the security_content directory does not exist!"
                  "  We will check it out for you.")

        elif os.path.exists("security_content/"):
            print("Deleting the security_content directory")
            try:
                shutil.rmtree("security_content/", ignore_errors=True)
                print("Successfully removed security_content directory")
            except Exception as e:
                print(
                    "Error - could not remove the security_content directory: [%s].\n\tQuitting..." % (str(e)))
                sys.exit(1)

        if pr_number:
            github_service = GithubService(branch, commit_hash, pr_number)
        else:
            github_service = GithubService(branch, commit_hash)

    return github_service


def generate_escu_app(persist_security_content: bool = False) -> str:
    # Go into the security content directory
    print("****GENERATING ESCU APP****")
    os.chdir("security_content")
    if persist_security_content is False:
        commands = ["python3 -m venv .venv",
                    ". ./.venv/bin/activate",
                    "python3 -m pip install wheel",
                    "python3 -m pip install -r requirements.txt",
                    "python3 contentctl.py --path . --verbose generate --product ESCU --output dist/escu",
                    "tar -czf DA-ESS-ContentUpdate.spl -C dist/escu ."]
    else:
        commands = [". ./.venv/bin/activate",
                    "python3 contentctl.py --path . --verbose generate --product ESCU --output dist/escu",
                    "tar -czf DA-ESS-ContentUpdate.spl -C dist/escu ."]
    ret = subprocess.run("; ".join(commands),
                         shell=True, capture_output=True)
    if ret.returncode != 0:
        print("Error generating new content.\n\tQuitting and dumping error...\n[%s]" % (
            ret.stderr))
        sys.exit(1)

    output_file_name = "DA-ESS-ContentUpdate-latest.tar.gz"
    output_file_path_from_slim_latest = os.path.join(
        "upload", output_file_name)
    output_file_path_from_security_content = os.path.join(
        "slim_packaging", "slim_latest", output_file_path_from_slim_latest)
    output_file_path_from_root = os.path.join(
        "security_content", output_file_path_from_security_content)

    if persist_security_content is True:
        try:
            os.remove(output_file_path_from_security_content)
        except FileNotFoundError:
            # No problem if we fail to remove it, that just means it wasn't there and we didn't need to
            pass
        except Exception as e:
            print("Error deleting the (possibly) existing old ESCU File: [%s]" % (
                str(e)), file=sys.stderr)
            sys.exit(1)

        # There remove the latest file if it exists
        commands = ["cd slim_packaging/slim_latest",
                    ". ./.venv/bin/activate",
                    "cp -R ../../dist/escu DA-ESS-ContentUpdate",
                    "slim package -o upload DA-ESS-ContentUpdate",
                    "cp upload/DA-ESS-ContentUpdate*.tar.gz %s" % (output_file_path_from_slim_latest)]

    else:
        os.mkdir("slim_packaging")
        os.mkdir("apps")
        try:
            SPLUNK_PACKAGING_TOOLKIT_URL = "https://download.splunk.com/misc/packaging-toolkit/splunk-packaging-toolkit-0.9.0.tar.gz"
            SPLUNK_PACKAGING_TOOLKIT_FILENAME = 'splunk-packaging-toolkit-latest.tar.gz'
            print("Downloading the Splunk Packaging Toolkit from %s..." %
                  (SPLUNK_PACKAGING_TOOLKIT_URL), end='')
            response = get(SPLUNK_PACKAGING_TOOLKIT_URL)
            response.raise_for_status()
            with open(SPLUNK_PACKAGING_TOOLKIT_FILENAME, 'wb') as slim_file:
                slim_file.write(response.content)
            print("Done")
        except Exception as e:
            print("Error downloading the Splunk Packaging Toolkit: [%s].\n\tQuitting..." %
                  (str(e)), file=sys.stderr)
            sys.exit(1)

        commands = ["rm -rf slim_packaging/slim_latest",
                    "mkdir slim_packaging/slim_latest",
                    "cd slim_packaging",
                    "tar -zxf splunk-packaging-toolkit-latest.tar.gz -C slim_latest --strip-components=1",
                    "cd slim_latest",
                    "virtualenv --python=/usr/bin/python2.7 --clear .venv",
                    ". ./.venv/bin/activate",
                    "python3 -m pip install --upgrade pip",
                    "python2 -m pip install wheel",
                    "python2 -m pip install semantic_version",
                    "python2 -m pip install .",
                    "cp -R ../../dist/escu DA-ESS-ContentUpdate",
                    "slim package -o upload DA-ESS-ContentUpdate",
                    "cp upload/DA-ESS-ContentUpdate*.tar.gz %s" % (output_file_path_from_slim_latest)]

    ret = subprocess.run("; ".join(commands),
                         shell=True, capture_output=True)
    if ret.returncode != 0:
        print("Command List:\n%s" % (commands))
        print("Error generating new ESCU Package.\n\tQuitting and dumping error...\n[%s]" % (
            ret.stderr.decode('utf-8')), file=sys.stderr)
        sys.exit(1)
    os.chdir("../")

    return output_file_path_from_root


def finish_mock(settings: dict, detections: list[str], output_file_template: str = "prior_config/config_tests_%d.json")->bool:
    num_containers = settings['num_containers']

    try:
        # Remove the prior config directory if it exists.  If not, continue
        shutil.rmtree("prior_config", ignore_errors=True)

        # We want to make the prior_config directory and the prior_config/apps directory
        os.makedirs("prior_config/apps")
    except FileExistsError as e:
        print("Directory priorconfig/apps exists, but we just deleted it!\m\tQuitting...", file=sys.stderr)
        return False
    except Exception as e:
        print("Some error occured when trying to make the configs folder: [%s]\n\tQuitting..." % (
            str(e)), file=sys.stderr)
        return False

    # Copy the apps to the appropriate local.  This will also update
    # the app paths in settings['local_apps']
    copy_local_apps_to_directory(settings['local_apps'], "prior_config/apps")

    for output_file_index in range(0, num_containers):
        fname = output_file_template % (output_file_index)

        # Get the n'th detection for this file
        detection_tests = detections[output_file_index::num_containers]
        normalized_detection_names = []
        # Normalize the test filename to the name of the detection instead.
        # These are what we should write to the file
        for d in detection_tests:
            filename = os.path.basename(d)
            filename = filename.replace(".test.yml", ".yml")
            leading = os.path.split(d)[0]
            leading = leading.replace("tests/", "detections/")
            new_name = os.path.join(
                "security_content", leading, filename)
            normalized_detection_names.append(new_name)

        # Generate an appropriate config file for this test
        mock_settings = copy.deepcopy(settings)
        # This may be able to support as many as 2 for GitHub Actions...
        # we will have to determine in testing.
        mock_settings['num_containers'] = 1

        # Must be selected since we are passing in a list of detections
        mock_settings['mode'] = 'selected'

        # Pass in the list of detections to run
        mock_settings['detections_list'] = normalized_detection_names

        # We want to persist security content and run with the escu package that we created
        mock_settings['persist_security_content'] = True

        mock_settings['mock'] = False

        # Make sure that it still validates after all of the changes

        try:
            with open(fname, 'w') as cfg:
                validated_settings, b = validate_and_write(
                    mock_settings, cfg)
                if validated_settings is None:
                    print(
                        "There was an error validating the updated mock settings.\n\tQuitting...", file=sys.stderr)
                    return False

        except Exception as e:
            print("Error writing config file %s: [%s]\n\tQuitting..." % (
                fname, str(e)), file=sys.stderr)
            return False

    return True


def main(args: list[str]):
    #Disable insecure warnings.  We make a number of HTTPS requests to Splunk
    #docker containers that we've set up.  Without this line, we get an 
    #insecure warning every time due to invalid cert.
    requests.packages.urllib3.disable_warnings()

    start_datetime = datetime.now()
    action, settings = modules.new_arguments2.parse(args)
    if action == "configure":
        # Done, nothing else to do
        print("Configuration complete!")
        sys.exit(0)
    elif action != "run":
        print("Unsupported action: [%s]" % (action), file=sys.stderr)
        sys.exit(1)

    if settings['mock'] is False:
        # If this is a real run, then make sure Docker is installed and running and usable
        # If this is a mock, then that is not required.  By only checking on a non-mock
        # run, we save ourselves the need to install docker in the CI for the manifest
        # generation step.
        try:
            docker.client.from_env()
        except Exception as e:
            print("Error, failed to get docker client.  Is Docker Installed and Running?\n\t%s" % (str(e)))

    
    FULL_DOCKER_HUB_CONTAINER_NAME = "splunk/splunk:%s" % settings['container_tag']

    if settings['num_containers'] > MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING:
        print("You requested to run with [%d] containers which may use a very large amount of resources "
              "as they all run in parallel.  The maximum suggested number of parallel containers is "
              "[%d].  We will do what you asked, but be warned!" % (settings['num_containers'], MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING))

    # Check out security content if required
    github_service = ensure_security_content(
        settings['branch'], settings['commit_hash'], settings['pr_number'], settings['persist_security_content'])
    settings['commit_hash'] = github_service.commit_hash

    # Make a backup of this config containing the hash and stripped credentials.
    # This makes the test perfectly reproducible.
    validate_args.validate_and_write(
        settings, output_file=None, strip_credentials=True)

    all_test_files = github_service.get_test_files(settings['mode'],
                                                   settings['folders'],
                                                   settings['types'],
                                                   settings['detections_list'],
                                                   settings['detections_file'])


    #Set up the directory that will be used to store the local apps/apps we build
    local_volume_absolute_path = os.path.abspath(
        os.path.join(os.getcwd(), "apps"))
    try:
        # remove the directory first
        shutil.rmtree(local_volume_absolute_path, ignore_errors=True)
        os.mkdir(local_volume_absolute_path)
    except FileExistsError as e:
        # Directory already exists, do nothing
        pass
    except Exception as e:
        print("Error creating the apps folder [%s]: [%s]\n\tQuitting..."
              % (local_volume_absolute_path, str(e)), file=sys.stderr)
        sys.exit(1)
    #Add the info about the mount
    mounts = [{"local_path": local_volume_absolute_path,
               "container_path": "/tmp/apps", "type": "bind", "read_only": True}]


    # Check to see if we want to install ESCU and whether it was preeviously generated and we should use that file
    if 'SPLUNK_ES_CONTENT_UPDATE' in settings['local_apps'] and settings['local_apps']['SPLUNK_ES_CONTENT_UPDATE']['local_path'] is not None:
        # Using a pregenerated ESCU, no need to build it
        pass
    elif 'SPLUNK_ES_CONTENT_UPDATE' not in settings['local_apps']:
        print("%s was not found in %s.  We assume this is an error and shut down.\n\t"
              "Quitting..." % ('SPLUNK_ES_CONTENT_UPDATE', "settings['local_apps']"), file=sys.stderr)
        sys.exit(1)
    else:
        # Generate the ESCU package from this branch.
        source_path = generate_escu_app(settings['persist_security_content'])
        settings['local_apps']['SPLUNK_ES_CONTENT_UPDATE']['local_path'] = source_path
        

    # Copy all the apps, to include ESCU (whether pregenerated or just generated)
    copy_local_apps_to_directory(
        settings['local_apps'], local_volume_absolute_path)


    # If this is a mock run, finish it now
    if settings['mock']:
        #The function below 
        if finish_mock(settings, all_test_files):
            # mock was successful!
            print("Mock successful!  Manifests generated!")
            sys.exit(0)
        else:
            print("There was an unrecoverage error during the mock.\n\tQuitting...",file=sys.stderr)
            sys.exit(1)



    #Add some files that always need to be copied to to container to set up indexes and datamodels.
    files_to_copy_to_container = OrderedDict()
    files_to_copy_to_container["INDEXES"] = {
        "local_file_path": index_file_local_path, "container_file_path": index_file_container_path}
    files_to_copy_to_container["DATAMODELS"] = {
        "local_file_path": datamodel_file_local_path, "container_file_path": datamodel_file_container_path}

    

    cm = container_manager.ContainerManager(all_test_files,
                                            FULL_DOCKER_HUB_CONTAINER_NAME,
                                            settings['local_base_container_name'],
                                            settings['num_containers'],
                                            settings['local_apps'],
                                            settings['splunkbase_apps'],
                                            settings['branch'],
                                            settings['commit_hash'],
                                            files_to_copy_to_container=files_to_copy_to_container,
                                            web_port_start=8000,
                                            management_port_start=8089,
                                            mounts=mounts,
                                            show_container_password=settings['show_splunk_app_password'],
                                            container_password=settings['splunk_app_password'],
                                            splunkbase_username=settings['splunkbase_username'],
                                            splunkbase_password=settings['splunkbase_password'],
                                            reuse_image=settings['reuse_image'],
                                            interactive_failure=settings['interactive_failure'])

    cm.run_test()


if __name__ == "__main__":
    main(sys.argv[1:])
