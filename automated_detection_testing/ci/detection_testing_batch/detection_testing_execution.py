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

def copy_local_apps_to_directory(apps: dict[str,dict], target_directory)->None:
    for key, item in apps.items():
        source_path = os.path.abspath(os.path.expanduser(item['local_path']))
        base_name = os.path.basename(source_path)
        dest_path = os.path.join(target_directory, base_name)
        
        try:
            shutil.copy(source_path, dest_path)
            item['local_path'] = dest_path
        except shutil.SameFileError as e:
            # Same file, not a real error.  The copy just doesn't happen
            print("err:%s"%(str(e)))
            pass
        except Exception as e:
            print("Error copying ESCU Package [%s] to [%s]: [%s].\n\tQuitting..." % (
                source_path, dest_path, str(e)), file=sys.stderr)
            sys.exit(1)


def ensure_security_content(branch: str, pr_number: Union[int, None], persist_security_content: bool) -> GithubService:
    if persist_security_content is True and os.path.exists("security_content"):
        print("****** You chose --persist_security_content and the security_content directory exists. "
              "We will not check out the repo again. Please be aware, this could cause issues if you're "
              "out of date. ******")
        github_service = GithubService(
            branch, existing_directory=persist_security_content)

    else:
        if persist_security_content is True and not os.path.exists("security_content"):
            print("Error - you chose --persist_security_content but the security_content directory does not exist!"
                  "  We will check it out for you.\n\tQuitting...")

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
            github_service = GithubService(branch, pr_number)
        else:
            github_service = GithubService(branch)

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


def main(args: list[str]):
    try:
        docker.client.from_env()
    except Exception as e:
        print("Error, failed to get docker client.  Is Docker Running?\n\t%s"%(str(e)))

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
    
    
    '''
    parser = argparse.ArgumentParser(description="CI Detection Testing")
    parser.add_argument("-b", "--branch", type=str, required=True, help="security content branch")
    parser.add_argument("-u", "--uuid", type=str, required=True, help="uuid for detection test")
    parser.add_argument("-pr", "--pr-number", type=int, required=False, help="Pull Request Number")

    parser.add_argument("-n", "--num_containers", required=False, type=int, default=1, help="The number of splunk docker containers to start and run for testing")
    
    parser.add_argument("-cw", "--container_password", required=False, help="A password to use for the container.  If you don't choose one, a complex one will be generated for you.")
    parser.add_argument("-show", "--show_password", required=False, default=False, action='store_true', help="Show the generated password to use to login to splunk.  For a CI/CD run, you probably don't want this.")
    parser.add_argument("-i", "--interactive_failure", required=False, default=False, action='store_true', help="If a test fails, should we pause before removing data so that the search can be debugged?")

    parser.add_argument("-ri", "--reuse_image", required=False, default=False, action='store_true', help="Should existing images be re-used, or should they be redownloaded?")
    
    #Allowing us to reuse containers is more trouble than it's worth (we may have rebuilt an app or, more likely, ESCU) and it is a pain to re-upload that
    #instead of having the container restart and download/install itself.
    #parser.add_argument("-rc", "--reuse_containers", required=False, default=False,  help="Should existing containers be re-used, or should they be rebuilt?")

    parser.add_argument("-s", "--success_file", type=str, required=False, help="File that contains previously successful runs that we don't need to test")
    parser.add_argument("-user", "--splunkbase_username", type=str, required=False, help="Splunkbase username for downloading Splunkbase apps")
    parser.add_argument("-pw", "--splunkbase_password", type=str, required=False, help="Splunkbase password for downloading Splunkbase apps")
    parser.add_argument("-m", "--mode", type=str, choices=DETECTION_MODES, required=False, help="Whether to test new detections, specific detections, or all detections", default="new")
    parser.add_argument("-tfl","--test_files_list", type=str, required=False, help="The names of files that you want to test, separated by commas.")
    parser.add_argument("-tff","--test_files_file", type=argparse.FileType('r'), required=False, help="A file containing a list of detections to run, one per line")
    parser.add_argument("-e","--escu_package", type=argparse.FileType('rb'), required=False, help="The ESCU file to use - will not generate a new ESCU package")

    parser.add_argument("-t", "--types", type=str, required=False, help="Detection types to test. Can be one of more of %s"%(str(DETECTION_TYPES)), default=','.join(DETECTION_TYPES))
    parser.add_argument("-ct", "--container_tag", type=str, required=False, help="The tag of the Splunk Container to use.  Tags are located at https://hub.docker.com/r/splunk/splunk/tags",default=DEFAULT_CONTAINER_TAG)
    parser.add_argument("-p", "--persist_security_content", required=False, default=False, action="store_true", help="Assumes security_content directory already exists.  Don't check it out and overwrite it again.  Saves "\
                                                                                                                     "time and allows you to test a detection that you've updated.  Runs generate again in case you have "\
                                                                                                                     "updated macros or anything else.  Especially useful for quick, local, iterative testing.")
    

    parser.add_argument("-split","--split_detections_then_stop", required=False, default=False, action='store_true', help="Should existing images be re-used, or should they be redownloaded?")

    
    
    
    args = parser.parse_args()
    '''
    '''
    branch = args.branch
    uuid_test = args.uuid
    pr_number = args.pr_number
    num_containers = args.num_containers
    #reuse_containers = args.reuse_containers
    reuse_image = args.reuse_image
    success_file = args.success_file
    splunkbase_username = args.splunkbase_username
    splunkbase_password = args.splunkbase_password
    full_docker_hub_container_name = "splunk/splunk:%s"%args.container_tag
    #full_docker_hub_container_name = "customimage"
    interactive_failure = args.interactive_failure
    show_password = args.show_password
    splunk_password = args.container_password
    pregenerated_escu_package = args.escu_package
    '''

    FULL_DOCKER_HUB_CONTAINER_NAME = "splunk/splunk:%s" % settings['container_tag']

    if settings['num_containers'] > MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING:
        print("You requested to run with [%d] containers which may use a very large amount of resources "
              "as they all run in parallel.  The maximum suggested number of parallel containers is "
              "[%d].  We will do what you asked, but be warned!" % (settings['num_containers'], MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING))

    # Check out security content if required
    github_service = ensure_security_content(
        settings['branch'], settings['pr_number'], settings['persist_security_content'])

    all_test_files = github_service.get_test_files(settings['mode'],
                                                   settings['folders'],
                                                   settings['types'],
                                                   settings['detections_list'],
                                                   settings['detections_file'])

    
    
    local_volume_absolute_path = os.path.abspath(
        os.path.join(os.getcwd(), "apps"))
    try:
        #remove the directory first
        shutil.rmtree(local_volume_absolute_path,ignore_errors=True)
        os.mkdir(local_volume_absolute_path)
    except FileExistsError as e:
        # Directory already exists, do nothing
        pass
    except Exception as e:
        print("Error creating the apps folder [%s]: [%s]\n\tQuitting..."
              % (local_volume_absolute_path, str(e)), file=sys.stderr)
        sys.exit(1)

    # Check to see if we want to install ESCU and whether it was preeviously generated and we should use that file
    if 'SPLUNK_ES_CONTENT_UPDATE' in settings['local_apps'] and settings['local_apps']['SPLUNK_ES_CONTENT_UPDATE']['local_path'] is not None:
        # Using a pregenerated ESCU, copy it to apps (unless it)
        pass
        #file_path = os.path.expanduser(settings['local_apps']['SPLUNK_ES_CONTENT_UPDATE']['local_path'])
        #source_path = file_path
        #dest_path = os.path.join(
        #    local_volume_absolute_path, os.path.basename(file_path))

    elif 'SPLUNK_ES_CONTENT_UPDATE' not in settings['local_apps']:
        print("%s was not found in %s.  We assume this is an error and shut down.\n\t"
              "Quitting..." % ('SPLUNK_ES_CONTENT_UPDATE', "settings['local_apps']"), file=sys.stderr)
        sys.exit(1)
    else:
        # Need to generate that package
        source_path = generate_escu_app(settings['persist_security_content'])
        settings['local_apps']['SPLUNK_ES_CONTENT_UPDATE']['local_path'] = source_path
        #dest_path = os.path.join(
        #    local_volume_absolute_path, os.path.basename(source_path))
    
    

    copy_local_apps_to_directory(settings['local_apps'], local_volume_absolute_path)
    


    
    '''
    # Now write out the package, whether it was previously generated or
    # we just generated it
    try:
        shutil.copy(source_path, dest_path)
        #Update apps path for the ESCU package we just built
        settings['local_apps']['SPLUNK_ES_CONTENT_UPDATE']['local_path'] = dest_path

    except shutil.SameFileError as e:
        # Same file, not a real error.  The copy just doesn't happen
        pass
    except Exception as e:
        print("Error copying ESCU Package [%s] to [%s]: [%s].\n\tQuitting..." % (
            source_path, dest_path, str(e)), file=sys.stderr)
        sys.exit(1)

    print("Wrote ESCU package to volume folder.")
    '''

    if settings['mock']:
        def finish_mock(settings: dict, detections: list[str], output_file_template: str = "prior_config/config_tests_%d.json"):
            num_containers = settings['num_containers']

            try:
                #Remove the prior config directory if it exists.  If not, continue
                shutil.rmtree("prior_config", ignore_errors=True)
                
                #We want to make the prior_config directory and the prior_config/apps directory
                os.makedirs("prior_config/apps")
            except FileExistsError as e:
                print("Directory priorconfig/apps exists, but we just deleted it!\m\tQuitting...",file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                print("Some error occured when trying to make the configs folder: [%s]\n\tQuitting..." % (
                    str(e)), file=sys.stderr)
                sys.exit(1)

            
            #Copy the apps to the appropriate local.  This will also update
            #the app paths in settings['local_apps']
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
                            sys.exit(1)

                except Exception as e:
                    print("Error writing config file %s: [%s]\n\tQuitting..." % (
                        fname, str(e)), file=sys.stderr)
                    sys.exit(1)

            sys.exit(0)
        finish_mock(settings, all_test_files)

    files_to_copy_to_container = OrderedDict()
    files_to_copy_to_container["INDEXES"] = {
        "local_file_path": index_file_local_path, "container_file_path": index_file_container_path}
    files_to_copy_to_container["DATAMODELS"] = {
        "local_file_path": datamodel_file_local_path, "container_file_path": datamodel_file_container_path}

    mounts = [{"local_path": local_volume_absolute_path,
               "container_path": "/tmp/apps", "type": "bind", "read_only": True}]
    
    cm = container_manager.ContainerManager(all_test_files,
                                            FULL_DOCKER_HUB_CONTAINER_NAME,
                                            settings['local_base_container_name'],
                                            settings['num_containers'],
                                            settings['local_apps'],
                                            settings['splunkbase_apps'],
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

    '''
    if args.split_detections_then_stop:
        for output_file_index in range(0, num_containers):
            fname = "container_%d_tests.txt" % (output_file_index)
            print("Writing tests to [%s]..." % (fname), end='')
            with open(fname, "w") as output_file:
                detection_tests = test_files[output_file_index::num_containers]
                normalized_detection_names = []
                for d in detection_tests:
                    filename = os.path.basename(d)
                    filename = filename.replace(".test.yml", ".yml")
                    leading = os.path.split(d)[0]
                    leading = leading.replace("tests/", "detections/")
                    new_name = os.path.join(
                        "security_content", leading, filename)
                    normalized_detection_names.append(new_name)
                output_file.write('\n'.join(normalized_detection_names))
            print("Done")
        sys.exit(0)

    # Create threads to manage all of the containers that we will start up
    splunk_container_manager_threads = []

    results_tracker = SynchronizedResultsTracker(test_files, num_containers)

    #SPLUNK_ADD_ON_FOR_SYSMON_OLD = "https://splunkbase.splunk.com/app/1914/release/10.6.2/download"
    #SPLUNK_ADD_ON_FOR_SYSMON_NEW = "https://splunkbase.splunk.com/app/5709/release/1.0.1/download"
    #SYSMON_APP_FOR_SPLUNK = "https://splunkbase.splunk.com/app/3544/release/2.0.0/download"
    #SPLUNK_ES_CONTENT_UPDATE = "https://splunkbase.splunk.com/app/3449/release/3.29.0/download"

    # Just a hack until we get the new version of system deployed and available from splunkbase
    CONTAINER_VOLUME_PATH = '/tmp/apps/'

    GENERATED_SPLUNK_ES_CONTENT_UPDATE_CONTAINER_PATH = os.path.join(
        CONTAINER_VOLUME_PATH, "DA-ESS-ContentUpdate-latest.tar.gz")

    SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/%d/release/%s/download"
    # Order that we install the apps is actually important
    APPS_DICT = OrderedDict()
    APPS_DICT['SPLUNK_ADD_ON_FOR_MICROSOFT_WINDOWS'] = {
        "app_number": 742, 'app_version': "8.2.0", 'location': 'splunkbase'}
    APPS_DICT['SPLUNK_SECURITY_ESSENTIALS'] = {
        "app_number": 3435, 'app_version': "3.3.4", 'location': 'splunkbase'}
    APPS_DICT['GENERATED_SPLUNK_ES_CONTENT_UPDATE'] = {"app_number": 3449, 'app_version': "Generated at %s" % (
        datetime.now()), 'location': GENERATED_SPLUNK_ES_CONTENT_UPDATE_CONTAINER_PATH}

    try:
        BETA_SPLUNK_ADD_ON_FOR_SYSMON_PATH = os.path.expanduser(
            "~/Downloads/Splunk_TA_microsoft_sysmon-1.0.2-B1.spl")
        shutil.copyfile(BETA_SPLUNK_ADD_ON_FOR_SYSMON_PATH, os.path.join(
            local_volume_path, "Splunk_TA_microsoft_sysmon-1.0.2-B1.spl"))

        BETA_SPLUNK_ADD_ON_FOR_SYSMON_CONTAINER_PATH = "/tmp/apps/Splunk_TA_microsoft_sysmon-1.0.2-B1.spl"
        APPS_DICT['BETA_SPLUNK_ADD_ON_FOR_SYSMON'] = {"app_number": 5709, 'app_version': "Generated at %s" % (
            datetime.now()), 'location': "local", "container_path": BETA_SPLUNK_ADD_ON_FOR_SYSMON_CONTAINER_PATH}
    except Exception as e:
        print("Failed to grab beta sysmon at ~/Downloads/Splunk_TA_microsoft_sysmon-1.0.2-B1.spl. Using the one from Splunkbase")
        APPS_DICT['SPLUNK_ADD_ON_FOR_SYSMON'] = {
            "app_number": 5709, 'app_version': "1.0.1", 'location': 'splunkbase'}

    if True:
        APPS_DICT['SPLUNK_ADD_ON_FOR_AMAZON_WEB_SERVICES'] = {
            "app_number": 1876, 'app_version': "5.2.0", 'location': 'splunkbase'}
        APPS_DICT['SPLUNK_ADD_ON_FOR_MICROSOFT_OFFICE_365'] = {
            "app_number": 4055, 'app_version': "2.2.0", 'location': 'splunkbase'}
        APPS_DICT['SPLUNK_ADD_ON_FOR_AMAZON_KINESIS_FIREHOSE'] = {
            "app_number": 3719, 'app_version': "1.3.2", 'location': 'splunkbase'}
        APPS_DICT['SPLUNK_ANALYTIC_STORY_EXECUTION_APP'] = {
            "app_number": 4971, 'app_version': "2.0.3", 'location': 'splunkbase'}
        APPS_DICT['PYTHON_FOR_SCIENTIC_COMPUTING_LINUX_64_BIT'] = {
            "app_number": 2882, 'app_version': "2.0.2", 'location': 'splunkbase'}
        APPS_DICT['SPLUNK_MACHINE_LEARNING_TOOLKIT'] = {
            "app_number": 2890, 'app_version': "5.2.2", 'location': 'splunkbase'}
        APPS_DICT['SPLUNK_APP_FOR_STREAM'] = {
            "app_number": 1809, 'app_version': "8.0.1", 'location': 'splunkbase'}
        APPS_DICT['SPLUNK_ADD_ON_FOR_STREAM_WIRE_DATA'] = {
            "app_number": 5234, 'app_version': "8.0.1", 'location': 'splunkbase'}
        APPS_DICT['SPLUNK_ADD_ON_FOR_STREAM_FORWARDERS'] = {
            "app_number": 5238, 'app_version': "8.0.1", 'location': 'splunkbase'}
        APPS_DICT['SPLUNK_ADD_ON_FOR_ZEEK_AKA_BRO'] = {
            "app_number": 1617, 'app_version': "4.0.0", 'location': 'splunkbase'}
        APPS_DICT['SPLUNK_ADD_ON_FOR_UNIX_AND_LINUX'] = {
            "app_number": 833, 'app_version': "8.3.1", 'location': 'splunkbase'}

    # CIM is last here for a reason!  Because we copy a file to a directory that does not exist until CIM
    # has been installed, we use it to prevent the testing from beginning until the copy has succeeded.
    # KEEP THIS APP LAST!
    APPS_DICT['SPLUNK_COMMON_INFORMATION_MODEL'] = {
        "app_number": 1621, 'app_version': "4.20.2", 'location': 'splunkbase'}

    SPLUNK_APPS = []
    for key, value in APPS_DICT.items():
        if value['location'] == 'splunkbase':
            # The app is on Splunkbase
            target = SPLUNKBASE_URL % (
                value['app_number'], value['app_version'])
            SPLUNK_APPS.append(target)
        else:
            # The app is a file we generated locally
            SPLUNK_APPS.append(value['location'])

    for container_index in range(num_containers):
        container_name = LOCAL_BASE_CONTAINER_NAME % container_index

        web_port = BASE_CONTAINER_WEB_PORT + container_index
        management_port = BASE_CONTAINER_MANAGEMENT_PORT + container_index

        environment = {"SPLUNK_START_ARGS": "--accept-license",
                       "SPLUNK_PASSWORD": splunk_password,
                       "SPLUNK_APPS_URL": ','.join(SPLUNK_APPS),
                       "SPLUNKBASE_USERNAME": splunkbase_username,
                       "SPLUNKBASE_PASSWORD": splunkbase_password
                       }
        ports = {"8000/tcp": web_port,
                 "8089/tcp": management_port
                 }

        mounts = [docker.types.Mount(
            target=CONTAINER_VOLUME_PATH, source=local_volume_path, type='bind', read_only=True)]

        print("Creating CONTAINER: [%s]" % (container_name))
        base_container = client.containers.create(
            full_docker_hub_container_name, ports=ports, environment=environment, name=container_name, mounts=mounts, detach=True)
        print("Created CONTAINER : [%s]" % (container_name))

        t = threading.Thread(target=splunk_container_manager,
                             args=(results_tracker,
                                   container_name,
                                   "127.0.0.1",
                                   splunk_password,
                                   web_port,
                                   management_port,
                                   uuid_test,
                                   interactive_failure
                                   ))

        splunk_container_manager_threads.append(t)

    # add the queue status thread - there can be some error in one of the test threads, so this
    # thread doesn't need to complete for the program to finish execution
    status_thread = threading.Thread(target=queue_status_thread,
                                     args=(results_tracker,),
                                     daemon=True)
    # Start this thread immediately
    status_thread.start()

    print("Start the testing threads")
    for t in splunk_container_manager_threads:
        t.start()
        # we need to start containers slowly.  Would be great it we could do all the setup and
        # app install once, but it looks like the container is unlikely to support that.
        # We don't really want to fundamentally change this container, either, and will
        # keep it as close to production as possible
        time.sleep(5)

    # Wait for all of the testing threads to complete
    for t in splunk_container_manager_threads:
        t.join()  # blocks on waiting to join
        print("Testing thread completed execution")

    print("All testing threads have completed execution")
    # read all the results out from the output queue
    strtime = str(int(time.time()))

    print("Wait for the status thread to finish executing...")
    status_thread.join()
    print("Status thread finished executing.")

    # Remove the attack data and
    # generate all of the output information
    stop_time = timer()
    stop_datetime = datetime.now()
    baseline = OrderedDict()
    baseline['SPLUNK_VERSION'] = full_docker_hub_container_name
    baseline['SPLUNK_APPS'] = APPS_DICT
    baseline['TEST_START_TIME'] = str(start_datetime)
    baseline['TEST_FINISH_TIME'] = str(stop_datetime)

    results_tracker.finish(baseline)

    # now we are done!

    print("Total Execution Time: [%s]" % (
        timedelta(seconds=stop_time - start_time, microseconds=0)))

    # detection testing service has already been prepared, no need to do it here!
    #testing_service.prepare_detection_testing(ssh_key_name, private_key, splunk_ip, splunk_password)

    #testing_service.test_detections(ssh_key_name, private_key, splunk_ip, splunk_password, test_files, uuid_test)
    '''


if __name__ == "__main__":
    main(sys.argv[1:])
