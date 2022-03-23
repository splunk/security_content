import argparse
import copy
import csv
from ctypes.wintypes import tagRECT
import json
import os
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
from posixpath import basename
from tempfile import mkdtemp
from timeit import default_timer as timer
from typing import Union
from urllib.parse import urlparse
import signal


import docker
import requests
import requests.packages.urllib3
from docker.client import DockerClient
from requests import get

import modules.new_arguments2
from modules import (container_manager, new_arguments2,
                     testing_service, validate_args)
from modules.github_service import GithubService
from modules.validate_args import validate, validate_and_write, ES_APP_NAME

SPLUNK_CONTAINER_APPS_DIR = "/opt/splunk/etc/apps"
index_file_local_path = "indexes.conf.tar"
index_file_container_path = os.path.join(SPLUNK_CONTAINER_APPS_DIR, "search")

# Should be the last one we copy.
datamodel_file_local_path = "datamodels.conf.tar"
datamodel_file_container_path = os.path.join(
    SPLUNK_CONTAINER_APPS_DIR, "Splunk_SA_CIM")


authorizations_file_local_path = "authorize.conf.tar"
authorizations_file_container_path = "/opt/splunk/etc/system/local"

CONTAINER_APP_DIRECTORY = "apps"

MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING = 2





def download_file_from_http(url:str, destination_file:str, overwrite_file:bool=False)->None:
    if os.path.exists(destination_file) and overwrite_file is False:
        print(f"[{destination_file}] already exists...using cached version")
        return
    print(f"downloading to [{destination_file}]")
    file_to_download = requests.get(url, stream=True)
    with open(destination_file, "wb") as output:
        for piece in file_to_download.iter_content(chunk_size=(1024*1024)):
            output.write(piece)
    

def copy_local_apps_to_directory(apps: dict[str, dict], splunkbase_username:tuple[str,None] = None, splunkbase_password:tuple[str,None] = None, mock:bool = False, target_directory:str = "apps") -> str:
    if mock is True:
        target_directory = os.path.join("prior_config", target_directory)
        
        # Remove the apps directory or the prior config directory.  If it's just an apps directory, then we don't want
        #to remove that.
        shutil.rmtree(target_directory, ignore_errors=True)
    try:
        # Make sure the directory exists.  If it already did, that's okay. Don't delete anything from it
        # We want to re-use previously downloaded apps
        os.makedirs(target_directory, exist_ok = True)
        
    except Exception as e:
        raise(Exception(f"Some error occured when trying to make the {target_directory}: [{str(e)}]"))

    
    for key, item in apps.items():

        # These apps are URLs that will be passed.  The apps will be downloaded and installed by the container
        # # Get the file from an http source
        splunkbase_info = True if ('app_number' in item and item['app_number'] is not None and 
                                  'app_version' in item and item['app_version'] is not None) else False
        splunkbase_creds = True if (splunkbase_username is not None and 
                                   splunkbase_password is not None) else False
        can_download_from_splunkbase = splunkbase_info and splunkbase_creds

        

        #local apps can either have a local_path or an http_path
        if 'local_path' in item:
            source_path = os.path.abspath(os.path.expanduser(item['local_path']))
            base_name = os.path.basename(source_path)
            dest_path = os.path.join(target_directory, base_name)
            try:
                print(f"copying {os.path.relpath(source_path)} to {os.path.relpath(dest_path)}")
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

        
        elif can_download_from_splunkbase is True:
            #Don't do anything, this will be downloaded from splunkbase
            pass
        elif splunkbase_info is True and splunkbase_creds is False and mock is True:
            #Don't need to do anything, when this actually runs the apps will be downloaded from Splunkbase
            #There is another opportunity to provide the creds then
            pass
        elif 'http_path' in item and can_download_from_splunkbase is False:
            http_path = item['http_path']
            try:
                url_parse_obj = urlparse(http_path)
                path_after_host = url_parse_obj[2].rstrip('/') #removes / at the end, if applicable
                base_name = path_after_host.rpartition('/')[-1] #just get the file name
                dest_path = os.path.join(target_directory, base_name) #write the whole path
                download_file_from_http(http_path, dest_path)
                #we need to update the local path because this is used to copy it into the container later
                item['local_path'] = dest_path
                #Remove the HTTP Path, we will use the local_path instead
            except Exception as e:
                print("Error trying to download %s @ %s: [%s].  This app is required.\n\tQuitting..."%(key, http_path, str(e)),file=sys.stderr)
                sys.exit(1)

        elif splunkbase_info is False:
            print(f"Error - trying to install an app [{key}] that does not have 'local_path', 'http_path', "
                   "or 'app_version' and 'app_number' for installing from Splunkbase.\n\tQuitting...")
            sys.exit(1)
    return target_directory


def ensure_security_content(branch: str, commit_hash: Union[str,None], pr_number: Union[int, None], persist_security_content: bool) -> tuple[GithubService, bool]:
    if persist_security_content is True and os.path.exists("security_content"):
        print("****** You chose --persist_security_content and the security_content directory exists. "
              "We will not check out the repo again. Please be aware, this could cause issues if your "
              "repo is out of date or if a previous build failed to download all required tools and "\
              "libraries.  If this occurs, it is suggested to change the "\
              "persist_security_content setting to false. ******")
              
        github_service = GithubService(
            branch, commit_hash, persist_security_content=persist_security_content)

    else:
        if persist_security_content is True and not os.path.exists("security_content"):
            print("Error - you chose --persist_security_content but the security_content directory does not exist!"
                  "  We will check it out for you.")
            persist_security_content = False

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

    return github_service, persist_security_content


def generate_escu_app(persist_security_content: bool = False) -> str:
    # Go into the security content directory
    print("****GENERATING ESCU APP****")
    os.chdir("security_content")
    if persist_security_content is False:
        commands = ["python3 -m venv .venv",
                    ". ./.venv/bin/activate",
                    "python -m pip install wheel",
                    "python -m pip install -r requirements.txt",
                    "python3 contentctl.py --path . generate --product ESCU --output dist/escu"]
    else:
        commands = [". ./.venv/bin/activate",
                    "python3 contentctl.py --path . generate --product ESCU --output dist/escu"]
    ret = subprocess.run("; ".join(commands),
                         shell=True, capture_output=True)
    if ret.returncode != 0:
        print("Error generating new content.\n\tQuitting and dumping error...\n[%s]" % (
            ret.stderr))
        sys.exit(1)

    ret = subprocess.run("tar -czf DA-ESS-ContentUpdate.spl -C dist/escu .",
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
                    "tar -zxf ../splunk-packaging-toolkit-latest.tar.gz -C slim_latest --strip-components=1",
                    "cd slim_latest",
                    "python3 -m venv .venv",
                    ". ./.venv/bin/activate",
                    "python -m pip install --upgrade pip",
                    "python -m pip install wheel",
                    "python -m pip install semantic_version",
                    "python -m pip install .",
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

        # We want to persist security content and run with the escu package that we created.
        #Note that if we haven't checked this out yet, we will check it out for you.
        mock_settings['persist_security_content'] = True

        mock_settings['mock'] = False

        # Make sure that it still validates after all of the changes

        try:
            with open(fname, 'w') as outfile:
                validated_settings, b = validate_and_write(configuration=mock_settings, output_file = outfile, strip_credentials=True)
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
            sys.exit(1)
        
        credentials_needed = False
        credential_error = False
        
        
        
        if settings['splunkbase_username'] == None or settings['splunkbase_password'] == None:

            missing_credentials = []
            if settings['splunkbase_username'] == None:
                missing_credentials.append("--splunkbase_username")
            if settings['splunkbase_password'] == None:
                missing_credentials.append("--splunkbase_password")
            
            missing_credentials_string = '\n\t'.join(missing_credentials)
            
            splunkbase_only_apps = []
            for app,content in settings['apps'].items():
                if 'local_path' not in content and 'http_path' not in content:
                    splunkbase_only_apps.append(app)
            if len(splunkbase_only_apps) != 0:
                print(f"Error - you have attempted to install the following apps: {splunkbase_only_apps}, "
                     "but you have not provided a local_path or an http_path in the config file.  Normally, "
                     "we would download these from Splunkbase, but the following credentials are "
                     f"missing:\n\t{missing_credentials_string}\n  Please provide them on the command line "
                     "or in the config file.\n\tQuitting...")
                sys.exit(1)

            print(f"You have listed apps to install but have "\
                  f"not provided\n\t{missing_credentials_string} \nvia the command line or config file. "
                  f"We will download these files from S3 rather than Splunkbase.")
        else:

            print(f"You have listed apps to install and provided Splunkbase credentials. "\
                  f"These apps will be downloaded and installed from Splunkbase!")

        

    
    FULL_DOCKER_HUB_CONTAINER_NAME = "splunk/splunk:%s" % settings['container_tag']

    if settings['num_containers'] > MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING:
        print("You requested to run with [%d] containers which may use a very large amount of resources "
              "as they all run in parallel.  The maximum suggested number of parallel containers is "
              "[%d].  We will do what you asked, but be warned!" % (settings['num_containers'], MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING))

    # Check out security content if required
    try:
        #Make sure we fix up the persist_securiy_content argument if it is passed in error (we say it exists but it doesn't)
        github_service, settings['persist_security_content'] = ensure_security_content(
            settings['branch'], settings['commit_hash'], settings['pr_number'], settings['persist_security_content'])
        settings['commit_hash'] = github_service.commit_hash
    except Exception as e:
        print("\nFailure checking out git repository: [%s]"\
              "\n\tCommit Hash: [%s]"\
              "\n\tBranch     : [%s]"\
              "\n\tPR         : [%s]\n\tQuitting..."%
              (str(e),settings['commit_hash'],settings['branch'],settings['pr_number']),file=sys.stderr)
        sys.exit(1)

    #passes = [{'search_string': '| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name ="7z.exe" OR Processes.process_name = "7za.exe" OR Processes.original_file_name = "7z.exe" OR Processes.original_file_name =  "7za.exe") AND (Processes.process="*\\\\C$\\\\*" OR Processes.process="*\\\\Admin$\\\\*" OR Processes.process="*\\\\IPC$\\\\*") by Processes.original_file_name Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.parent_process_id Processes.process_id  Processes.dest Processes.user | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | `7zip_commandline_to_smb_share_path_filter` | stats count | where count > 0', 'detection_name': '7zip CommandLine To SMB Share Path', 'detection_file': 'endpoint/7zip_commandline_to_smb_share_path.yml', 'success': True, 'error': False, 'diskUsage': '286720', 'runDuration': '0.922', 'scanCount': '4897'}]
    #github_service.update_and_commit_passed_tests(passes)
    #sys.exit(0)
    # Make a backup of this config containing the hash and stripped credentials.
    # This makes the test perfectly reproducible.
    reproduce_test_config, _ = validate_args.validate_and_write(settings, output_file=None, strip_credentials=True)
    if reproduce_test_config == None:
        print("Error - there was an error writing out the file to reproduce the test.  This should not happen, as all "\
              "settings should have been validated by this point.\n\tQuitting...",file=sys.stderr)
        sys.exit(1)

    try:
        all_test_files = github_service.get_test_files(settings['mode'],
                                                    settings['folders'],
                                                    settings['types'],
                                                    settings['detections_list'])
        
        #We randomly shuffle this because there are likely patterns in searches.  For example,
        #cloud/endpoint/network likely have different impacts on the system.  By shuffling,
        #we spread out this load on a single computer, but also spread it in case
        #we are running on GitHub Actions against multiple machines.  Hopefully, this
        #will reduce that chnaces the some machines run and complete quickly while
        #others take a long time.
        random.shuffle(all_test_files)        

    except Exception as e:
        print("Error getting test files:\n%s"%(str(e)), file=sys.stderr)
        print("\tQuitting...", file=sys.stderr)
        sys.exit(1)

    print("***This run will test [%d] detections!***"%(len(all_test_files)))
    

    


    # Check to see if we want to install ESCU and whether it was preeviously generated and we should use that file
    if ES_APP_NAME in settings['apps'] and settings['apps'][ES_APP_NAME]['local_path'] is not None:
        # Using a pregenerated ESCU, no need to build it
        pass

    elif ES_APP_NAME not in settings['apps']:
        print(f"{ES_APP_NAME} was not found in {settings['apps'].keys()}.  We assume this is an error and shut down.\n\t"
              "Quitting...", file=sys.stderr)
        sys.exit(1)
    else:
        # Generate the ESCU package from this branch.
        source_path = generate_escu_app(settings['persist_security_content'])
        settings['apps']['SPLUNK_ES_CONTENT_UPDATE']['local_path'] = source_path
        

    # Copy all the apps, to include ESCU (whether pregenerated or just generated)
    try:
        relative_app_path = copy_local_apps_to_directory(settings['apps'], 
                                     splunkbase_username = settings['splunkbase_username'], 
                                     splunkbase_password = settings['splunkbase_password'], 
                                     mock=settings['mock'], target_directory = CONTAINER_APP_DIRECTORY)
        
        mounts = [{"local_path": os.path.abspath(relative_app_path),
                    "container_path": "/tmp/apps", "type": "bind", "read_only": True}]
    except Exception as e:
        print(f"Error occurred when copying apps to app folder: [{str(e)}]\n\tQuitting...", file=sys.stderr)
        sys.exit(1)


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
    files_to_copy_to_container["AUTHORIZATIONS"] = {
        "local_file_path": authorizations_file_local_path, "container_file_path": authorizations_file_container_path}
    

    
    def shutdown_signal_handler_setup(sig, frame):
        
        print(f"Signal {sig} received... stopping all [{settings['num_containers']}] containers and shutting down...")
        shutdown_client = docker.client.from_env()
        errorCount = 0
        for container_number in range(settings['num_containers']):
            container_name = settings['local_base_container_name']%container_number
            print(f"Shutting down {container_name}...", file=sys.stderr, end='')
            sys.stdout.flush()
            try:
                container = shutdown_client.containers.get(container_name)
                #Note that stopping does not remove any of the volumes or logs,
                #so stopping can be useful if we want to debug any container failure 
                container.stop(timeout=10)
                print("done", file=sys.stderr)
            except Exception as e:
                print(f"Error trying to shut down {container_name}. It may have already shut down.  Stop it youself with 'docker containter stop {container_name}", sys.stderr)
                errorCount += 1
        if errorCount == 0:
            print("All containers shut down successfully", file=sys.stderr)        
        else:
            print(f"{errorCount} containers may still be running. Find out what is running with:\n\t'docker container ls'\nand shut them down with\n\t'docker container stop CONTAINER_NAME' ", file=sys.stderr)
        
        print("Quitting...",file=sys.stderr)
        #We must use os._exit(1) because sys.exit(1) actually generates an exception which can be caught! And then we don't Quit!
        os._exit(1)
        

            

    #Setup requires a different teardown handler than during execution
    signal.signal(signal.SIGINT, shutdown_signal_handler_setup)

    try:
        cm = container_manager.ContainerManager(all_test_files,
                                                FULL_DOCKER_HUB_CONTAINER_NAME,
                                                settings['local_base_container_name'],
                                                settings['num_containers'],
                                                settings['apps'],
                                                settings['branch'],
                                                settings['commit_hash'],
                                                reproduce_test_config,
                                                files_to_copy_to_container=files_to_copy_to_container,
                                                web_port_start=8000,
                                                management_port_start=8089,
                                                mounts=mounts,
                                                show_container_password=settings['show_splunk_app_password'],
                                                container_password=settings['splunk_app_password'],
                                                splunkbase_username=settings['splunkbase_username'],
                                                splunkbase_password=settings['splunkbase_password'],
                                                reuse_image=settings['reuse_image'],
                                                interactive_failure=not settings['no_interactive_failure'],
                                                interactive=settings['interactive'])
    except Exception as e:
        print("Error - unrecoverable error trying to set up the containers: [%s].\n\tQuitting..."%(str(e)),file=sys.stderr)
        sys.exit(1)

    def shutdown_signal_handler_execution(sig, frame):
        #Set that a container has failed which will gracefully stop the other containers.
        #This way we get our full cleanup routine, too!
        print("Got a signal to shut down. Shutting down all containers, please wait...", file=sys.stderr)
        cm.synchronization_object.containerFailure()
    
    #Update the signal handler

    signal.signal(signal.SIGINT, shutdown_signal_handler_execution)
    try:
        result = cm.run_test()
    except Exception as e:
        print("Error - there was an error running the tests: [%s]\n\tQuitting..."%(str(e)),file=sys.stderr)
        sys.exit(1)

    #github_service.update_and_commit_passed_tests(cm.synchronization_object.successes)
    

    #Return code indicates whether testing succeeded and all tests were run.
    #It does NOT indicate that all tests passed!
    if result is True:
        print("Test Execution Successful")
        sys.exit(0)
    else:
        print("Test Execution Failed - review the logs for more details")
        #Because one or more of the threads could be stuck in a certain setup loop, like
        #trying to copy files to a containers (which igonores errors), we must os._exit
        #instead of sys.exit
        os._exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])

