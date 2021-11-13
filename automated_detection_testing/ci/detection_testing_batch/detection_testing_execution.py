import sys
import argparse
import shutil
import os
import time
import random
import secrets
import docker
import threading
import queue

from docker.client import DockerClient
from modules.github_service import GithubService
from modules import aws_service, testing_service
import time
import subprocess

from timeit import default_timer as timer
from datetime import timedelta
from datetime import datetime
import string
import shutil
from typing import Union
from collections import OrderedDict
from tempfile import mkdtemp
import csv

from requests import get
import json

SPLUNK_CONTAINER_APPS_DIR = "/opt/splunk/etc/apps"
index_file_local_path = "indexes.conf.tar"
index_file_container_path = os.path.join(SPLUNK_CONTAINER_APPS_DIR, "search")

datamodel_file_local_path = "datamodels.conf.tar"
datamodel_file_container_path = os.path.join(SPLUNK_CONTAINER_APPS_DIR, "Splunk_SA_CIM")



MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING=2
DEFAULT_CONTAINER_TAG="latest"
LOCAL_BASE_CONTAINER_NAME = "splunk_test_%d"



BASE_CONTAINER_WEB_PORT=8000
BASE_CONTAINER_MANAGEMENT_PORT=8089


DETECTION_TYPES = ['endpoint', 'cloud', 'network']
DETECTION_MODES = ['new', 'all', 'selected']




def main(args):
    
    start_time = timer()
    

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

    start_datetime = datetime.now()
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
    args = parser.parse_args()
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
    if splunk_password is None and reuse_containers is True:
        print("Error - if you are going to reuse a container you MUST provide the password to it!")
        sys.exit(1)
    '''
    if splunk_password is None:
        #Generate a sufficiently complex password 
        splunk_password = get_random_password()
        if show_password is True:
            print("Generated the password: [%s]"%splunk_password)
    else:
        print("Since you supplied a password, we will not generate one for you.")
    

    persist_security_content = args.persist_security_content
    #Read in all of the tests that we will ignore because they already passed
    success_tests = []
    if success_file is not None:
        try:
            with open(success_file, "r") as successes:
                for line in successes.readlines():
                    file_path_new = os.path.join("tests", os.path.splitext(line)[0]) + ".test.yml"
                    success_tests.append(file_path_new)
        except Exception as e:
            print("Error - error reading success_file: [%s]"%(str(e)))
            print("\n\tQuitting...")
            sys.exit(1)
                

    

    #Ensure that a valid mode was chosen 
    mode = args.mode
    if mode == "selected" and args.test_files_list is None and args.test_files_file is None:
        print("Error - mode [%s] but did not provide any files to test.\nQuitting..."%(mode))
        sys.exit(1)
    elif mode == "selected" and args.test_files_list is not None and args.test_files_file is not None:
        print("Error - mode [%s] but you specified a list of detections to test AND a file of detections to test.\nQuitting..."%(mode))
        sys.exit(1)
    elif mode == "selected" and args.test_files_list is not None:
        command_line_files_to_test = [name.strip() for name in args.test_files_list.split(',')]
    elif mode == "selected" and args.test_files_file is not None:
        lines = args.test_files_file.readlines()
        command_line_files_to_test = [l.strip() for l in lines]

    folders = [a.strip() for a in args.types.split(',')]
    for t in folders:
        if t not in DETECTION_TYPES:
            print("Error - requested test of [%s] but the only valid types are %s.\tQuitting..."%(t, str(DETECTION_TYPES)))
            sys.exit(1)
    


    

    #Do some initial setup and validation of the containers and images  

    #If a user requests to use existing containers, they must also explicitly request to reuse existing images
    '''
    if reuse_containers and not reuse_image:
        print("Error - requested --reuse_containers but did not explicitly request --reuse_image.\n\tQuitting")
        sys.exit(1)
    '''
    if num_containers < 1:
        #Perhaps this should be a mock-run - do the initial steps but don't do testing on the containers?
        print("Error, requested 0 containers.  You must run with at least 1 container.")
        sys.exit(1)
    elif num_containers > MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING:
        print("You requested to run with [%d] containers which may use a very large amount of resources "
               "as they all run in parallel.  The maximum suggested number of parallel containers is "
               "[%d].  We will do what you asked, but be warned!"%(num_containers, MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING))

    client = docker.client.from_env()

    #Ensure that the images and containers are set up in a proper state

    #Remove containers that previously existed (if we are directed to do so)
    try:
        remove_existing_containers(client, False, LOCAL_BASE_CONTAINER_NAME, num_containers)
    except Exception as e:
        print("Error tryting to remove existing containers.\n\tQuitting...")
        sys.exit(1)

    #Download and setup the image
    try:
        setup_image(client, reuse_image, full_docker_hub_container_name)
    except Exception as e:
        print("Error trying to set up the image.\n\tQuitting...")
        sys.exit(1)
    

    




    
    

    if persist_security_content is True and os.path.exists("security_content"):
        print("******You chose --persist_security_content and the security_content directory exists. We will not check out the repo again. Please be aware, this could cause issues if you're out of date.******")
        github_service = GithubService(branch, existing_directory=persist_security_content)

    elif persist_security_content is True:
        print("Error - you chose --persist_security_content but the security_content directory does not exist!\n\tQuitting...")
        sys.exit(1)
    else:
        if os.path.exists("security_content/"):
            print("Deleting the security_content directory")
            try:
                shutil.rmtree("security_content/", ignore_errors=True)
                print("Successfully removed security_content directory")
            except Exception as e:
                print("Error - could not remove the security_content directory: [%s].\n\tQuitting..."%(str(e)))
                sys.exit(1)
        
        if pr_number:
            github_service = GithubService(branch, pr_number)
        else:
            github_service = GithubService(branch)
    
    try:
        if mode == "all":
            test_files = github_service.get_all_tests_and_detections(folders=folders, 
                                                                    previously_successful_tests=success_tests)
        elif mode == "new":
            test_files = github_service.get_changed_test_files(folders=folders,
                                                            previously_successful_tests=success_tests)
        elif mode == "selected":
            if set(folders) != set(DETECTION_TYPES):
                print("You specified mode [%s] but also types: [%s]. We will ignore type restrictions and test all specified files"%(mode,str(folders)))
            
            test_files = github_service.get_selected_test_files(command_line_files_to_test,
                                                            previously_successful_tests=success_tests)

        else:
            print("Unsupported mode [%s] chosen.  Supported modes are %s.\n\tQuitting..."%(args.mode, str(DETECTION_MODES)))
            sys.exit(1)
    except Exception as e:
        print("Error - Failed to read in detection files: [%s].\nQuitting..."%(str(e)))    
        sys.exit(1)
    
    if len(test_files) == 0:
        print("No files were found to be tested.  Returning an error (should this return success?).\n\tQuitting...")
        sys.exit(1)
    
    local_volume_path = os.path.join(os.getcwd(), "apps")
    try:
        os.mkdir("apps")
    except FileExistsError as e:
        #Directory already exists, do nothing
        pass
    except Exception as e:
        print("Caught an error when copying the ESCU package [%s] to the apps folder [%s].\n\tQuitting..."%(pregenerated_escu_package.name, local_volume_path))
        sys.exit(1)

    if pregenerated_escu_package is None:
        #Go into the security content directory
        print("****GENERATE NEW CONTENT****")
        os.chdir("security_content")
        print(os.getcwd())
        if persist_security_content is False:
            commands = ["python3 -m venv .venv", 
                        ". ./.venv/bin/activate", 
                        "python3 -m pip install wheel", 
                        "python3 -m pip install -r requirements.txt", 
                        "python3 contentctl.py --path . --verbose generate --product ESCU --output dist/escu", "tar -czf DA-ESS-ContentUpdate.spl -C dist/escu ."]
        else:
            commands = ["s. ./.venv/bin/activate", "python3 contentctl.py --path . --verbose generate --product ESCU --output dist/escu", "tar -czf DA-ESS-ContentUpdate.spl -C dist/escu ."]
        ret = subprocess.run("; ".join(commands), shell=True, capture_output=True)
        if ret.returncode != 0:
            print("Error generating new content.  Exiting...")
            sys.exit(1)
        print("New content generated successfully")    
        

        print("Generate new ESCU Package using new content")
        if persist_security_content is True:
            os.chdir("slim_packaging")
            commands = ["cd slim-latest", 
                        ". ./.venv/bin/activate",
                        "cp -R ../../dist/escu DA-ESS-ContentUpdate",
                        "slim package -o upload DA-ESS-ContentUpdate",
                         "cp upload/DA-ESS-ContentUpdate*.tar.gz %s"%(os.path.join(local_volume_path, "DA-ESS-ContentUpdate-latest.tar.gz" ))]
        
        else:
            os.mkdir("slim_packaging")
            os.chdir("slim_packaging")
            os.mkdir("apps")
            
            try:
                SPLUNK_PACKAGING_TOOLKIT_URL = "https://download.splunk.com/misc/packaging-toolkit/splunk-packaging-toolkit-0.9.0.tar.gz"
                SPLUNK_PACKAGING_TOOLKIT_FILENAME = 'splunk-packaging-toolkit-latest.tar.gz'
                print("Downloading the Splunk Packaging Toolkit from %s..."%(SPLUNK_PACKAGING_TOOLKIT_URL), end='')
                response = get(SPLUNK_PACKAGING_TOOLKIT_URL)
                response.raise_for_status()
                with open(SPLUNK_PACKAGING_TOOLKIT_FILENAME, 'wb') as slim_file:
                    slim_file.write(response.content)
                
                print("success")


            except Exception as e:
                print("FAILED")
                print("Error downloading the Splunk Packaging Toolkit: [%s]"%(str(e)))
                sys.exit(1)
            
            
            commands = ["rm -rf slim-latest",
                        "mkdir slim-latest", 
                        "tar -zxf splunk-packaging-toolkit-latest.tar.gz -C slim-latest --strip-components=1",
                        "cd slim-latest", 
                        "virtualenv --python=/usr/bin/python2.7 --clear .venv",
                        ". ./.venv/bin/activate",
                        "python3 -m pip install --upgrade pip",
                        "python2 -m pip install wheel",
                        "python2 -m pip install semantic_version",
                        "python2 -m pip install .",
                        "cp -R ../../dist/escu DA-ESS-ContentUpdate",
                        "slim package -o upload DA-ESS-ContentUpdate",
                        "cp upload/DA-ESS-ContentUpdate*.tar.gz %s"%(os.path.join(local_volume_path, "DA-ESS-ContentUpdate-latest.tar.gz" ))]
            
        
        

        ret = subprocess.run("; ".join(commands), shell=True, capture_output=True)
        if ret.returncode != 0:
            print("Error generating new ESCU Package.\n\tQuitting..."%())
            sys.exit(1)
        os.chdir("../..")
        print("New ESCU Package generated successfully")
    else:
        print("Using previous generated ESCU package: [%s]"%(pregenerated_escu_package.name))    
        try:
            with open(os.path.join(local_volume_path, os.path.basename(pregenerated_escu_package.name)),'wb') as escu_package:
                escu_package.write(pregenerated_escu_package.read())
        except Exception as e:
            print("Failure writing the ESCU package [%s] to [%s]: [%s].\n\tQuitting..."%(pregenerated_escu_package.name, local_volume_path, str(e)))
            sys.exit(1)
        
    
    print("Wrote ESCU package to volume.")
        
    
    
    if args.split_detections_then_stop:
        for output_file_index in range(0,num_containers):
            fname = "container_%d_tests.txt"%(output_file_index)
            print("Writing tests to [%s]..."%(fname), end='')
            with open(fname, "w") as output_file:
                detection_tests = test_files[output_file_index::num_containers]
                normalized_detection_names = []
                for d in detection_tests:
                    filename = os.path.basename(d)
                    filename = filename.replace(".test.yml", ".yml")
                    leading = os.path.split(d)[0]
                    leading = leading.replace("tests/", "detections/")
                    new_name = os.path.join("security_content", leading, filename)
                    normalized_detection_names.append(new_name)
                output_file.write('\n'.join(normalized_detection_names))
            print("Done")
        sys.exit(0)




    
    
    #Create threads to manage all of the containers that we will start up
    splunk_container_manager_threads = []
    

    
    


    results_tracker = SynchronizedResultsTracker(test_files, num_containers)
    
    

          
    
    #SPLUNK_ADD_ON_FOR_SYSMON_OLD = "https://splunkbase.splunk.com/app/1914/release/10.6.2/download"
    #SPLUNK_ADD_ON_FOR_SYSMON_NEW = "https://splunkbase.splunk.com/app/5709/release/1.0.1/download"
    #SYSMON_APP_FOR_SPLUNK = "https://splunkbase.splunk.com/app/3544/release/2.0.0/download"
    #SPLUNK_ES_CONTENT_UPDATE = "https://splunkbase.splunk.com/app/3449/release/3.29.0/download"

    #Just a hack until we get the new version of system deployed and available from splunkbase
    CONTAINER_VOLUME_PATH = '/tmp/apps/'
    
    GENERATED_SPLUNK_ES_CONTENT_UPDATE_CONTAINER_PATH = os.path.join(CONTAINER_VOLUME_PATH, "DA-ESS-ContentUpdate-latest.tar.gz")

    SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/%d/release/%s/download"
    #Order that we install the apps is actually important
    APPS_DICT = OrderedDict()
    APPS_DICT['SPLUNK_ADD_ON_FOR_MICROSOFT_WINDOWS'] = {"app_number":742, 'app_version':"8.2.0", 'location':'splunkbase'}
    APPS_DICT['SPLUNK_SECURITY_ESSENTIALS'] = {"app_number":3435, 'app_version':"3.3.4", 'location':'splunkbase'}
    APPS_DICT['GENERATED_SPLUNK_ES_CONTENT_UPDATE'] = {"app_number":3449, 'app_version':"Generated at %s"%(datetime.now()), 'location':GENERATED_SPLUNK_ES_CONTENT_UPDATE_CONTAINER_PATH}
    
    
    try:
        BETA_SPLUNK_ADD_ON_FOR_SYSMON_PATH  = os.path.expanduser("~/Downloads/Splunk_TA_microsoft_sysmon-1.0.2-B1.spl")    
        shutil.copyfile(BETA_SPLUNK_ADD_ON_FOR_SYSMON_PATH, os.path.join(local_volume_path, "Splunk_TA_microsoft_sysmon-1.0.2-B1.spl"))
    
        BETA_SPLUNK_ADD_ON_FOR_SYSMON_CONTAINER_PATH  = "/tmp/apps/Splunk_TA_microsoft_sysmon-1.0.2-B1.spl"
        APPS_DICT['BETA_SPLUNK_ADD_ON_FOR_SYSMON'] = {"app_number":5709, 'app_version':"Generated at %s"%(datetime.now()), 'location':BETA_SPLUNK_ADD_ON_FOR_SYSMON_CONTAINER_PATH}
    except Exception as e:
        print("Failed to grab beta sysmon at ~/Downloads/Splunk_TA_microsoft_sysmon-1.0.2-B1.spl. Using the one from Splunkbase")
        APPS_DICT['SPLUNK_ADD_ON_FOR_SYSMON'] = {"app_number":5709, 'app_version':"1.0.1", 'location':'splunkbase'}
    
    if True:
        APPS_DICT['SPLUNK_ADD_ON_FOR_AMAZON_WEB_SERVICES'] = {"app_number":1876, 'app_version':"5.2.0", 'location':'splunkbase'}
        APPS_DICT['SPLUNK_ADD_ON_FOR_MICROSOFT_OFFICE_365'] = {"app_number":4055, 'app_version':"2.2.0", 'location':'splunkbase'}
        APPS_DICT['SPLUNK_ADD_ON_FOR_AMAZON_KINESIS_FIREHOSE'] = {"app_number":3719, 'app_version':"1.3.2", 'location':'splunkbase'}
        APPS_DICT['SPLUNK_ANALYTIC_STORY_EXECUTION_APP'] = {"app_number":4971, 'app_version': "2.0.3", 'location':'splunkbase'}
        APPS_DICT['PYTHON_FOR_SCIENTIC_COMPUTING_LINUX_64_BIT'] = {"app_number":2882, 'app_version':"2.0.2", 'location':'splunkbase'}
        APPS_DICT['SPLUNK_MACHINE_LEARNING_TOOLKIT'] = {"app_number":2890, 'app_version':"5.2.2", 'location':'splunkbase'}
        APPS_DICT['SPLUNK_APP_FOR_STREAM'] = {"app_number":1809, 'app_version':"8.0.1", 'location':'splunkbase'}
        APPS_DICT['SPLUNK_ADD_ON_FOR_STREAM_WIRE_DATA'] = {"app_number":5234, 'app_version':"8.0.1", 'location':'splunkbase'}
        APPS_DICT['SPLUNK_ADD_ON_FOR_STREAM_FORWARDERS'] = {"app_number":5238, 'app_version':"8.0.1", 'location':'splunkbase'}
        APPS_DICT['SPLUNK_ADD_ON_FOR_ZEEK_AKA_BRO'] = {"app_number":1617, 'app_version':"4.0.0", 'location':'splunkbase'}
        APPS_DICT['SPLUNK_ADD_ON_FOR_UNIX_AND_LINUX'] = {"app_number":833, 'app_version':"8.3.1", 'location':'splunkbase'}
    

    #CIM is last here for a reason!  Because we copy a file to a directory that does not exist until CIM
    #has been installed, we use it to prevent the testing from beginning until the copy has succeeded.  
    #KEEP THIS APP LAST!
    APPS_DICT['SPLUNK_COMMON_INFORMATION_MODEL'] = {"app_number":1621, 'app_version':"4.20.2", 'location':'splunkbase'}
    
    

    
    SPLUNK_APPS = []
    for key, value in APPS_DICT.items():
        if value['location'] == 'splunkbase':
            #The app is on Splunkbase
            target=SPLUNKBASE_URL%(value['app_number'],value['app_version'])
            SPLUNK_APPS.append(target)
        else:
            #The app is a file we generated locally
            SPLUNK_APPS.append(value['location'])
    


    for container_index in range(num_containers):
        container_name = LOCAL_BASE_CONTAINER_NAME%container_index
        
        web_port = BASE_CONTAINER_WEB_PORT  + container_index
        management_port = BASE_CONTAINER_MANAGEMENT_PORT + container_index

        
        

        environment = {"SPLUNK_START_ARGS": "--accept-license",
                        "SPLUNK_PASSWORD"  : splunk_password, 
                        "SPLUNK_APPS_URL"   : ','.join(SPLUNK_APPS),
                        "SPLUNKBASE_USERNAME" : splunkbase_username,
                        "SPLUNKBASE_PASSWORD" : splunkbase_password
                        }
        ports= {"8000/tcp": web_port,
                "8089/tcp": management_port
               }
        
        
        

        
        mounts = [docker.types.Mount(target = CONTAINER_VOLUME_PATH, source = local_volume_path, type='bind', read_only=True)]
        
        print("Creating CONTAINER: [%s]"%(container_name))
        base_container = client.containers.create(full_docker_hub_container_name, ports=ports, environment=environment, name=container_name, mounts=mounts, detach=True)
        print("Created CONTAINER : [%s]"%(container_name))
        

        
        
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

    #add the queue status thread - there can be some error in one of the test threads, so this
    #thread doesn't need to complete for the program to finish execution
    status_thread = threading.Thread(target=queue_status_thread, 
                                     args=(results_tracker,), 
                                           daemon=True)
    #Start this thread immediately
    status_thread.start()


    print("Start the testing threads")
    for t in splunk_container_manager_threads:
        t.start()
        #we need to start containers slowly.  Would be great it we could do all the setup and
        #app install once, but it looks like the container is unlikely to support that.
        #We don't really want to fundamentally change this container, either, and will 
        #keep it as close to production as possible
        time.sleep(5)
    
    #Wait for all of the testing threads to complete
    for t in splunk_container_manager_threads:
        t.join() #blocks on waiting to join
        print("Testing thread completed execution")

    print("All testing threads have completed execution")
    #read all the results out from the output queue
    strtime = str(int(time.time()))

    print("Wait for the status thread to finish executing...")
    status_thread.join()
    print("Status thread finished executing.")

    
    #Remove the attack data and 
    #generate all of the output information
    stop_time = timer()
    stop_datetime = datetime.now()
    baseline = OrderedDict()
    baseline['SPLUNK_VERSION'] = full_docker_hub_container_name
    baseline['SPLUNK_APPS'] = APPS_DICT
    baseline['TEST_START_TIME'] = str(start_datetime)
    baseline['TEST_FINISH_TIME'] = str(stop_datetime)

    results_tracker.finish(baseline)
    
    

    #now we are done!
    
    print("Total Execution Time: [%s]"%(timedelta(seconds=stop_time - start_time, microseconds=0)))
    

    #detection testing service has already been prepared, no need to do it here!
    #testing_service.prepare_detection_testing(ssh_key_name, private_key, splunk_ip, splunk_password)

    #testing_service.test_detections(ssh_key_name, private_key, splunk_ip, splunk_password, test_files, uuid_test)
    




        




            
if __name__ == "__main__":
    main(sys.argv[1:])





