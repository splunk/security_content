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
from typing import OrderedDict, Union

from tempfile import mkdtemp
import csv
from urllib.request import urlretrieve 
SPLUNK_CONTAINER_APPS_DIR = "/opt/splunk/etc/apps"
index_file_local_path = "indexes.conf.tar"
index_file_container_path = os.path.join(SPLUNK_CONTAINER_APPS_DIR, "search")

datamodel_file_local_path = "datamodels.conf.tar"
datamodel_file_container_path = os.path.join(SPLUNK_CONTAINER_APPS_DIR, "Splunk_SA_CIM")


PASSWORD_LENGTH=20
MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING=2
DEFAULT_CONTAINER_TAG="latest"
LOCAL_BASE_CONTAINER_NAME = "splunk_test_%d"



BASE_CONTAINER_WEB_PORT=8000
BASE_CONTAINER_MANAGEMENT_PORT=8089


DETECTION_TYPES = ['endpoint', 'cloud', 'network']
DETECTION_MODES = ['new', 'all', 'selected']


#taken from attack_range
def get_random_password()->str:
    random_source = string.ascii_letters + string.digits
    password = random.choice(string.ascii_lowercase)
    password += random.choice(string.ascii_uppercase)
    password += random.choice(string.digits)

    
    for i in range(random.randrange(16,26)):
        password += random.choice(random_source)

    password_list = list(password)
    random.SystemRandom().shuffle(password_list)
    password = ''.join(password_list)
    return password


def wait_for_splunk_ready(splunk_container_name=None, splunk_web_port=None, max_seconds=30):
    #The smarter version of this will try to hit one of the pages,
    #probably the login page, and when that is available it means that
    #splunk is fully started and ready to go.  Until then, we just
    #use a simple sleep
    time.sleep(max_seconds)





        


def setup_image(client: DockerClient, reuse_images: bool, container_name: str) -> None:
    if not reuse_images:
        #Check to see if the image exists.  If it does, then remove it.  If it does not, then do nothing
        docker_image = None
        try:
            docker_image = client.images.get(container_name)
        except Exception as e:
            #We don't need to do anything, the image did not exist on our system
            print("Image named [%s] did not exist, so we don't need to try and remove it."%(container_name))
        if docker_image != None:
            #We found the image.  Let's try to delete it
            print("Found docker image named [%s] and you have requested that we forcefully remove it"%(container_name))
            try:
                client.images.remove(image=container_name, force=True, noprune=False)
                print("Docker image named [%s] forcefully removed"%(container_name))
            except Exception as e:
                print("Error forcefully removing [%s]"%(container_name))
                raise(e)
    
    #See if the image exists.  If it doesn't, then pull it from Docker Hub
    docker_image = None
    try:
        docker_image = client.images.get(container_name)
        print("Docker image [%s] found, no need to download it."%(container_name))
    except Exception as e:
        #Image did not exist on the system
        docker_image = None

    if docker_image is None:
        #We did not find the image, so pull it
        try:
            print("Downloading image [%s].  Please note "
                 "that this could take a long time depending on your "
                 "connection. It's around 2GB."%(container_name))
            pull_start_time = timer()
            client.images.pull(container_name)
            pull_finish_time = timer()
            print("Successfully pulled the docker image [%s] in %ss"%
                  (container_name,
                  timedelta(seconds=pull_finish_time - pull_start_time, microseconds=0) ))

        except Exception as e:
            print("There was an error trying to pull the image [%s]: [%s]"%(container_name,str(e)))
            raise(e)

def remove_existing_containers(client: DockerClient, reuse_containers: bool, container_template: str, num_containers: int, forceRemove: bool=True) -> bool:
    if reuse_containers is True:
        #Check to make sure that all of the requested containers exist
        for index in range(0, num_containers):
            container_name = container_template%(index)
            print("Checking for the existence of container named [%s]"%(container_name))
            try:
                this_container = client.containers.get(container_name)
            except Exception as e:
                print("Failed to find a container named [%s]"%(container_name))
                reuse_containers = False
                break
            try:
                #Make sure that the container is stopped
                print("Found [%s]. Stopping container..."%(container_name))
                this_container.stop()
            except Exception as e:
                print("Failed to stop a container named [%s]"%(container_name))
                reuse_containers = False
                break
        print("Found all of the containers, we will reuse them")
        return True
    
    #Note that this variable can be changed by the block above, so don't
    #convert this into an if/else. Note that this IF is for verbosity:

    if reuse_containers is False:
        for index in range(0,num_containers):
            container_name = container_template%(index)
            removeContainer(client, container_name, forceRemove)
        return False
    else:
        raise(Exception("Error removing existing containers"))

def removeContainer(client: DockerClient, container_name:str, forceRemove:bool=True)->bool:
    print("Trying to remove container [%s]"%(container_name))
    try:
        container = client.containers.get(container_name)
    except Exception as e:
        print("Could not find Docker Container [%s]. Container does not exist, so no need to remove it"%(container_name))
        return True
    try:
        #container was found, so now we try to remove it
        #v also removes volumes linked to the container
        container.remove(v=True, force=forceRemove) #remove it even if it is running. remove volumes as well
        print("Successfully removed Docker Container [%s]"%(container_name))
        return True
    except Exception as e:
        print("Could not remove Docker Container [%s]"%(container_name))
        raise(Exception("CONTAINER REMOVE ERROR"))



        

    

    


def main(args):
    
    start_time = timer()
    

    parser = argparse.ArgumentParser(description="CI Detection Testing")
    parser.add_argument("-b", "--branch", type=str, required=True, help="security content branch")
    parser.add_argument("-u", "--uuid", type=str, required=True, help="uuid for detection test")
    parser.add_argument("-pr", "--pr-number", type=int, required=False, help="Pull Request Number")
    parser.add_argument("-n", "--num_containers", required=False, type=int, default=1, help="The number of splunk docker containers to start and run for testing")
    
    parser.add_argument("-cw", "--container_password", required=False, help="A password to use for the container.  If you don't choose one, a complex one will be generated for you.")
    parser.add_argument("-show", "--show_password", required=False, default=False, action='store_true', help="Show the generated password to use to login to splunk.  For an CI/CD run, you probably don't want this.")
    parser.add_argument("-i", "--interactive_failure", required=False, default=False, action='store_true', help="If a test fails, should we pause before removing data so that the search can be debugged?")

    parser.add_argument("-ri", "--reuse_image", required=False, default=False, action='store_true', help="Should existing images be re-used, or should they be redownloaded?")
    
    #Allowing us to reuse containers is more trouble than it's worth (we may have rebuilt an app or, more likely, ESCU) and it is a pain to re-upload that
    #instead of having the container restart and download/install itself.
    #parser.add_argument("-rc", "--reuse_containers", required=False, default=False,  help="Should existing containers be re-used, or should they be rebuilt?")

    parser.add_argument("-s", "--success_file", type=str, required=False, help="File that contains previously successful runs that we don't need to test")
    parser.add_argument("-user", "--splunkbase_username", type=str, required=False, help="Splunkbase username for downloading Splunkbase apps")
    parser.add_argument("-pw", "--splunkbase_password", type=str, required=False, help="Splunkbase password for downloading Splunkbase apps")
    parser.add_argument("-m", "--mode", type=str, choices=DETECTION_MODES, required=False, help="Whether to test new detections, specific detections, or all detections", default="new")
    parser.add_argument("-tf","--test_files", type=str, required=False, help="The names of files that you want to test, separated by commas.")

    parser.add_argument("-t", "--types", type=str, required=False, help="Detection types to test. Can be one of more of %s"%(str(DETECTION_TYPES)), default=DETECTION_TYPES)
    parser.add_argument("-ct", "--container_tag", type=str, required=False, help="The tag of the Splunk Container to use.  Tags are located at https://hub.docker.com/r/splunk/splunk/tags",default=DEFAULT_CONTAINER_TAG)
    parser.add_argument("-p", "--persist_security_content", required=False, default=False, action="store_true", help="Assumes security_content directory already exists.  Don't check it out and overwrite it again.  Saves "\
                                                                                                                     "time and allows you to test a detection that you've updated.  Runs generate again in case you have "\
                                                                                                                     "updated macros or anything else.  Especially useful for quick, local, iterative testing.")
    start_datetime = datetime.now()
    
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
    interactive_failure = args.interactive_failure
    show_password = args.show_password
    splunk_password = args.container_password
    
    
    
        
    
        
    
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
    if mode == "selected" and args.test_files == None:
        print("Error - mode [%s] but did not provide any files to test.\nQuitting..."%(mode))
    

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
            files_to_test = [name.strip() for name in args.test_files.split(',')]
            test_files = github_service.get_selected_test_files(files_to_test,
                                                            previously_successful_tests=success_tests)

        else:
            print("Unsupported mode [%s] chosen.  Supported modes are %s.\n\tQuitting..."%(args.mode, str(DETECTION_MODES)))
            sys.exit(1)
    except Exception as e:
        print("Error - Failed to read in detection files: [%s].\nQuitting..."%(str(e)))    
        sys.exit(1)
    
    
    
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
        commands = ["source .venv/bin/activate", "python3 contentctl.py --path . --verbose generate --product ESCU --output dist/escu", "tar -czf DA-ESS-ContentUpdate.spl -C dist/escu ."]
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
                    "cp upload/DA-ESS-ContentUpdate*.tar.gz ../apps/DA-ESS-ContentUpdate-latest.tar.gz"]
    
    else:
        os.mkdir("slim_packaging")
        os.chdir("slim_packaging")
        os.mkdir("apps")
        
        try:
            SPLUNK_PACKAGING_TOOLKIT_URL = "https://download.splunk.com/misc/packaging-toolkit/splunk-packaging-toolkit-0.9.0.tar.gz"
            print("Downloading the Splunk Packaging Toolkit from %s..."%(SPLUNK_PACKAGING_TOOLKIT_URL), end='')
            urlretrieve(SPLUNK_PACKAGING_TOOLKIT_URL, 'splunk-packaging-toolkit-latest.tar.gz')
            print("success")


        except Exception as e:
            print("FAILED")
            print("Error downloading the Splunk Packaging Toolkit: [%s]"%(str(e)))
            sys.exit(1)
        
        
        commands = ["rm -rf slim-latest",
                    "mkdir slim-latest", 
                    "tar -zxf splunk-packaging-toolkit-latest.tar.gz -C slim-latest --strip-components=1",
                    "cd slim-latest", 
                    "python3 -m venv .venv", 
                    ". ./.venv/bin/activate", 
                    "python3 -m pip install wheel", 
                    "python3 -m pip install semantic_version",
                    "python3 -m pip install .",  
                    "cp -R ../../dist/escu DA-ESS-ContentUpdate",
                    "slim package -o upload DA-ESS-ContentUpdate",
                    "cp upload/DA-ESS-ContentUpdate*.tar.gz ../apps/DA-ESS-ContentUpdate-latest.tar.gz"]
        
    
    

    ret = subprocess.run("; ".join(commands), shell=True, capture_output=False)
    if ret.returncode != 0:
        print("Error generating new ESCU Package.\n\tQuitting..."%())
        sys.exit(1)
    os.chdir("../..")
    print("New ESCU Package generated successfully")    
    
    
    


    
    
    #Create threads to manage all of the containers that we will start up
    splunk_container_manager_threads = []
    

    
    


    results_tracker = SynchronizedResultsTracker(test_files)
    
    local_volume_path = os.path.join(os.getcwd(), "security_content", "slim_packaging","apps")

    SPLUNK_COMMON_INFORMATION_MODEL = "https://splunkbase.splunk.com/app/1621/release/4.20.2/download"        
    SPLUNK_SECURITY_ESSENTIALS = "https://splunkbase.splunk.com/app/3435/release/3.3.4/download"
    #SPLUNK_ADD_ON_FOR_SYSMON_OLD = "https://splunkbase.splunk.com/app/1914/release/10.6.2/download"
    #SPLUNK_ADD_ON_FOR_SYSMON_NEW = "https://splunkbase.splunk.com/app/5709/release/1.0.1/download"
    #SYSMON_APP_FOR_SPLUNK = "https://splunkbase.splunk.com/app/3544/release/2.0.0/download"
    #SPLUNK_ES_CONTENT_UPDATE = "https://splunkbase.splunk.com/app/3449/release/3.29.0/download"

    #Just a hack until we get the new version of system deployed and available from splunkbase
    LOCAL_SPLUNK_ADD_ON_FOR_SYSMON_PATH  = os.path.expanduser("~/Downloads/Splunk_TA_microsoft_sysmon-1.0.2-B1.spl")    
    shutil.copyfile(LOCAL_SPLUNK_ADD_ON_FOR_SYSMON_PATH, os.path.join(local_volume_path, "Splunk_TA_microsoft_sysmon-1.0.2-B1.spl"))
    SPLUNK_ADD_ON_FOR_SYSMON_VOLUME_PATH  = "/tmp/apps/Splunk_TA_microsoft_sysmon-1.0.2-B1.spl"
    


    
    SPLUNK_ADD_ON_FOR_MICROSOFT_WINDOWS = "https://splunkbase.splunk.com/app/742/release/8.2.0/download"
    CONTAINER_VOLUME_PATH = '/tmp/apps/'
    CONTAINER_GENERATED_ESCU_LATEST = os.path.join(CONTAINER_VOLUME_PATH, "DA-ESS-ContentUpdate-latest.tar.gz")
    
    SPLUNK_APPS = [SPLUNK_COMMON_INFORMATION_MODEL, 
                    SPLUNK_SECURITY_ESSENTIALS, 
                    SPLUNK_ADD_ON_FOR_SYSMON_VOLUME_PATH, 
                    CONTAINER_GENERATED_ESCU_LATEST, 
                    SPLUNK_ADD_ON_FOR_MICROSOFT_WINDOWS]



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
    baseline = OrderedDict()
    baseline['SPLUNK_VERSION'] = full_docker_hub_container_name
    baseline['SPLUNK_APPS'] = ','.join(SPLUNK_APPS)
    baseline['TEST_START_TIME'] = str(start_datetime)

    results_tracker.finish(baseline)
    
    

    #now we are done!
    stop_time = timer()
    print("Total Execution Time: [%s]"%(timedelta(seconds=stop_time - start_time, microseconds=0)))
    

    #detection testing service has already been prepared, no need to do it here!
    #testing_service.prepare_detection_testing(ssh_key_name, private_key, splunk_ip, splunk_password)

    #testing_service.test_detections(ssh_key_name, private_key, splunk_ip, splunk_password, test_files, uuid_test)
    

def copy_file_to_container(localFilePath, remoteFilePath, containerName, sleepTimeSeconds=5):
    successful_copy = False
    #need to use the low level client to put a file onto a container
    apiclient = docker.APIClient()
    while not successful_copy:
        try:
            with open(localFilePath,"rb") as fileData:
                #splunk will restart a few times will installation of apps takes place so it will reload its indexes...
                apiclient.put_archive(container=containerName, path=remoteFilePath, data=fileData)
                successful_copy=True
        except Exception as e:
            #print("Failed copy of [%s] file to CONTAINER:[%s]...we will try again"%(localFilePath, containerName))
            time.sleep(10)
            successful_copy=False
    print("Successfully copied [%s] to [%s] on [%s]"%(localFilePath, remoteFilePath, containerName))


class SynchronizedResultsTracker:
    def __init__(self, num_containers:int, tests:list[str]):
        #Create the queue and enque all of the tests
        self.testing_queue = queue.Queue()
        for test in tests:
            self.testing_queue.put(test)
        
        self.total_number_of_tests = self.testing_queue.qsize()
        #Creates a lock that will be used to synchronize access to this object
        self.lock = threading.Lock()
        self.start_time = timer()
        self.failures = []
        self.successes = []
        self.errors = []
        self.container_ready_time = None
        
        #Just make a random folder to store attack data that we donwload
        self.attack_data_root_folder = mkdtemp(prefix="attack_data_", dir=os.getcwd())
        print("Attack data for this run will be stored at: [%s]"%(self.attack_data_root_folder))
        self.start_barrier = threading.Barrier(num_containers)

    def getTest(self)-> Union[str,None]:
        try:
            return self.testing_queue.get(block=False)
        except Exception as e:
            print("Testing queue empty!")
            return None
        
    def addSuccess(self, result:dict)->None:
        print("Test PASSED for detection: [%s --> %s"%(result['detection_name'], result['detection_file']))
        self.lock.acquire()
        try:
            self.successes.append(result)
        finally:
            self.lock.release()
        

    def addFailure(self, result:dict)->None:
        print("Test FAILED for detection: [%s --> %s"%(result['detection_name'], result['detection_file']))
        self.lock.acquire()
        try:
            self.failures.append(result)
        finally:
            self.lock.release()

    def addError(self, detection:dict)->None:
        self.lock.acquire()
        try:
            self.errors.append(detection)
        finally:
            self.lock.release()
    def outputResultsFile(self, field_names:list[str], output_filename:str, data:list[dict], baseline:OrderedDict)->bool:
        success = True
        print("Generating %s..."%(output_filename), end='')
        self.lock.acquire()
        
        try:                        
            with open(output_filename, 'w') as csvfile:
                header_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
                for key in baseline:
                    header_writer.writerow([key, baseline[key]])
                header_writer.writerow(['',''])
                csv_writer = csv.DictWriter(csvfile, fieldnames=field_names)
                csv_writer.writeheader()
                for row in data:
                    csv_writer.writerow(row)
            print("Done with [%d] detections"%(len(data)))

        except Exception as e:
            print("Failure writing to CSV file for [%s]:"%(output_filename, str(e)))
            success = False

        finally:
            self.lock.release()

        return success

    def outputResultsFiles(self, baseline:OrderedDict, fields:list[str]=['detection_name', 'detection_file','runDuration','diskUsage', 'search_string', 'error', 'success', 'scanCount', 'detection_error'])->bool:
        res = self.outputResultsFile(fields,"success.csv", self.successes, baseline)
        res |= self.outputResultsFile(fields, "failures.csv", self.failures, baseline)
        res |= self.outputResultsFile(fields, "errors.csv", self.errors, baseline)
        res |= self.outputResultsFile(fields, "combined.csv", self.successes + self.failures + self.errors, baseline)
        return res

    def finish(self, baseline:OrderedDict):
        self.cleanup()
        self.outputResultsFiles(baseline)
        

    def cleanup(self):
        self.lock.acquire()
        try:
            print("Removing all attack data that was downloaded during this test at: [%s]"%(self.attack_data_root_folder))
            shutil.rmtree(self.attack_data_root_folder)
            print("Successfully removed all attack data")
        finally:
            self.lock.release()
    def summarize(self)->bool:
        
        self.lock.acquire()
        
        try:
            current_time = timer()
            if self.testing_queue.qsize() == self.total_number_of_tests:
                #Testing has not started yet. We are setting up containers
                print("***********PROGRESS UPDATE***********\n"\
                      "\tWaiting for container setup: %s"%(timedelta(seconds=current_time - self.start_time)))
            else:
                if self.container_ready_time is None:
                    #This is the first status update since container setup has completed.  Get the current time.
                    #This makes our remaining time estimates better since that estimate should not involve
                    #the container setup time  
                    self.container_ready_time = current_time

                numberOfCompletedTests = len(self.successes) + len(self.failures) + len(self.errors)
                remaining_tests = self.testing_queue.qsize()         
                testsCurrentlyRunning = self.total_number_of_tests - remaining_tests - numberOfCompletedTests
                total_execution_time_seconds = current_time - self.start_time

                test_execution_time_seconds = current_time - self.container_ready_time
                
                
                if numberOfCompletedTests == 0 or test_execution_time_seconds == 0:
                    estimated_seconds_to_finish_all_tests = "UNKNOWN"
                    estimated_completion_time_seconds = "UNKNOWN"
                else:
                    average_time_per_test = test_execution_time_seconds / numberOfCompletedTests
                    #divide testsCurrentlyRunning by 2.0 because, on average, each running test will be 50% completed
                    estimated_seconds_to_finish_all_tests = average_time_per_test * (remaining_tests + testsCurrentlyRunning/2.0)
                    estimated_completion_time_seconds = timedelta(seconds=estimated_seconds_to_finish_all_tests)
                    
                

            
                print("***********PROGRESS UPDATE***********\n"\
                "\tElapsed Time               : %s\n"\
                "\tEstimated Remaining Time   : %s\n"\
                "\tTests to run               : %d\n"\
                "\tTests currently running    : %d\n"\
                "\tTests completed            : %d\n"\
                "\t\tSuccess : %d\n"\
                "\t\tFailure : %d\n"\
                "\t\tError   : %d"%(timedelta(seconds=total_execution_time_seconds), 
                                    estimated_completion_time_seconds, 
                                    remaining_tests, 
                                    testsCurrentlyRunning,
                                    numberOfCompletedTests, 
                                    len(self.successes), 
                                    len(self.failures), 
                                    len(self.errors)))
    
        except Exception as e:
            print("Error in printing execution summary: [%s]"%(str(e)))
        finally:
            self.lock.release()
        
        #Return true while there are tests remaining
        return (self.total_number_of_tests - 
                (len(self.successes) + len(self.failures) + len(self.errors)) > 0)
        
        
    def addResult(self, result:dict)->None:
        try:
            if result['detection_result']['success'] is False:
                #This is actually a failure of the detection, not an error. Naming is confusiong
                self.addFailure(result['detection_result'])
            elif result['detection_result']['success'] is True:
                self.addSuccess(result['detection_result'])
        except Exception as e:
            #Neither a success or a failure, so add the object to the failures queue
            self.addError({'detection_file':"Unknown File", "detection_error":str(result)})
        


def splunk_container_manager(testing_object:SynchronizedResultsTracker, container_name, splunk_ip, splunk_password, splunk_port, uuid_test, interactive_failure:bool=False):
    print("Starting the container [%s] after a sleep"%(container_name))
    #Is this going to be safe to use in different threads
    client = docker.client.from_env()
    
    #start up the container from the base container
    #Assume that the base container has already been fully built with
    #escu etc
    #sleep for a little bit so that we don't all start at once...
    

    container = client.containers.get(container_name)
    
    print("Starting the container [%s]"%(container_name))

    
    
    container.start()
    print("Start copying files to container: [%s]"%(container_name))
    copy_file_to_container(index_file_local_path, index_file_container_path, container_name)
    copy_file_to_container(datamodel_file_local_path, datamodel_file_container_path, container_name)
    print("Finished copying files to container: [%s]"%(container_name))


    wait_for_splunk_ready(max_seconds=120)
    from modules.splunk_sdk import enable_delete_for_admin
    if not enable_delete_for_admin(splunk_ip, splunk_port, splunk_password):
        print("COULD NOT ENABLE DELETE FOR [%s].... quitting"%(container_name))
        sys.exit(0)
    
    print("Successfully enabled DELETE for [%s]"%(container_name))
    
    #Wait for all of the threads to join here
    print("Container [%s] setup complete and waiting for other containers to be ready..."%(container_name))
    testing_object.start_barrier.wait()
    
    while True:
        #Sleep for a small random time so that containers drift apart and don't synchronize their testing
        time.sleep(random.randint(1,30))
        #Try to get something from the queue
        detection_to_test = testing_object.getTest()
        if detection_to_test is None:
            try:
                print("Container [%s] has finished running detections, time to stop the container."%(container_name))
                container.stop()
                print("Container [%s] successfully stopped"%(container_name))
                #remove the container
                removeContainer(client, container_name, forceRemove=True)
            except Exception as e:
                print("Error stopping or removing the container: [%s]"%(str(e)))

            return None


        
        #There is a detection to test
        print("Container [%s]--->[%s]"%(container_name, detection_to_test))
        try:
            result = testing_service.test_detection_wrapper(container_name, splunk_ip, splunk_password, splunk_port, detection_to_test, 0, uuid_test, testing_object.attack_data_root_folder, wait_on_failure=interactive_failure)
            testing_object.addResult(result)
            
            #Remove the data from the test that we just ran.  We MUST do this when running on CI because otherwise, we will download
            #a massive amount of data over the course of a long path and will run out of space on the relatively small CI runner drive
            shutil.rmtree(result['attack_data_directory'])
        except Exception as e:
            print("Warning - uncaught error in detection test for [%s] - this should not happen: [%s]"%(detection_to_test, str(e)))
            testing_object.addError({"detection_file":detection_to_test,"detection_error":str(e)})

def queue_status_thread(status_object:SynchronizedResultsTracker)->None:
    #This will run forever by design
    print("start status")
    while True:      
        if status_object.summarize() == False:
            #There are no more tests to run, so we can return from this thread
            return None
        time.sleep(10)
            
if __name__ == "__main__":
    main(sys.argv[1:])





