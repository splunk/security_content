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
from modules.github_service import GithubService
from modules import aws_service, testing_service
import time


DT_ATTACK_RANGE_STATE_STORE = "dt-attack-range-tf-state-store"
DT_ATTACK_RANGE_STATE = "dt-attack-range-state"
REGION = "eu-central-1"
NAME = "detection-testing-attack-range"

PASSWORD_LENGTH=20
MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING=2
DOCKER_HUB_CONTAINER_PATH="splunk/splunk:latest"
BASE_CONTAINER_NAME="splunk"

DOCKER_COMMIT_NAME = "splunk_configured"


BASE_CONTAINER_WEB_PORT=8000
BASE_CONTAINER_MANAGEMENT_PORT=8089


def wait_for_splunk_ready(splunk_container_name=None, splunk_web_port=None, max_seconds=30):
    #The smarter version of this will try to hit one of the pages,
    #probably the login page, and when that is available it means that
    #splunk is fully started and ready to go.  Until then, we just
    #use a simple sleep
    time.sleep(max_seconds)

def main(args):

    parser = argparse.ArgumentParser(description="CI Detection Testing")
    parser.add_argument("-b", "--branch", type=str, required=True, help="security content branch")
    parser.add_argument("-u", "--uuid", type=str, required=True, help="uuid for detection test")
    parser.add_argument("-pr", "--pr-number", type=int, required=False, help="Pull Request Number")
    parser.add_argument("-n", "--num_containers", required=False, type=int, default=1, help="The number of splunk docker containers to start and run for testing")

    args = parser.parse_args()
    branch = args.branch
    uuid_test = args.uuid
    pr_number = args.pr_number
    num_containers = args.num_containers
    if num_containers < 1:
        #Perhaps this should be a mock-run - do the initial steps but don't do testing on the containers?
        print("Error, requested 0 containers.  You must run with at least 1 container.")
        sys.exit(1)
    elif num_containers > MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING:
        print("You requested to run with [%d] containers which may use a very large amount of resources \
               as they all run in parallel.  The maximum suggested number of parallel. The maximum \
               suggested number of containers is [%d].  We will do what you asked, but be warned!"%(num_containers, MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING))


    if pr_number:
        github_service = GithubService(branch, pr_number)
    else:
        github_service = GithubService(branch)
    test_files = github_service.get_changed_test_files()
    if len(test_files) == 0:
        print("No new detections to test.")
        #aws_service.dynamo_db_nothing_to_test(REGION, uuid_test, str(int(time.time())))
        sys.exit(0)

    #dt_ar = aws_service.get_ar_information_from_dynamo_db(REGION, DT_ATTACK_RANGE_STATE)
    #splunk_instance = aws_service.get_splunk_instance(REGION, dt_ar['ssh_key_name'])

    #splunk_ip = splunk_instance['NetworkInterfaces'][0]['Association']['PublicIp']
    #splunk_password = dt_ar['password']
    #ssh_key_name = dt_ar['ssh_key_name']
    #private_key = dt_ar['private_key']

    #because this is only accessible to localhost, the password doesn't need to be particularly secure
    #We can also share it between splunk on all containers
    
    splunk_password = secrets.token_urlsafe(PASSWORD_LENGTH)
    splunk_container_manager_threads = []
    

    print("***Files to test: %d"%(len(test_files)))
    test_file_queue = queue.Queue()
    for filename in test_files:
        test_file_queue.put(filename)
    print("***Test files enqueued")

    print("Getting docker client")
    client = docker.client.from_env()
    try:
        print("Removing any existing containers called [%s]."%(BASE_CONTAINER_NAME))

        c = client.containers.get(BASE_CONTAINER_NAME)
        c.remove(v=True, force=True) #remove it even if it is running. remove volumes as well
    except:
        print("Container [%s] did not exist. No need to remove it"%(BASE_CONTAINER_NAME))

    try:
        try:
            client.images.get(DOCKER_HUB_CONTAINER_PATH)
            print("You already have an image named [%s]. We will not "
                "download it again."%(DOCKER_HUB_CONTAINER_PATH))
        except:
            print("You did not have an image named [%s]. We will "
                "download it now from the Docker Hub.  Please note "
                "that this could take a long time depending on your "
                "connection. It's around 2GB."%(DOCKER_HUB_CONTAINER_PATH))
            client.images.pull(DOCKER_HUB_CONTAINER_PATH)
            print("Finished downloading the image [%s]"%(DOCKER_HUB_CONTAINER_PATH))

        try:
            image = client.images.get(DOCKER_COMMIT_NAME)
            print("Found an image called [%s]. We will remove it"%(DOCKER_COMMIT_NAME))
            #Stop it if it's running, remove associated volumes too
            image.remove(v=True, force=True)
        except:
            print("No image found named [%s]"%(DOCKER_COMMIT_NAME))
        
            

        

        print("Creating a new container called [%s]"%(BASE_CONTAINER_NAME))
        environment = {"SPLUNK_START_ARGS": "--accept-license",
                       "SPLUNK_PASSWORD"  : splunk_password }
        ports= {"8000/tcp": BASE_CONTAINER_WEB_PORT - 1,
                "8089/tcp": BASE_CONTAINER_MANAGEMENT_PORT - 1
                }

        base_container = client.containers.create("splunk/splunk:latest", ports=ports, environment=environment, name=BASE_CONTAINER_NAME, detach=True)
        print("Running the new container called [%s]"%(BASE_CONTAINER_NAME))
        base_container.start()
        print("Container is running [%s]"%(BASE_CONTAINER_NAME))
        print("Sleep for 60 seconds to allow the container to fully start up...")
        wait_for_splunk_ready(max_seconds=60)
        print("The container has fully started!")

    except Exception as e:
        print("There was an error getting the base container up and running.  "
            "We cannot recover from this: [%s]\nGoodbye..."%(str(e)))
        sys.exit(1)

    print("Do the ESCU installation on this container. That way we don't have to "
          "do it on every container that we then spin up.")

    testing_service.prepare_detection_testing(BASE_CONTAINER_NAME, splunk_password)
    print("Waiting for a few seconds for the splunk app to come up.")
    wait_for_splunk_ready(max_seconds=30)
    
    print("Stopping the running container [%s]"%(BASE_CONTAINER_NAME))
    base_container.stop()

    print("Committing the configured container: [%s]--->[%s]"%(BASE_CONTAINER_NAME, DOCKER_COMMIT_NAME))
    base_container.commit(repository=DOCKER_COMMIT_NAME)


    '''
    print("Removing container called splunk if it exists already...")
    client.container.r

    print("Build base docker container")


    for container_index in range(num_containers):
        container_name = "splunk_runner_%d"%(container_index)
        t = threading.Thread(target=splunk_container_manager, args=(test_file_queue, container_name, splunk_password))
        splunk_container_manager_threads.append(t)

    splunk_container_name = "splunk"

    testing_service.prepare_detection_testing(ssh_key_name, private_key, splunk_ip, splunk_password)
    testing_service.test_detections(ssh_key_name, private_key, splunk_ip, splunk_password, test_files, uuid_test)
    '''

def splunk_container_manager(testing_queue, container_name, splunk_password):
    #Is this going to be safe to use in different threads
    docker_client = docker.client.from_env()
    #start up the container from the base container
    #Assume that the base container has already been fully built with
    #escu etc
    pass

if __name__ == "__main__":
    main(sys.argv[1:])