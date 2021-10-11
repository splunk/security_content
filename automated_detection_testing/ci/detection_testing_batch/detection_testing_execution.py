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
import subprocess
from datetime import datetime
index_file_container_path = "/opt/splunk/etc/apps/search/"
index_file_local_path = "indexes.conf.tar"

PASSWORD_LENGTH=20
MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING=2
DOCKER_HUB_CONTAINER_PATH="splunk/splunk:latest"
BASE_CONTAINER_NAME="splunk"



#DOCKER_COMMIT_NAME = "splunk_configured"
#RUNNER_BASE_NAME = "splunk_runner"


BASE_CONTAINER_WEB_PORT=8000
BASE_CONTAINER_MANAGEMENT_PORT=8089




def wait_for_splunk_ready(splunk_container_name=None, splunk_web_port=None, max_seconds=30):
    #The smarter version of this will try to hit one of the pages,
    #probably the login page, and when that is available it means that
    #splunk is fully started and ready to go.  Until then, we just
    #use a simple sleep
    time.sleep(max_seconds)


def remove_container(docker_client, container_name, force=True):
    try:
        container = docker_client.containers.get(container_name)
    except Exception as e:
        print("Could not find Docker Container [%s]. Container does not exist"%(container_name))
        return True
    try:
        container.remove(v=True, force=force) #remove it even if it is running. remove volumes as well
        print("Successfully removed Docker Container [%s]"%(container_name))
    except Exception as e:
        print("Could not remove Docker Container [%s]"%(container_name))
        raise(Exception("CONTAINER REMOVE ERROR"))


def stop_container(docker_client, container_name, force=True):
    try:
        container = docker_client.containers.get(container_name)
    except:
        print("Container with name [%s] does not exist"%(container_name))
        return True
    
    try:
        print("Checking to see if [%s] is running..."%(container_name), end='')
        if container.status == 'exited':
            print("NO")
            return True
        else:
            print("YES (container.status is [%s])"%(container.status))
            print("Stopping [%s]"%(container_name))
            container.stop(force=force)
            return True
    except Exception as e:
        print("Error trying to stop the container [%s]"%(container_name))
        raise(Exception("CONTAINER STOP ERROR"))

        


def main(args):
    start_time = datetime.now()
    parser = argparse.ArgumentParser(description="CI Detection Testing")
    parser.add_argument("-b", "--branch", type=str, required=True, help="security content branch")
    parser.add_argument("-u", "--uuid", type=str, required=True, help="uuid for detection test")
    parser.add_argument("-pr", "--pr-number", type=int, required=False, help="Pull Request Number")
    parser.add_argument("-n", "--num_containers", required=False, type=int, default=1, help="The number of splunk docker containers to start and run for testing")
    
    parser.add_argument("-i", "--reuse_images", required=False, type=bool, default=False, help="Should existing images be re-used, or should they be redownloaded?")
    parser.add_argument("-c", "--reuse_containers", required=False, type=bool, default=False,  help="Should existing containers be re-used, or should they be rebuilt?")

    args = parser.parse_args()
    branch = args.branch
    uuid_test = args.uuid
    pr_number = args.pr_number
    num_containers = args.num_containers
    reuse_containers = args.reuse_containers
    reuse_images = args.reuse_images


    if num_containers < 1:
        #Perhaps this should be a mock-run - do the initial steps but don't do testing on the containers?
        print("Error, requested 0 containers.  You must run with at least 1 container.")
        sys.exit(1)
    elif num_containers > MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING:
        print("You requested to run with [%d] containers which may use a very large amount of resources "
               "as they all run in parallel.  The maximum suggested number of parallel containers is "
               "[%d].  We will do what you asked, but be warned!"%(num_containers, MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING))


    if pr_number:
        github_service = GithubService(branch, pr_number)
    else:
        github_service = GithubService(branch)
    test_files = github_service.get_changed_test_files()
    if len(test_files) == 0:
        print("No new detections to test.")
        #aws_service.dynamo_db_nothing_to_test(REGION, uuid_test, str(int(time.time())))
        sys.exit(0)
    print("The files to test: %s", str(test_files))
    
    #Go into the security content directory
    print("****GENERATE NEW CONTENT****")
    os.chdir("security_content")
    commands = ["python3 -m venv .venv", "source .venv/bin/activate", "python3 -m pip install -r requirements.txt", "python3 contentctl.py --path . --verbose generate --product ESCU --output dist/escu"]
    ret = subprocess.run("; ".join(commands), shell=True, capture_output=False)
    if ret.returncode != 0:
        print("Error generating new content.  Exiting...")
        sys.exit(1)
    print("New content generated successfully")
    os.chdir("..")

    client = docker.client.from_env()
    splunk_password = '123456qwertyQWERTY'
    
    
    
    
    

    #print("run it now!")
    
    #time.sleep(180)
    #dt_ar = aws_service.get_ar_information_from_dynamo_db(REGION, DT_ATTACK_RANGE_STATE)
    #splunk_instance = aws_service.get_splunk_instance(REGION, dt_ar['ssh_key_name'])

    #splunk_ip = splunk_instance['NetworkInterfaces'][0]['Association']['PublicIp']
    #splunk_password = dt_ar['password']
    #ssh_key_name = dt_ar['ssh_key_name']
    #private_key = dt_ar['private_key']

    #because this is only accessible to localhost, the password doesn't need to be particularly secure
    #We can also share it between splunk on all containers
    
    #splunk_password = secrets.token_urlsafe(PASSWORD_LENGTH)

    #Only accessible on local host, it's okay to expose the password for debugging
    #splunk_password = "123456qwerty!@#$%^QWERTY"
    #splunk_password = '123456qwerty%^QWERTY'
    splunk_container_manager_threads = []
    

    # print("***Files to test: %d"%(len(test_files)))
    test_file_queue = queue.Queue()
    for filename in test_files:
        test_file_queue.put(filename)
    # print("***Test files enqueued")

    testing_service.test_detection_wrapper(None, None, splunk_password, None, test_file_queue.get(), 0%1, uuid_test)
    
    # print("Getting docker client")
    client = docker.client.from_env()
    
    # try:
    #     print("Removing any existing containers called [%s]."%(BASE_CONTAINER_NAME))

    #     c = client.containers.get(BASE_CONTAINER_NAME)
    # except:
    #     print("Container [%s] did not exist. No need to remove it. It will; be created for you."%(BASE_CONTAINER_NAME))
    #     c = None
    

    # if (c and reuse_containers):
    #     print("Found a container called [%s]. NOT removing it because you have specified --reuse_containers [%s]. "
    #             "However, we must stop the container.  Stopping it now..."%(BASE_CONTAINER_NAME, reuse_containers))
    #     stop_container(client, BASE_CONTAINER_NAME)
        
    # elif c:
    #     print("Found a container called [%s]. Removing it because you have specified --reuse_containers [%s]"%(BASE_CONTAINER_NAME, reuse_containers))
    #     remove_container(client, BASE_CONTAINER_NAME)
        



    # download_image = False
    # try:
    #     client.images.get(DOCKER_HUB_CONTAINER_PATH)
    #     if reuse_images:
    #         print("You already have an image named [%s]."%(DOCKER_HUB_CONTAINER_PATH))
    #         download_image = False
    #     else:
    #         print("You already have an image named [%s]., "
    #                 "but have speicified --reuse_images %s"%(DOCKER_HUB_CONTAINER_PATH, reuse_images))
    #         download_image = True

    # except:
    #     print("You did not have an image named [%s]."%(DOCKER_HUB_CONTAINER_PATH))
    #     download_image = True

    # if download_image:        
    #     try:
    #         print("Downloading image [%s].  Please note "
    #             "that this could take a long time depending on your "
    #             "connection. It's around 2GB."%(DOCKER_HUB_CONTAINER_PATH))
    #         client.images.pull(DOCKER_HUB_CONTAINER_PATH)
    #         print("Finished downloading the image [%s]"%(DOCKER_HUB_CONTAINER_PATH))
    #     except Exception as e: 
    #         print("Unrecoverable error downloading image [%s]:[%s]"%(DOCKER_HUB_CONTAINER_PATH, str(e)))
    #         sys.exit(1)


    # remove_tag = False        
    # try:
    #     image = client.images.get(DOCKER_COMMIT_NAME)
    #     print("Found an image called [%s]"%(DOCKER_COMMIT_NAME))
    #     if reuse_images == False:
    #         print("We will remove the image [%s] because you have specificed --reuse_images %s"%(DOCKER_COMMIT_NAME, reuse_images))
    #         remove_tag = True
    #         build_Tag = True
    #     else:
    #         print("We will use the preexisting image for [%s]"%(DOCKER_COMMIT_NAME))
    #         build_tag = False
    # except:
    #     print("No image found named [%s]"%(DOCKER_COMMIT_NAME))
    #     build_tag = True
    

    # if remove_tag:
    #     try:
    #         #Stop it if it's running, remove associated volumes too
    #         client.images.remove(image=DOCKER_COMMIT_NAME, force=True)
            
    #     except Exception as e:
    #         print("Unrecoverable error removing [%s]: [%s]"%(DOCKER_COMMIT_NAME, str(e)))
    #         sys.exit(1)
            
    
            

    # for ind in range(num_containers):
    #     ind = str(ind)
    #     if not reuse_containers:
    #         try:
    #             print("Creating a new container called [%s]"%(BASE_CONTAINER_NAME+ind))
            

    #             environment = {"SPLUNK_START_ARGS": "--accept-license",
    #                     "SPLUNK_PASSWORD"  : splunk_password }
    #             ports= {"8000/tcp": BASE_CONTAINER_WEB_PORT - 1 + int(ind) + 1,
    #             "8089/tcp": BASE_CONTAINER_MANAGEMENT_PORT - 1 + int(ind) + 1
    #             }
    #             base_container = client.containers.create("splunk/splunk:latest", ports=ports, environment=environment, name=BASE_CONTAINER_NAME+ind, detach=True)
    #             print("Running the new container called [%s]"%(BASE_CONTAINER_NAME+ind))
    #             base_container.start()
    #             print("Container is running [%s]"%(BASE_CONTAINER_NAME+ind))
    #             print("Sleep for 60 seconds to allow the container to fully start up...")
    #             wait_for_splunk_ready(max_seconds=60)
    #             print("The container has fully started!")

    #             print("Do the ESCU installation on this container. That way we don't have to "
    #                     "do it on every container that we then spin up.")

    #             testing_service.prepare_detection_testing(BASE_CONTAINER_NAME+ind, splunk_password)
    #             print("Waiting for a few seconds for the splunk app to come up.")
    #             wait_for_splunk_ready(max_seconds=30)
    #             print("Install the apps and enable accelerate")
    #             wait_for_splunk_ready(max_seconds=180)
    #             print("Stopping the running container [%s]"%(BASE_CONTAINER_NAME+ind))
    #             base_container.stop()
    #             #I am almost positive that I'm doing this wrong but it works for now...

    #             #print("Committing the configured container: [%s]--->[%s]"%(BASE_CONTAINER_NAME, DOCKER_COMMIT_NAME))
    #             #base_container.commit(repository=DOCKER_COMMIT_NAME)
        

    #         except Exception as e:
    #             print("There was an error getting the base container up and running.  "
    #                 "We cannot recover from this: [%s]\nGoodbye..."%(str(e)))
    #             sys.exit(1)

     
    # # # #The part below does not seem to be working as expected. Will need to look into it
    # # # #When I create the new container, it fails to boot with 
    # # # # The CA file specified (/opt/splunk/etc/auth/cacert.pem) does not exist. Cannot continue.
    # # # # SSL certificate generation failed.


    # # # # MSG:

    # # # # non-zero return code
    
    
    

    
    print("Make all the threads...")
    print("The number of detections we will test is [%d]"%(test_file_queue.qsize()))
    
    results_queue = queue.Queue()
    success_names_queue = queue.Queue()
    failure_names_queue = queue.Queue()
    for container_index in range(num_containers):
        container_name = "%s_%d"%(BASE_CONTAINER_NAME, container_index)
        
        web_port = BASE_CONTAINER_WEB_PORT  + container_index
        management_port = BASE_CONTAINER_MANAGEMENT_PORT + container_index

        #docker run -p8089:8089 -p 8000:8000 -e "SPLUNK_START_ARGS=--accept-license" -e "SPLUNK_PASSWORD=123456qwertyQWERTY" -e "SPLUNK_APPS_URL=https://splunkbase.splunk.com/app/3435/release/3.3.4/download,https://splunkbase.splunk.com/app/5709/release/1.0.1/download,https://splunkbase.splunk.com/app/3449/release/3.29.0/download,https://splunkbase.splunk.com/app/1621/release/4.20.2/download" -e "SPLUNKBASE_USERNAME=ericmcginnistwo" -e "SPLUNKBASE_PASSWORD=splunkSecondAccount5@" -name splunktemplate splunk/splunk:latest 
        environment = {"SPLUNK_START_ARGS": "--accept-license",
                        "SPLUNK_PASSWORD"  : splunk_password, 
                        "SPLUNK_APPS_URL"   : "https://splunkbase.splunk.com/app/3435/release/3.3.4/download,https://splunkbase.splunk.com/app/5709/release/1.0.1/download,https://splunkbase.splunk.com/app/3449/release/3.29.0/download,https://splunkbase.splunk.com/app/1621/release/4.20.2/download",
                        "SPLUNKBASE_USERNAME" : "emcginnistwo",
                        "SPLUNKBASE_PASSWORD" : "splunkSecondAccount5@"
                        }
        ports= {"8000/tcp": web_port,
                "8089/tcp": management_port
               }

        print("Creating CONTAINER: [%s]"%(container_name))
        base_container = client.containers.create(DOCKER_HUB_CONTAINER_PATH, ports=ports, environment=environment, name=container_name, detach=True)
        print("Created CONTAINER : [%s]"%(container_name))
        #print("Creating a new container called [%s]"%(container_name))
        #environment = {"SPLUNK_START_ARGS": "--accept-license",
        #               "SPLUNK_PASSWORD"  : splunk_password }
        #ports= {"8000/tcp": web_port,
        #        "8089/tcp": management_port
        #        }

        #test_container = client.containers.create(DOCKER_COMMIT_NAME, ports=ports, environment=environment, name=container_name, detach=True, volumes_from=[BASE_CONTAINER_NAME])
        
        t = threading.Thread(target=splunk_container_manager, args=(test_file_queue, container_name, "127.0.0.1", splunk_password, management_port, uuid_test, results_queue, success_names_queue, failure_names_queue))
        splunk_container_manager_threads.append(t)

    #add the queue status thread - there can be some error in one of the test threads, so this
    #thread doesn't need to complete for the program to finish execution
    status_thread = threading.Thread(target=queue_status_thread, args=(test_file_queue.qsize(), test_file_queue, results_queue, success_names_queue, failure_names_queue), daemon=True)
    status_thread.start()
    print("Start all the threads...")
    for t in splunk_container_manager_threads:
        t.start()
        #we need to start containers slowly.  Would be great it we could do all the setup and
        #app install once (with Dockerfile?)
        time.sleep(60)
    
    #Try to join all the threads
    for t in splunk_container_manager_threads:
        t.join() #blocks on waiting to join
        print("Joined a thread!")

    print("DONE!")
    #read all the results out from the output queue
    try:
        while True:

            o = results_queue.get(block=False)
            print(o)
    except queue.Empty:
        print("That's all the output!")
    
    #now we are done!
    stop_time = datetime.now()
    print("Total Execution Time: [%s]"%(stop_time-start_time))
    

    #detection testing service has already been prepared, no need to do it here!
    #testing_service.prepare_detection_testing(ssh_key_name, private_key, splunk_ip, splunk_password)

    #testing_service.test_detections(ssh_key_name, private_key, splunk_ip, splunk_password, test_files, uuid_test)
    
def queue_status_thread(total_tests_count, testing_queue, results_queue, success_names_queue, failure_names_queue):
    while True:
        print("***Progress Update:\n"\
              "\tTests to run           : %d\n"\
              "\tTests currently running: %d\n"\
              "\tTests completed        : %d\n"\
              "\t\tSuccess : %d\n"\
              "\t\tFailure : %d"%(testing_queue.qsize(), total_tests_count - testing_queue.qsize() - results_queue.qsize(), results_queue.qsize(), success_names_queue.qsize(), failure_names_queue.qsize()))
        if results_queue.qsize() == total_tests_count:
            return
        else:
            time.sleep(10)

def splunk_container_manager(testing_queue, container_name, splunk_ip, splunk_password, splunk_port, uuid_test, results_queue, success_names_queue, failure_names_queue):
    print("Starting the container [%s] after a sleep"%(container_name))
    #Is this going to be safe to use in different threads
    client = docker.client.from_env()
    
    #start up the container from the base container
    #Assume that the base container has already been fully built with
    #escu etc
    #sleep for a little bit so that we don't all start at once...
    time.sleep(random.randrange(0,60))

    container = client.containers.get(container_name)
    print("Starting the container [%s]"%(container_name))

    #need to use the low level client to put a file onto a container
    apiclient = docker.APIClient()

    container.start()
    successful_copy = False
    while not successful_copy:
        try:
            with open(index_file_local_path,"rb") as indexData:
                #splunk will restart a few times will installation of apps takes place so it will reload its indexes...
                time.sleep(10)
                apiclient.put_archive(container=container_name, path=index_file_container_path, data=indexData)
                successful_copy=True
        except Exception as e:
            print("Failed copy of index file to CONTAINER:[%s]...we will try again"%(container_name))
            successful_copy=False
            


    wait_for_splunk_ready(max_seconds=120)

    index=0
    try:
        while True:
            #Try to get something from the queue
            detection_to_test = testing_queue.get(block=False)
            
            
            #There is a detection to test
            print("Container [%s]--->[%s]"%(container_name, detection_to_test))
            try:
                result = testing_service.test_detection_wrapper(container_name, splunk_ip, splunk_password, splunk_port, detection_to_test, index%1, uuid_test)
                if result['detection_result']['error']:
                    failure_names_queue.put(result['detection_result']['detection_name'])
                else:
                    success_names_queue.put(result['detection_result']['detection_name'])
                results_queue.put(result)
            except Exception as e:
                print("Caught some exception in test detection: [%s]"%(str(e)))
                #just log the error itself for now so that we can continue
                result_test = str(e)

            index=(index+1)%10
    except queue.Empty:
        print("Queue was empty, [%s] finished testing detections!"%(container_name))
    
    print("Shutting down the container [%s]"%(container_name))
    container.stop()
    print("Finished shutting down the container [%s]"%(container_name))

if __name__ == "__main__":
    main(sys.argv[1:])