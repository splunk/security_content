from collections import OrderedDict
import datetime
import docker
import docker.types
import docker.models
import docker.models.resource
import docker.models.containers
import os.path
import random
import requests
import shutil
from modules import splunk_sdk
from modules import testing_service
from modules import test_driver
import time
import timeit
from typing import Union
import threading
import wrapt_timeout_decorator
import sys
import traceback
SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/%d/release/%s/download"
SPLUNK_START_ARGS = "--accept-license"

#Give ten minutes to start - this is probably enough time
MAX_CONTAINER_START_TIME_SECONDS = 60*20
class SplunkContainer:
    def __init__(
        self,
        synchronization_object: test_driver.TestDriver,
        full_docker_hub_path,
        container_name: str,
        apps: OrderedDict,
        web_port_tuple: tuple[str, int],
        management_port_tuple: tuple[str, int],
        container_password: str,
        files_to_copy_to_container: OrderedDict = OrderedDict(),
        mounts: list[docker.types.Mount] = [],
        splunkbase_username: Union[str, None] = None,
        splunkbase_password: Union[str, None] = None,
        splunk_ip: str = "127.0.0.1",
        interactive_failure: bool = False,
        interactive:bool = False
    ):
        self.interactive_failure = interactive_failure
        self.interactive = interactive
        self.synchronization_object = synchronization_object
        self.client = docker.client.from_env()
        self.full_docker_hub_path = full_docker_hub_path
        self.container_password = container_password
        
        self.apps = apps

        self.files_to_copy_to_container = files_to_copy_to_container
        self.splunk_ip = splunk_ip
        self.container_name = container_name
        self.mounts = mounts
        self.environment = self.make_environment(
            apps, container_password, splunkbase_username, splunkbase_password
        )
        self.ports = self.make_ports(web_port_tuple, management_port_tuple)
        self.web_port = web_port_tuple[1]
        self.management_port = management_port_tuple[1]
        self.container = self.make_container()

        self.thread = threading.Thread(target=self.run_container, )
        

        self.container_start_time = -1
        self.test_start_time = -1
        self.num_tests_completed = 0



    def prepare_apps_path(
        self,
        apps: OrderedDict,
        splunkbase_username: Union[str, None] = None,
        splunkbase_password: Union[str, None] = None,
    ) -> tuple[str, bool]:
        apps_to_install = []

        #We don't require credentials unless we install at least one splunkbase app
        require_credentials = False

        #If the username and password are supplied, then we will use splunkbase...
        #assuming that the app_name and app_number are supplied.  Note that if a 
        #local_path is supplied, then it should override this option!
        if splunkbase_username is not None and splunkbase_password is not None:
            use_splunkbase = True
        else:
            use_splunkbase = False

        for app_name, app_info in self.apps.items():
            if use_splunkbase is True and 'local_path' not in app_info:
                target = SPLUNKBASE_URL % (app_info["app_number"], app_info["app_version"])
                apps_to_install.append(target)
                #We will require credentials since we are installing at least one splunkbase app
                require_credentials = True
            #Some paths may have a local_path and an HTTP path defined. Default to the local_path first,
            #mostly because we may have copied it before into the cache to speed up start time.
            elif 'local_path' in app_info:
                app_file_name = os.path.basename(app_info['local_path'])
                app_file_container_path = os.path.join("/tmp/apps", app_file_name)
                apps_to_install.append(app_file_container_path)                
            elif 'http_path' in app_info:
                apps_to_install.append(app_info['http_path'])
                
            else:
                if use_splunkbase is True:
                    print("Error, the app %s: %s could not be installed from Splunkbase because "
                          "--splunkbase_username and.or --splunkbase_password were not provided."
                          "\n\tQuitting..."%(app_name,app_info), file=sys.stderr)
                else:
                    print("Error, the app %s: %s has no http_path or local_path.\n\tQuitting..."%(app_name,app_info), file=sys.stderr)
                sys.exit(1)

        
        return ",".join(apps_to_install), require_credentials

    def make_environment(
        self,
        apps: OrderedDict,
        container_password: str,
        splunkbase_username: Union[str, None] = None,
        splunkbase_password: Union[str, None] = None,
    ) -> dict:
        env = {}
        env["SPLUNK_START_ARGS"] = SPLUNK_START_ARGS
        env["SPLUNK_PASSWORD"] = container_password
        splunk_apps_url, require_credentials = self.prepare_apps_path(
            apps, splunkbase_username, splunkbase_password
        )
        
        if require_credentials:
            env["SPLUNKBASE_USERNAME"] = splunkbase_username
            env["SPLUNKBASE_PASSWORD"] = splunkbase_password
        env["SPLUNK_APPS_URL"] = splunk_apps_url
        
        
        return env

    def make_ports(self, *ports: tuple[str, int]) -> dict[str, int]:
        port_dict = {}
        for port in ports:
            port_dict[port[0]] = port[1]
        return port_dict

    def __str__(self) -> str:
        container_string = (
            "Container Name: %s\n\t"
            "Docker Hub Path: %s\n\t"
            "Apps: %s\n\t"
            "Ports: %s\n\t"
            "Mounts: %s\n\t"
            % (
                self.container_name,
                self.full_docker_hub_path,
                self.environment["SPLUNK_APPS_URL"],
                self.ports,
            )
        )

        return container_string

    def make_container(self) -> docker.models.resource.Model:
        # First, make sure that the container has been removed if it already existed
        self.removeContainer()

        container = self.client.containers.create(
            self.full_docker_hub_path,
            ports=self.ports,
            environment=self.environment,
            name=self.container_name,
            mounts=self.mounts,
            detach=True,
        )

        return container

    def extract_tar_file_to_container(
        self, local_file_path: str, container_file_path: str, sleepTimeSeconds: int = 5
    ) -> bool:
        # Check to make sure that the file ends in .tar.  If it doesn't raise an exception
        if os.path.splitext(local_file_path)[1] != ".tar":
            raise Exception(
                "Error - Failed copy of file [%s] to container [%s].  Only "
                "files ending in .tar can be copied to the container using this function."
                % (local_file_path, self.container_name)
            )
        successful_copy = False
        api_client = docker.APIClient()
        # need to use the low level client to put a file onto a container
        while not successful_copy:
            try:
                with open(local_file_path, "rb") as fileData:
                    # splunk will restart a few times will installation of apps takes place so it will reload its indexes...

                    api_client.put_archive(
                        container=self.container_name,
                        path=container_file_path,
                        data=fileData,
                    )
                    successful_copy = True
            except Exception as e:
                #print("Failed copy of [%s] file to [%s] on CONTAINER [%s]: [%s]\n...we will try again"%(local_file_path, container_file_path, self.container_name, str(e)))
                time.sleep(10)
                successful_copy = False
        #print("Successfully copied [%s] to [%s] on [%s]"% (local_file_path, container_file_path, self.container_name))
        return successful_copy

    def stopContainer(self,timeout=10) -> bool:
        try:        
            container = self.client.containers.get(self.container_name)
            #Note that stopping does not remove any of the volumes or logs,
            #so stopping can be useful if we want to debug any container failure 
            container.stop(timeout=10)
            self.synchronization_object.containerFailure()
            return True

        except Exception as e:
            # Container does not exist, or we could not get it. Throw and error
            print("Error stopping docker container [%s]"%(self.container_name))
            return False
        

    def removeContainer(
        self, removeVolumes: bool = True, forceRemove: bool = True
    ) -> bool:
        try:
            container = self.client.containers.get(self.container_name)
        except Exception as e:
            # Container does not exist, no need to try and remove it
            return True
        try:
            # container was found, so now we try to remove it
            # v also removes volumes linked to the container
            container.remove(
                v=removeVolumes, force=forceRemove
            )  # remove it even if it is running. remove volumes as well
            # No need to print that the container has been removed, it is expected behavior
            return True
        except Exception as e:
            print("Could not remove Docker Container [%s]" % (
                self.container_name))
            raise (Exception(f"CONTAINER REMOVE ERROR: {str(e)}"))

    def get_container_summary(self) -> str:
        current_time = timeit.default_timer()

        # Total time the container has been running
        if self.container_start_time == -1:
            total_time_string = "NOT STARTED"
        else:
            total_time_rounded = datetime.timedelta(
                seconds=round(current_time - self.container_start_time))
            total_time_string = str(total_time_rounded)

        # Time that the container setup took
        if self.test_start_time == -1 or self.container_start_time == -1:
            setup_time_string = "NOT SET UP"
        else:
            setup_secounds_rounded = datetime.timedelta(
                seconds=round(self.test_start_time - self.container_start_time))
            setup_time_string = str(setup_secounds_rounded)

        # Time that the tests have been running
        if self.test_start_time == -1 or self.num_tests_completed == 0:
            testing_time_string = "NO TESTS COMPLETED"
        else:
            testing_seconds_rounded = datetime.timedelta(
                seconds=round(current_time - self.test_start_time))

            # Get the approximate time per test.  This is a clunky way to get rid of decimal
            # seconds.... but it works
            timedelta_per_test = testing_seconds_rounded/self.num_tests_completed
            timedelta_per_test_rounded = timedelta_per_test - \
                datetime.timedelta(
                    microseconds=timedelta_per_test.microseconds)

            testing_time_string = "%s (%d tests @ %s per test)" % (
                testing_seconds_rounded, self.num_tests_completed, timedelta_per_test_rounded)

        summary_str = "Summary for %s\n\t"\
                      "Total Time          : [%s]\n\t"\
                      "Container Start Time: [%s]\n\t"\
                      "Test Execution Time : [%s]\n" % (
                          self.container_name, total_time_string, setup_time_string, testing_time_string)

        return summary_str

    def wait_for_splunk_ready(
        self,
        seconds_between_attempts: int = 10,
    ) -> bool:
        
        # The smarter version of this will try to hit one of the pages,
        # probably the login page, and when that is available it means that
        # splunk is fully started and ready to go.  Until then, we just
        # use a simple sleep
        
        
        while True:
            try:
                service = splunk_sdk.client.connect(host=self.splunk_ip, port=self.management_port, username='admin', password=self.container_password)
                if service.restart_required:
                    #The sleep below will wait
                    pass
                else:
                    return True
              
            except Exception as e:
                # There is a good chance the server is restarting, so the SDK connection failed.
                # Or, we tried to check restart_required while the server was restarting.  In the
                # calling function, we have a timeout, so it's okay if this function could get 
                # stuck in an infinite loop (the caller will generate a timeout error)
                pass
                    
            time.sleep(seconds_between_attempts)

    
    #@wrapt_timeout_decorator.timeout(MAX_CONTAINER_START_TIME_SECONDS, timeout_exception=RuntimeError)
    def setup_container(self):
        
        self.container.start()


        # def shutdown_signal_handler(sig, frame):
        #     shutdown_client = docker.client.from_env()
        #     errorCount = 0
        
        #     print(f"Shutting down {self.container_name}...", file=sys.stderr)
        #     try:
        #         container = shutdown_client.containers.get(self.container_name)
        #         #Note that stopping does not remove any of the volumes or logs,
        #         #so stopping can be useful if we want to debug any container failure 
        #         container.stop(timeout=10)
        #         print(f"{self.container_name} shut down successfully", file=sys.stderr)        
        #     except Exception as e:
        #         print(f"Error trying to shut down {self.container_name}. It may have already shut down.  Stop it youself with 'docker containter stop {self.container_name}", sys.stderr)
            
            
        #     #We must use os._exit(1) because sys.exit(1) actually generates an exception which can be caught! And then we don't Quit!
        #     import os
        #     os._exit(1)
                

                    
        # import signal
        # signal.signal(signal.SIGINT, shutdown_signal_handler)

        # By default, first copy the index file then the datamodel file
        for file_description, file_dict in self.files_to_copy_to_container.items():
            self.extract_tar_file_to_container(
                file_dict["local_file_path"], file_dict["container_file_path"]
            )

        print("Finished copying files to [%s]" % (self.container_name))
        self.wait_for_splunk_ready()
        
    def successfully_finish_tests(self)->None:
        try:
            if self.num_tests_completed == 0:
                print("Container [%s] did not find any tests and will not start.\n"\
                      "This does not mean there was an error!"%(self.container_name))
            else:
                print("Container [%s] has finished running [%d] detections, time to stop the container."
                      % (self.container_name, self.num_tests_completed))
            
            
            # remove the container
            self.removeContainer()
        except Exception as e:
            print(
                "Error stopping or removing the container: [%s]" % (str(e)))

        return None
    

    def run_container(self) -> None:
        print("Starting the container [%s]" % (self.container_name))
        
        # Try to get something from the queue. Check this early on
        # before launching the container because it can save us a lot of time!
        detection_to_test = self.synchronization_object.getTest()
        if detection_to_test is None:
            return self.successfully_finish_tests()

        self.container_start_time = timeit.default_timer()
    
        container_start_time = timeit.default_timer()
        
        try:
            self.setup_container()
        except Exception as e:
            print("There was an exception starting the container [%s]: [%s].  Shutting down container"%(self.container_name,str(e)),file=sys.stdout)
            self.stopContainer()
            elapsed_rounded = round(timeit.default_timer() - container_start_time)
            time_string = (datetime.timedelta(seconds=elapsed_rounded))
            print("Container [%s] FAILED in [%s]"%(self.container_name, time_string))
            return None


        #GTive some info about how long the container took to start up
        elapsed_rounded = round(timeit.default_timer() - container_start_time)
        time_string = (datetime.timedelta(seconds=elapsed_rounded))
        print("Container [%s] took [%s] to start"%(self.container_name, time_string))
        self.synchronization_object.start_barrier.wait()


        # Sleep for a small random time so that containers drift apart and don't synchronize their testing
        time.sleep(random.randint(1, 30))
        self.test_start_time = timeit.default_timer()
        while detection_to_test is not None:
            if self.synchronization_object.checkContainerFailure():
                self.container.stop()
                print("Container [%s] successfully stopped early due to failure" % (self.container_name))
                return None

            current_test_start_time = timeit.default_timer()
            # Sleep for a small random time so that containers drift apart and don't synchronize their testing
            #time.sleep(random.randint(1, 30))
            
             
            # There is a detection to test
            
            print("Container [%s]--->[%s]" %
                  (self.container_name, detection_to_test))
            try:
                result = testing_service.test_detection_wrapper(
                    self.container_name,
                    self.splunk_ip,
                    self.container_password,
                    self.management_port,
                    detection_to_test,
                    self.synchronization_object.attack_data_root_folder,
                    wait_on_failure=self.interactive_failure,
                    wait_on_completion = self.interactive
                )
                
                
                self.synchronization_object.addResult(result, duration_string =  datetime.timedelta(seconds=round(timeit.default_timer() - current_test_start_time)))

                # Remove the data from the test that we just ran.  We MUST do this when running on CI because otherwise, we will download
                # a massive amount of data over the course of a long path and will run out of space on the relatively small CI runner drive
                shutil.rmtree(result["attack_data_directory"],ignore_errors=True)
            except Exception as e:
                print(
                    "Warning - uncaught error in detection test for [%s] - this should not happen: [%s]"
                    % (detection_to_test, str(e))
                )
                
                #traceback.print_exc()
                #import pdb
                #pdb.set_trace()
                # Fill in all the "Empty" fields with default values. Otherwise, we will not be able to 
                # process the result correctly.  
                self.synchronization_object.addError(
                    {"detection_file": detection_to_test,
                        "detection_error": str(e)}, duration_string = datetime.timedelta(seconds=round(timeit.default_timer() - current_test_start_time))


                )
            self.num_tests_completed += 1

            # Try to get something from the queue
            detection_to_test = self.synchronization_object.getTest()
            
        #We failed to get a test from the queue, so we must be done gracefully!  Quit
        return self.successfully_finish_tests()

            
