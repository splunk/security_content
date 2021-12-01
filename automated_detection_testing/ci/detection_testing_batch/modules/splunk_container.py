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

SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/%d/release/%s/download"
SPLUNK_START_ARGS = "--accept-license"


class SplunkContainer:
    def __init__(
        self,
        synchronization_object: test_driver.TestDriver,
        full_docker_hub_path,
        container_name: str,
        local_apps: OrderedDict,
        splunkbase_apps: OrderedDict,
        web_port_tuple: tuple[str, int],
        management_port_tuple: tuple[str, int],
        container_password: str,
        files_to_copy_to_container: OrderedDict = OrderedDict(),
        mounts: list[docker.types.Mount] = [],
        splunkbase_username: Union[str, None] = None,
        splunkbase_password: Union[str, None] = None,
        splunk_ip: str = "127.0.0.1",
        interactive_failure: bool = False,
    ):
        self.interactive_failure = interactive_failure
        self.synchronization_object = synchronization_object
        self.client = docker.client.from_env()
        self.full_docker_hub_path = full_docker_hub_path
        self.container_password = container_password
        self.local_apps = local_apps
        self.splunkbase_apps = splunkbase_apps

        self.files_to_copy_to_container = files_to_copy_to_container
        self.splunk_ip = splunk_ip
        self.container_name = container_name
        self.mounts = mounts
        self.environment = self.make_environment(
            local_apps, splunkbase_apps, container_password, splunkbase_username, splunkbase_password
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
        local_apps: OrderedDict,
        splunkbase_apps: OrderedDict,
        splunkbase_username: Union[str, None] = None,
        splunkbase_password: Union[str, None] = None,
    ) -> tuple[str, bool]:
        apps_to_install = []
        require_credentials = False

        for app_name, app_info in self.local_apps.items():

            app_file_name = os.path.basename(app_info['local_path'])
            app_file_container_path = os.path.join("/tmp/apps", app_file_name)
            apps_to_install.append(app_file_container_path)

        for app_name, app_info in self.splunkbase_apps.items():

            if splunkbase_username is None or splunkbase_password is None:
                raise Exception(
                    "Error: Requested app from Splunkbase but Splunkbase username and/or password were not supplied."
                )
            target = SPLUNKBASE_URL % (
                app_info["app_number"], app_info["app_version"])
            apps_to_install.append(target)
            require_credentials = True
            # elif app["location"] == "local":
            #    apps_to_install.append(app["container_path"])
        return ",".join(apps_to_install), require_credentials

    def make_environment(
        self,
        local_apps: OrderedDict,
        splunkbase_apps: OrderedDict,
        container_password: str,
        splunkbase_username: Union[str, None] = None,
        splunkbase_password: Union[str, None] = None,
    ) -> dict:
        env = {}
        env["SPLUNK_START_ARGS"] = SPLUNK_START_ARGS
        env["SPLUNK_PASSWORD"] = container_password
        splunk_apps_url, require_credentials = self.prepare_apps_path(
            local_apps, splunkbase_apps, splunkbase_username, splunkbase_password
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
                # print("Failed copy of [%s] file to CONTAINER:[%s]...we will try again"%(localFilePath, containerName))
                time.sleep(10)
                successful_copy = False
        print(
            "Successfully copied [%s] to [%s] on [%s]"
            % (local_file_path, container_file_path, self.container_name)
        )
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
            raise (Exception("CONTAINER REMOVE ERROR"))

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
                      "Test Execution Time : [%s]" % (
                          self.container_name, total_time_string, setup_time_string, testing_time_string)

        return summary_str

    def wait_for_splunk_ready(
        self,
        max_seconds: int = 300,
        seconds_between_attempts: int = 5,
    ) -> bool:
        
        # The smarter version of this will try to hit one of the pages,
        # probably the login page, and when that is available it means that
        # splunk is fully started and ready to go.  Until then, we just
        # use a simple sleep
        splunk_ready_url = "http://%s:%d" % (self.splunk_ip, self.web_port)
        start = timeit.default_timer()
        while True:
            try:
                # Splunk container will not have proper ssl certificate
                response = requests.get(
                    splunk_ready_url, timeout=seconds_between_attempts, verify=False)
                response.raise_for_status()
                return True
            except Exception as e:
                elapsed = timeit.default_timer() - start
                
                if elapsed > max_seconds:
                    self.stopContainer()
                    raise (
                        Exception(
                            "Container [%s] took longer than maximum start time of [%d].\n\tStopping container..."
                            % (self.container_name, max_seconds)
                        )
                    )
                    
            time.sleep(seconds_between_attempts)

    def run_container(self) -> None:
        print("Starting the container [%s]" % (self.container_name))
        self.container_start_time = timeit.default_timer()
        self.container.start()

        # By default, first copy the index file then the datamodel file
        for file_description, file_dict in self.files_to_copy_to_container.items():
            self.extract_tar_file_to_container(
                file_dict["local_file_path"], file_dict["container_file_path"]
            )

        print("Finished copying files to [%s]" % (self.container_name))

        try:
            while not splunk_sdk.enable_delete_for_admin(self.splunk_ip, self.management_port, self.container_password):
                time.sleep(10)
        except Exception as e:
            print(
                "Failure enabling DELETE for container [%s]: [%s].\n\tQuitting..."
                % (self.container_name, str(e))
            )

        # Wait for all of the threads to join here
        print(
            "Container [%s] setup complete and waiting for other containers to be ready..."
            % (self.container_name)
        )

        self.synchronization_object.start_barrier.wait()
        
        try:
            self.wait_for_splunk_ready()
        except Exception as e:
            print("Error starting docker container: [%s]"%(str(e)))
            return None
        

        # Sleep for a small random time so that containers drift apart and don't synchronize their testing
        time.sleep(random.randint(1, 30))
        
        self.test_start_time = timeit.default_timer()
        while True:
            if self.synchronization_object.checkContainerFailure():
                self.container.stop()
                print("Container [%s] successfully stopped early due to failure" % (self.container_name))
                return None

            # Try to get something from the queue
            detection_to_test = self.synchronization_object.getTest()
            if detection_to_test is None:
                try:
                    print(
                        "Container [%s] has finished running detections, time to stop the container."
                        % (self.container_name)
                    )
                    
                    # remove the container
                    self.removeContainer()
                except Exception as e:
                    print(
                        "Error stopping or removing the container: [%s]" % (str(e)))

                return None

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
                )
                self.synchronization_object.addResult(result)

                # Remove the data from the test that we just ran.  We MUST do this when running on CI because otherwise, we will download
                # a massive amount of data over the course of a long path and will run out of space on the relatively small CI runner drive
                shutil.rmtree(result["attack_data_directory"])
            except Exception as e:
                print(
                    "Warning - uncaught error in detection test for [%s] - this should not happen: [%s]"
                    % (detection_to_test, str(e))
                )
                # Fill in all the "Empty" fields with default values. Otherwise, we will not be able to 
                # process the result correctly.  
                self.synchronization_object.addError(
                    {"detection_file": detection_to_test,
                        "detection_error": str(e)}


                )
            self.num_tests_completed += 1

            # Sleep for a small random time so that containers drift apart and don't synchronize their testing
            time.sleep(random.randint(1, 30))
