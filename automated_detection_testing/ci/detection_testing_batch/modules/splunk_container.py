from collections import OrderedDict
import docker
import docker.types
import docker.models
import docker.models.resource
import docker.models.containers
import os.path
import requests
import shutil
import splunk_sdk
import testing_service
import time
import timeit
from typing import Union


SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/%d/release/%s/download"
SPLUNK_START_ARGS = "--accept-license"


class SplunkContainer:
    def __init__(
        self,
        synchronization_object,
        full_docker_hub_path,
        container_name: str,
        apps: list[dict],
        web_port: tuple[str, int],
        management_port: tuple[str, int],
        container_password: str,
        files_to_copy_to_container: OrderedDict = OrderedDict(),
        mounts: list[docker.types.Mount] = [],
        splunkbase_username: Union[str, None] = None,
        splunkbase_password: Union[str, None] = None,
        splunk_ip:str = "127.0.0.1"
    ):
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
        self.ports = self.make_ports(web_port, management_port)
        self.web_port = web_port
        self.management_port = management_port
        self.container = self.make_container()

    def prepare_apps_path(
        self,
        apps: list[dict],
        splunkbase_username: Union[str, None] = None,
        splunkbase_password: Union[str, None] = None,
    ) -> tuple[str, bool]:
        apps_to_install = []
        require_credentials = False
        for app in self.apps:
            if app["location"] == "splunkbase":
                if splunkbase_username is None or splunkbase_password is None:
                    raise Exception(
                        "Error: Requested app from Splunkbase but Splunkbase username and/or password were not supplied."
                    )
                target = SPLUNKBASE_URL % (app["app_number"], app["app_version"])
                apps_to_install.append(target)
                require_credentials = True
            elif app["location"] == "local":
                apps_to_install.append(app["container_path"])
        return ",".join(apps_to_install), require_credentials

    def make_volume(
        self,
        local_path: str,
        container_path: str,
        type: str = "bind",
        read_only: bool = True,
    ) -> docker.types.Mount:
        return docker.types.Mount(
            source=local_path, target=container_path, type="bind", read_only=True
        )

    def make_environment(
        self,
        apps: list[dict],
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
            print("Could not remove Docker Container [%s]" % (self.container_name))
            raise (Exception("CONTAINER REMOVE ERROR"))

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
                response = requests.get(splunk_ready_url, timeout=5, verify=False)
                response.raise_for_status()
                return True
            except Exception as e:
                elapsed = timeit.default_timer() - start
                if elapsed > max_seconds:
                    raise (
                        Exception(
                            "Container [%s] took longer than maximum start time of [%d].\n\tQuitting..."
                            % (self.container_name, max_seconds)
                        )
                    )
            time.sleep(seconds_between_attempts)

    def run_container(self) -> None:
        print("Starting the container [%s]" % (self.container_name))
        self.container.start()

        # By default, first copy the index file then the datamodel file
        for f in self.files_to_copy_to_container:
            self.extract_tar_file_to_container(
                f["local_file_path"], f["container_file_path"]
            )

        print("Finished copying files to [%s]" % (self.container_name))

        try:
            while not splunk_sdk.enable_delete_for_admin(
                self.splunk_ip, self.management_port, self.container_password
            ):
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
        synchornization_object.start_barrier.wait()
        self.wait_for_splunk_ready()
        
        while True:
            # Sleep for a small random time so that containers drift apart and don't synchronize their testing
            time.sleep(random.randint(1, 30))
            # Try to get something from the queue
            detection_to_test = testing_object.getTest()
            if detection_to_test is None:
                try:
                    print(
                        "Container [%s] has finished running detections, time to stop the container."
                        % (container_name)
                    )
                    container.stop()
                    print("Container [%s] successfully stopped" % (container_name))
                    # remove the container
                    removeContainer(client, container_name, forceRemove=True)
                except Exception as e:
                    print("Error stopping or removing the container: [%s]" % (str(e)))

                return None

            # There is a detection to test
            print("Container [%s]--->[%s]" % (container_name, detection_to_test))
            try:
                result = testing_service.test_detection_wrapper(
                    container_name,
                    splunk_ip,
                    splunk_password,
                    splunk_management_port,
                    detection_to_test,
                    0,
                    uuid_test,
                    testing_object.attack_data_root_folder,
                    wait_on_failure=interactive_failure,
                )
                testing_object.addResult(result)

                # Remove the data from the test that we just ran.  We MUST do this when running on CI because otherwise, we will download
                # a massive amount of data over the course of a long path and will run out of space on the relatively small CI runner drive
                shutil.rmtree(result["attack_data_directory"])
            except Exception as e:
                print(
                    "Warning - uncaught error in detection test for [%s] - this should not happen: [%s]"
                    % (detection_to_test, str(e))
                )
                testing_object.addError(
                    {"detection_file": detection_to_test, "detection_error": str(e)}
                )


"""
def remove_existing_containers(client: docker.client.DockerClient, reuse_containers: bool, container_template: str, num_containers: int, forceRemove: bool=True) -> bool:
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
   """
