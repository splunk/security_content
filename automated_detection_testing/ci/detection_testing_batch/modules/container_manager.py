from collections import OrderedDict
import docker
import datetime
import docker.types
import random
import splunk_container
import string
import test_driver
import threading
import time
import timeit
from typing import Union

WEB_PORT_STRING = "8000/tcp"
MANAGEMENT_PORT_STRING = "8089/tcp"


class ContainerManager:
    def __init__(
        self,
        test_list: list[str],
        full_docker_hub_name: str,
        container_name_template: str,
        num_containers: int,
        apps: OrderedDict,
        files_to_copy_to_container: OrderedDict = OrderedDict(),
        web_port_start: int = 8000,
        management_port_start: int = 8089,
        mounts: list[dict[str, Union[str, bool]]] = [],
        container_password: Union[str, None] = None,
        splunkbase_username: Union[str, None] = None,
        splunkbase_password: Union[str, None] = None,
        reuse_image:bool = True
    ):
        self.synchronization_object = test_driver.TestDriver(
            test_list, num_containers)

        self.mounts = self.create_mounts(mounts)
        self.apps = apps

        if container_password is None:
            self.container_password = self.get_random_password()
        else:
            self.container_password = container_password

        self.containers = self.create_containers(
            full_docker_hub_name,
            container_name_template,
            num_containers,
            web_port_start,
            management_port_start,
            splunkbase_username,
            splunkbase_password,
            files_to_copy_to_container,
            reuse_image
        )
        self.summary_thread = threading.Thread(target=self.queue_status_thread,args=())

        #Construct the baseline from the splunk version and the apps to be installed
        self.baseline = OrderedDict()
        #Get a datetime and add it as the first entry in the baseline
        self.start_time = datetime.datetime.now()
        self.baseline['SPLUNK_VERSION'] = full_docker_hub_name
        #Added here first to preserve ordering for OrderedDict
        self.baseline['TEST_START_TIME'] = "TO BE UPDATED"
        self.baseline['TEST_FINISH_TIME'] = "TO BE UPDATED"
        self.baseline['TEST_DURATION'] = "TO BE UPDATED"

        for key in self.apps:
            self.baseline[key] = self.apps[key]

    def run_test(self):
        self.run_containers()
        self.run_status_thread()
        for container in self.containers:
            container.thread.join()
            print(container.get_container_summary())
        self.summary_thread.join()
        print("All containers completed testing!")
        
        
        stop_time = datetime.datetime.now()
        x = stop_time - self.start_time

        self.baseline['TEST_START_TIME'] = str(self.start_time)
        self.baseline['TEST_FINISH_TIME'] =  str(stop_time)
        
        duration = stop_time - self.start_time
        self.baseline['TEST_DURATION'] = duration - datetime.timedelta(microseconds=duration.microseconds)

        self.synchronization_object.finish(self.baseline)




    def run_containers(self) -> None:
        for container in self.containers:
            container.thread.run()
    
    def run_status_thread(self) -> None:
        self.queue_status_thread.run()
        


    def create_containers(
        self,
        full_docker_hub_name: str,
        container_name_template: str,
        num_containers: int,
        web_port_start: int,
        management_port_start: int,
        splunkbase_username: Union[str, None] = None,
        splunkbase_password: Union[str, None] = None,
        files_to_copy_to_container: OrderedDict = OrderedDict(),
        reuse_image = True
    ) -> list[splunk_container.SplunkContainer]:
        #First make sure that the image exists and has been downloaded
        self.setup_image(reuse_image, full_docker_hub_name)

        new_containers = []
        for index in range(num_containers):
            container_name = container_name_template % index
            web_port_tuple = (WEB_PORT_STRING, web_port_start + index)
            management_port_tuple = (
                MANAGEMENT_PORT_STRING,
                management_port_start + index,
            )
            
            new_containers.append(
                splunk_container.SplunkContainer(
                    self.synchronization_object,
                    full_docker_hub_name,
                    container_name,
                    self.apps,
                    web_port_tuple,
                    management_port_tuple,
                    self.container_password,
                    files_to_copy_to_container,
                    self.mounts,
                    splunkbase_username,
                    splunkbase_password,
                )
            )

        return new_containers

    def create_mounts(
        self, mounts: list[dict[str, Union[str, bool]]]
    ) -> list[docker.types.Mount]:
        new_mounts = []
        for mount in mounts:
            new_mounts.append(self.create_mount(mount))
        return new_mounts

    def create_mount(self, mount: dict[str, Union[str, bool]]) -> docker.types.Mount:
        return docker.types.Mount(
            source=mount["local_path"],
            target=mount["container_path"],
            type=mount["type"],
            read_only=mount["read_only"],
        )

    # taken from attack_range
    def get_random_password(
        self, password_min_length: int = 16, password_max_length: int = 26
    ) -> str:
        random_source = string.ascii_letters + string.digits
        password = random.choice(string.ascii_lowercase)
        password += random.choice(string.ascii_uppercase)
        password += random.choice(string.digits)

        for i in range(random.randrange(password_min_length, password_max_length)):
            password += random.choice(random_source)

        password_list = list(password)
        random.SystemRandom().shuffle(password_list)
        password = "".join(password_list)
        return password

    def queue_status_thread(self)->None:
        #This will run fo
        while True:      
            if self.synchronization_object.summarize() == False:
                #There are no more tests to run, so we can return from this thread
                return None
            time.sleep(10)

    def setup_image(self, reuse_images: bool, container_name: str) -> None:
        client = docker.client.from_env()
        if not reuse_images:
            #Check to see if the image exists.  If it does, then remove it.  If it does not, then do nothing
            docker_image = None
            try:
                docker_image = client.images.get(container_name)
            except Exception as e:
                #We don't need to do anything, the image did not exist on our system
                #print("Image named [%s] did not exist, so we don't need to try and remove it."%(container_name))
                pass
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
                pull_start_time = timeit.default_timer()
                client.images.pull(container_name)
                pull_finish_time = timeit.default_timer()
                print("Successfully pulled the docker image [%s] in %ss"%
                    (container_name,
                    datetime.timedelta(seconds=pull_finish_time - pull_start_time, microseconds=0) ))

            except Exception as e:
                print("There was an error trying to pull the image [%s]: [%s]"%(container_name,str(e)))
                raise(e)
