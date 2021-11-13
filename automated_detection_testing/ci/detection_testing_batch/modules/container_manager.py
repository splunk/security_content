from collections import OrderedDict
import docker
import docker.types
import random
import splunk_container
import string
import test_driver
from typing import Union

WEB_PORT_STRING = "8000/tcp"
MANAGEMENT_PORT_STRING = "8089/tcp"


class ContainerManager:
    def __init__(
        self,
        test_list: list[str],
        full_docker_hub_name,
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
    ):
        self.synchronization_object = test_driver.TestDriver(test_list, num_containers)

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
        )

        self.run_containers()

    def run_containers(self) -> None:
        for container in self.containers:
            container.thread.run()

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
    ) -> list[splunk_container.SplunkContainer]:
        new_containers = []
        for index in range(num_containers):
            container_name = container_name_template % index
            web_port_tuple = (WEB_PORT_STRING, web_port_start + index)
            management_port_tuple = (
                MANAGEMENT_PORT_STRING,
                management_port_start + index,
            )
            #Get a new client for this container
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
