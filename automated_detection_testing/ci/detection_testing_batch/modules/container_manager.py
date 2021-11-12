from collections import OrderedDict
import docker
import docker.types
import random
import splunk_container
import string
from typing import Union

WEB_PORT_STRING = "8000/tcp"
MANAGEMENT_PORT_STRING = "8089/tcp"


class ContainerManager:
    def __init__(
        self,
        container_name_template: str,
        num_containers: int,
        apps: list[dict],
        files_to_copy_to_container:OrderedDict=OrderedDict(),
        web_port_start: int = 8000,
        management_port_start: int = 8089,
        mounts: list[dict[str, Union[str, bool]]] = [],
        container_password: Union[str, None] = None,
        splunkbase_username: Union[str, None] = None,
        splunkbase_password: Union[str, None] = None,
    ):
        self.mounts = self.create_mounts(mounts)
        self.apps = apps
        self.client = docker.from_env()

        if container_password is None:
            self.container_password = self.get_random_password()
        else:
            self.container_password = container_password

        self.create_containers(
            container_name_template,
            num_containers,
            web_port_start,
            management_port_start,
            splunkbase_username,
            splunkbase_password,
        )

    def create_containers(
        self,
        container_name_template: str,
        num_containers: int,
        web_port_start: int,
        management_port_start: int,
        splunkbase_username: Union[str, None] = None,
        splunkbase_password: Union[str, None] = None,
    ) -> list[splunk_container.SplunkContainer]:
        new_containers = []
        for index in range(num_containers):
            container_name = container_name_template % index
            web_port = (WEB_PORT_STRING, web_port_start + index)
            management_port = (MANAGEMENT_PORT_STRING, management_port_start + index)

            new_containers.append(
                splunk_container.SplunkContainer(
                    self.client,
                    container_name,
                    self.apps,
                    web_port,
                    management_port,
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
