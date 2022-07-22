import os

from dataclasses import dataclass

from bin.contentctl_project.contentctl_core.application.builder.basic_builder import BasicBuilder
from bin.contentctl_project.contentctl_core.application.builder.director import Director
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_core.application.factory.utils.utils import Utils

@dataclass(frozen=True)
class ObjectFactoryInputDto:
    input_path: str
    builder: BasicBuilder
    director: Director


class ObjectFactory():
    objects: list

    def __init__(self, objects: list) -> None:
        self.objects = objects

    def execute(self, input_dto: ObjectFactoryInputDto) -> None:
        self.input_path = input_dto.input_path

        files = Utils.get_all_yml_files_from_directory(input_dto.input_path)
        for file in files:
            input_dto.director.constructObjects(input_dto.builder, file)
            self.objects.append(input_dto.builder.getObject())