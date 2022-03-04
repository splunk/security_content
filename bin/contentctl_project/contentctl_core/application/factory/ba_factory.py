import os

from dataclasses import dataclass

from contentctl_core.domain.entities.enums.enums import SecurityContentType
from contentctl_core.application.builder.basic_builder import BasicBuilder
from contentctl_core.application.builder.detection_builder import DetectionBuilder
from contentctl_core.application.builder.story_builder import StoryBuilder
from contentctl_core.application.builder.director import Director
from contentctl_core.application.factory.utils.utils import Utils


@dataclass(frozen=True)
class BAFactoryInputDto:
    input_path: str
    basic_builder: BasicBuilder
    detection_builder: DetectionBuilder
    director: Director

@dataclass(frozen=True)
class BAFactoryOutputDto:
     detections: list
     tests: list

class BAFactory():
    input_dto: BAFactoryInputDto
    output_dto: BAFactoryOutputDto

    def __init__(self, output_dto: BAFactoryOutputDto) -> None:
        self.output_dto = output_dto

    def execute(self, input_dto: BAFactoryInputDto) -> None:
        self.input_dto = input_dto

        self.createSecurityContent(SecurityContentType.unit_tests)
        self.createSecurityContent(SecurityContentType.detections)

        

    def createSecurityContent(self, type: SecurityContentType) -> list:
        objects = []
        if type == SecurityContentType.unit_tests:
            files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.input_path, 'tests'))
        else:
            files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.input_path, str(type.name)))

        for file in files:
            if 'ssa__' in file:
                if type == SecurityContentType.detections:
                    self.input_dto.director.constructDetection(self.input_dto.detection_builder, file, [], [], [], self.output_dto.tests, {}, [], [])
                    detection = self.input_dto.detection_builder.getObject()
                    if not detection.deprecated and not detection.experimental:
                        self.output_dto.detections.append(detection)
                elif type == SecurityContentType.unit_tests:
                    self.input_dto.director.constructTest(self.input_dto.basic_builder, file)
                    test = self.input_dto.basic_builder.getObject()
                    self.output_dto.tests.append(test)