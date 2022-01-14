import abc
import os 

from dataclasses import dataclass

from contentctl.contentctl.domain.entities.enums.enums import SecurityContentType
from contentctl.contentctl.domain.entities.detection import Detection
from contentctl.contentctl.application.builder.basic_builder import BasicBuilder
from contentctl.contentctl.application.builder.detection_builder import DetectionBuilder
from contentctl.contentctl.application.builder.story_builder import StoryBuilder
from contentctl.contentctl.application.builder.baseline_builder import BaselineBuilder
from contentctl.contentctl.application.builder.investigation_builder import InvestigationBuilder
from contentctl.contentctl.application.builder.director import Director

@dataclass(frozen=True)
class GenerateInputDto:
    input_path: str
    output_path: str
    basic_builder: BasicBuilder
    detection_builder: DetectionBuilder
    story_builder: StoryBuilder
    baseline_builder: BaselineBuilder
    investigation_builder: InvestigationBuilder
    director: Director


@dataclass(frozen=True)
class GenerateOutputDto:
    message: str


class GenerateOutputBoundary(abc.ABC):
    @abc.abstractmethod
    def present(self, output_dto: GenerateOutputDto) -> None:
        pass


class Generate:
    input_dto: GenerateInputDto

    def __init__(self, output_boundary: GenerateOutputBoundary) -> None:
        self.output_boundary = output_boundary

    def execute(self, input_dto: GenerateInputDto) -> None:
        self.input_dto = input_dto


    def read_security_content_objects(self, type: SecurityContentType) -> list:
        pass
