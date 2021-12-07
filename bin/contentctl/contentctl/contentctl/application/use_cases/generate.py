import abc
import os 

from dataclasses import dataclass

from contentctl.contentctl.application.repositories.security_content import SecurityContentRepository
from contentctl.contentctl.domain.entities.enums.enums import SecurityContentType
from contentctl.contentctl.domain.entities.detection import Detection
from contentctl.contentctl.application.use_cases.utils.utils import Utils

@dataclass(frozen=True)
class GenerateInputDto:
    input_path: str
    output_path: str


@dataclass(frozen=True)
class GenerateOutputDto:
    message: str


class GenerateOutputBoundary(abc.ABC):
    @abc.abstractmethod
    def present(self, output_dto: GenerateOutputDto) -> None:
        pass


class Generate:
    def __init__(self, output_boundary: GenerateOutputBoundary, security_content_repo: SecurityContentRepository) -> None:
        self.output_boundary = output_boundary
        self.security_content_repository = security_content_repo

    def execute(self, input_dto: GenerateInputDto) -> None:
        self.input_dto = input_dto
        detections = self.read_security_content_objects(SecurityContentType.detections)

    def read_security_content_objects(self, type: SecurityContentType) -> list:
        files = Utils.get_all_files_from_directory(os.path.join(self.input_dto.input_path, str(type.name)))
        security_content_objects = []
        for file in files:
            security_content_objects.append(self.security_content_repository.get(file))
