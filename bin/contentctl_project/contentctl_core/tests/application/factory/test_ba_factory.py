import os
import pytest

from bin.contentctl_project.contentctl_core.application.factory.ba_factory import BAFactory, BAFactoryInputDto, BAFactoryOutputDto
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_director import SecurityContentDirector
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_basic_builder import SecurityContentBasicBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_detection_builder import SecurityContentDetectionBuilder



def test_factory_BA():
    input_path = os.path.join(os.path.dirname(__file__), '../../../../../..')

    input_dto = BAFactoryInputDto(
        input_path,
        SecurityContentBasicBuilder(),
        SecurityContentDetectionBuilder(),
        SecurityContentDirector()
    )

    output_dto = BAFactoryOutputDto([],[])

    factory = BAFactory(output_dto)
    factory.execute(input_dto)
    
    for detection in output_dto.detections:
        if not detection.test:
            raise AssertionError("test file missing for ssa detection: " + detection.name)