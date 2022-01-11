import os

from contentctl.contentctl.application.factory.factory import FactoryInputDto
from contentctl.contentctl.application.factory.factory import FactoryOutputDto
from contentctl.contentctl.application.factory.factory import Factory
from contentctl_infrastructure.contentctl_infrastructure.builder.security_content_director import SecurityContentDirector
from contentctl_infrastructure.contentctl_infrastructure.builder.security_content_basic_builder import SecurityContentBasicBuilder
from contentctl_infrastructure.contentctl_infrastructure.builder.security_content_detection_builder import SecurityContentDetectionBuilder
from contentctl_infrastructure.contentctl_infrastructure.builder.security_content_story_builder import SecurityContentStoryBuilder
from contentctl.contentctl.domain.entities.enums.enums import SecurityContentProduct
from contentctl_infrastructure.contentctl_infrastructure.builder.security_content_investigation_builder import SecurityContentInvestigationBuilder
from contentctl_infrastructure.contentctl_infrastructure.builder.security_content_baseline_builder import SecurityContentBaselineBuilder


def test_factory_ESCU():
    input_path = os.path.join(os.path.dirname(__file__), '../../../../../../..')

    input_dto = FactoryInputDto(
        input_path,
        SecurityContentBasicBuilder(),
        SecurityContentDetectionBuilder(),
        SecurityContentStoryBuilder(),
        SecurityContentBaselineBuilder(),
        SecurityContentInvestigationBuilder(),
        SecurityContentDirector(),
        SecurityContentProduct.ESCU
    )

    output_dto = FactoryOutputDto([],[],[],[],[],[],[],[])

    factory = Factory(output_dto)
    factory.execute(input_dto)

    print(len(output_dto.detections))
