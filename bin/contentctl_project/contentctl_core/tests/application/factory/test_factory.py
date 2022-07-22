import os
from re import A
from bin.contentctl_project.contentctl_infrastructure.tests.test_constants import SECURITY_CONTENT_ROOT

from bin.contentctl_project.contentctl_core.application.factory.factory import FactoryInputDto
from bin.contentctl_project.contentctl_core.application.factory.factory import FactoryOutputDto
from bin.contentctl_project.contentctl_core.application.factory.factory import Factory
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_director import SecurityContentDirector
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_basic_builder import SecurityContentBasicBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_detection_builder import SecurityContentDetectionBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_story_builder import SecurityContentStoryBuilder
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentProduct
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_investigation_builder import SecurityContentInvestigationBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_baseline_builder import SecurityContentBaselineBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.attack_enrichment import AttackEnrichment
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_playbook_builder import SecurityContentPlaybookBuilder


def test_factory_ESCU():
    input_path = os.path.join(os.path.dirname(__file__), '../../../../../..')

    input_dto = FactoryInputDto(
        input_path,
        SecurityContentBasicBuilder(),
        SecurityContentDetectionBuilder(),
        SecurityContentStoryBuilder(),
        SecurityContentBaselineBuilder(),
        SecurityContentInvestigationBuilder(),
        SecurityContentPlaybookBuilder(input_path = SECURITY_CONTENT_ROOT),
        SecurityContentDirector(),
        AttackEnrichment.get_attack_lookup(input_path = SECURITY_CONTENT_ROOT)
    )

    output_dto = FactoryOutputDto([],[],[],[],[],[],[],[],[])

    factory = Factory(output_dto)
    factory.execute(input_dto)

