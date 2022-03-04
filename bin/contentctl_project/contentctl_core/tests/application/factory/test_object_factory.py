import os


from contentctl_core.domain.entities.enums.enums import SecurityContentType
from contentctl_core.application.factory.object_factory import ObjectFactoryInputDto
from contentctl_core.application.factory.object_factory import ObjectFactory
from contentctl_infrastructure.builder.security_content_object_builder import SecurityContentObjectBuilder
from contentctl_infrastructure.builder.security_content_director import SecurityContentDirector


def test_object_factory():
    input_path = os.path.join(os.path.dirname(__file__), '../../../../../../detections')

    input_dto = ObjectFactoryInputDto(
        input_path,
        SecurityContentObjectBuilder(),
        SecurityContentDirector()
    )

    objects = list()

    factory = ObjectFactory(objects)
    factory.execute(input_dto)

    #assert len(objects) == 959