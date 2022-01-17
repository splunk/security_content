
from dataclasses import dataclass

from contentctl_core.application.factory.object_factory import ObjectFactory, ObjectFactoryInputDto
from contentctl_core.application.adapter.adapter import Adapter


@dataclass(frozen=True)
class ContentOrganizerInputDto:
    adapter : Adapter
    factory_input_dto : ObjectFactoryInputDto
    output_path : str


class ContentOrganizer:

    def execute(self, input_dto: ContentOrganizerInputDto) -> None:
        objects = list()
        factory = ObjectFactory(objects)
        factory.execute(input_dto.factory_input_dto)

        input_dto.adapter.writeObjects(objects, input_dto.output_path)