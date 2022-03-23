

from dataclasses import dataclass

from bin.contentctl_project.contentctl_core.application.factory.factory import FactoryInputDto, Factory, FactoryOutputDto
from bin.contentctl_project.contentctl_core.application.adapter.adapter import Adapter


@dataclass(frozen=True)
class DocGenInputDto:
    output_path: str
    factory_input_dto: FactoryInputDto
    adapter : Adapter


class DocGen:

    def execute(self, input_dto: DocGenInputDto) -> None:
        factory_output_dto = FactoryOutputDto([],[],[],[],[],[],[],[],[])
        factory = Factory(factory_output_dto)
        factory.execute(input_dto.factory_input_dto)

        input_dto.adapter.writeObjects([factory_output_dto.stories, factory_output_dto.detections, factory_output_dto.playbooks], input_dto.output_path)

        print('Documentation generation of security content successful.')