
from dataclasses import dataclass
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentProduct

from contentctl_core.application.adapter.adapter import Adapter
from contentctl_core.application.factory.factory import FactoryInputDto, Factory, FactoryOutputDto


@dataclass(frozen=True)
class GenerateInputDto:
    output_path: str
    factory_input_dto: FactoryInputDto
    adapter : Adapter


class Generate:

    def execute(self, input_dto: GenerateInputDto) -> None:

        factory_output_dto = FactoryOutputDto([],[],[],[],[],[],[],[])
        factory = Factory(factory_output_dto)
        factory.execute(input_dto.factory_input_dto)

        if input_dto.factory_input_dto.product == SecurityContentProduct.ESCU:
            input_dto.adapter.writeHeaders(input_dto.output_path)
            input_dto.adapter.writeDetections(factory_output_dto.detections, input_dto.output_path)
            input_dto.adapter.writeStories(factory_output_dto.stories, input_dto.output_path)
            input_dto.adapter.writeBaselines(factory_output_dto.baselines, input_dto.output_path)
            input_dto.adapter.writeInvestigations(factory_output_dto.investigations, input_dto.output_path)
            input_dto.adapter.writeLookups(factory_output_dto.lookups, input_dto.output_path, input_dto.factory_input_dto.input_path)
            input_dto.adapter.writeMacros(factory_output_dto.macros, input_dto.output_path)
        elif input_dto.factory_input_dto.product == SecurityContentProduct.BA:
            pass
