import os
import shutil

from dataclasses import dataclass

from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentProduct, SecurityContentType
from bin.contentctl_project.contentctl_core.application.adapter.adapter import Adapter
from bin.contentctl_project.contentctl_core.application.factory.factory import FactoryInputDto, Factory, FactoryOutputDto
from bin.contentctl_project.contentctl_core.application.factory.ba_factory import BAFactoryInputDto, BAFactory, BAFactoryOutputDto



@dataclass(frozen=True)
class GenerateInputDto:
    output_path: str
    factory_input_dto: FactoryInputDto
    ba_factory_input_dto: BAFactoryInputDto
    adapter : Adapter
    product: SecurityContentProduct


class Generate:

    def execute(self, input_dto: GenerateInputDto) -> None:

        if input_dto.product == SecurityContentProduct.ESCU:
            factory_output_dto = FactoryOutputDto([],[],[],[],[],[],[],[],[])
            factory = Factory(factory_output_dto)
            factory.execute(input_dto.factory_input_dto)
            input_dto.adapter.writeHeaders(input_dto.output_path)
            input_dto.adapter.writeObjects(factory_output_dto.detections, input_dto.output_path, SecurityContentType.detections)
            input_dto.adapter.writeObjects(factory_output_dto.stories, input_dto.output_path, SecurityContentType.stories)
            input_dto.adapter.writeObjects(factory_output_dto.baselines, input_dto.output_path, SecurityContentType.baselines)
            input_dto.adapter.writeObjects(factory_output_dto.investigations, input_dto.output_path, SecurityContentType.investigations)
            input_dto.adapter.writeObjects(factory_output_dto.lookups, input_dto.output_path, SecurityContentType.lookups)
            input_dto.adapter.writeObjects(factory_output_dto.macros, input_dto.output_path, SecurityContentType.macros)
        
        elif input_dto.product == SecurityContentProduct.SSA:
            shutil.rmtree(input_dto.output_path + '/srs/', ignore_errors=True)
            shutil.rmtree(input_dto.output_path + '/complex/', ignore_errors=True)
            os.makedirs(input_dto.output_path + '/complex/')
            os.makedirs(input_dto.output_path + '/srs/')     
            factory_output_dto = BAFactoryOutputDto([],[])
            factory = BAFactory(factory_output_dto)
            factory.execute(input_dto.ba_factory_input_dto)
            input_dto.adapter.writeObjects(factory_output_dto.detections, input_dto.output_path)

        elif input_dto.product == SecurityContentProduct.API:
            factory_output_dto = FactoryOutputDto([],[],[],[],[],[],[],[],[])
            factory = Factory(factory_output_dto)
            factory.execute(input_dto.factory_input_dto)
            input_dto.adapter.writeObjects(factory_output_dto.detections, input_dto.output_path, SecurityContentType.detections)
            input_dto.adapter.writeObjects(factory_output_dto.stories, input_dto.output_path, SecurityContentType.stories)
            input_dto.adapter.writeObjects(factory_output_dto.baselines, input_dto.output_path, SecurityContentType.baselines)
            input_dto.adapter.writeObjects(factory_output_dto.investigations, input_dto.output_path, SecurityContentType.investigations)
            input_dto.adapter.writeObjects(factory_output_dto.lookups, input_dto.output_path, SecurityContentType.lookups)
            input_dto.adapter.writeObjects(factory_output_dto.macros, input_dto.output_path, SecurityContentType.macros)
            input_dto.adapter.writeObjects(factory_output_dto.deployments, input_dto.output_path, SecurityContentType.deployments)

        print('Generate of security content successful.')