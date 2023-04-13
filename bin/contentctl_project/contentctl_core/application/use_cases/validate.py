

from dataclasses import dataclass

from pydantic import ValidationError
from typing import Union

from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentProduct
from bin.contentctl_project.contentctl_core.application.factory.factory import FactoryInputDto, Factory, FactoryOutputDto
from bin.contentctl_project.contentctl_core.application.factory.ba_factory import BAFactoryInputDto, BAFactory, BAFactoryOutputDto


@dataclass(frozen=True)
class ValidateInputDto:
    factory_input_dto: Union[FactoryInputDto,None]
    ba_factory_input_dto: Union[BAFactoryInputDto,None]
    product: SecurityContentProduct


class Validate:

    def execute(self, input_dto: ValidateInputDto) -> None:
        if input_dto.product == SecurityContentProduct.ESCU:
            factory_output_dto = FactoryOutputDto([],[],[],[],[],[],[],[])
            factory = Factory(factory_output_dto)
            factory.execute(input_dto.factory_input_dto)

        elif input_dto.product == SecurityContentProduct.SSA:
            factory_output_dto = BAFactoryOutputDto([])
            factory = BAFactory(factory_output_dto)
            factory.execute(input_dto.ba_factory_input_dto)        


        # validate detections
        
        print('Validation of security content successful.')
        