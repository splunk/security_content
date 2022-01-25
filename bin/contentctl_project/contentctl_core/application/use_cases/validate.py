

from dataclasses import dataclass

from contentctl_core.application.factory.factory import FactoryInputDto, Factory, FactoryOutputDto


@dataclass(frozen=True)
class ValidateInputDto:
    factory_input_dto: FactoryInputDto


class Validate:

    def execute(self, input_dto: ValidateInputDto) -> None:

        factory_output_dto = FactoryOutputDto([],[],[],[],[],[],[],[])
        factory = Factory(factory_output_dto)
        factory.execute(input_dto.factory_input_dto)