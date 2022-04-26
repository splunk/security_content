import os

from dataclasses import dataclass

from bin.contentctl_project.contentctl_core.application.factory.factory import FactoryInputDto, Factory, FactoryOutputDto
from bin.contentctl_project.contentctl_core.application.adapter.adapter import Adapter


@dataclass(frozen=True)
class ReportingInputDto:
    factory_input_dto: FactoryInputDto
    adapter_svg : Adapter
    adapter_attack : Adapter


class Reporting:

    def execute(self, input_dto: ReportingInputDto) -> None:
        factory_output_dto = FactoryOutputDto([],[],[],[],[],[],[],[],[])
        factory = Factory(factory_output_dto)
        factory.execute(input_dto.factory_input_dto)

        input_dto.adapter_svg.writeObjects(factory_output_dto.detections, os.path.join(os.path.dirname(__file__), '../../../../reporting'))
        input_dto.adapter_attack.writeObjects(factory_output_dto.detections, os.path.join(os.path.dirname(__file__), '../../../../../docs/mitre-map'))

        print('Reporting of security content successful.')