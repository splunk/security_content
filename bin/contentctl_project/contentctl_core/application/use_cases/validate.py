

from dataclasses import dataclass

from pydantic import ValidationError

from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentProduct
from bin.contentctl_project.contentctl_core.application.factory.factory import FactoryInputDto, Factory, FactoryOutputDto
from bin.contentctl_project.contentctl_core.application.factory.ba_factory import BAFactoryInputDto, BAFactory, BAFactoryOutputDto


@dataclass(frozen=True)
class ValidateInputDto:
    factory_input_dto: FactoryInputDto
    ba_factory_input_dto: BAFactoryInputDto
    product: SecurityContentProduct


class Validate:

    def execute(self, input_dto: ValidateInputDto) -> None:
        if input_dto.product == SecurityContentProduct.ESCU:
            factory_output_dto = FactoryOutputDto([],[],[],[],[],[],[],[],[])
            factory = Factory(factory_output_dto)
            factory.execute(input_dto.factory_input_dto)

        elif input_dto.product == SecurityContentProduct.SSA:
            factory_output_dto = BAFactoryOutputDto([],[])
            factory = BAFactory(factory_output_dto)
            factory.execute(input_dto.ba_factory_input_dto)        


        # validate detections

        # validate tests
        self.validate_detection_exist_for_test(factory_output_dto.tests, factory_output_dto.detections)
        
        print('Validation of security content successful.')
        

    def validate_detection_exist_for_test(self, tests : list, detections: list):
        for test in tests:
            found_detection = False
            for detection in detections:
                if test.tests[0].file in detection.file_path:
                     found_detection = True

            if not found_detection:
                ValueError("detection doesn't exist for test file: " + test.name)