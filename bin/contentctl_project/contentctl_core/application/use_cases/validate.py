

from dataclasses import dataclass

from pydantic import ValidationError

from contentctl_core.application.factory.factory import FactoryInputDto, Factory, FactoryOutputDto


@dataclass(frozen=True)
class ValidateInputDto:
    factory_input_dto: FactoryInputDto


class Validate:

    def execute(self, input_dto: ValidateInputDto) -> None:

        factory_output_dto = FactoryOutputDto([],[],[],[],[],[],[],[],[])
        factory = Factory(factory_output_dto)
        factory.execute(input_dto.factory_input_dto)

        # validate detections

        # validate tests
        self.validate_detection_exist_for_test(factory_output_dto.tests, factory_output_dto.detections)
        

    def validate_detection_exist_for_test(self, tests : list, detections: list):
        for test in tests:
            found_detection = False
            for detection in detections:
                if test.tests[0].file in detection.file_path:
                     found_detection = True

            if not found_detection:
                ValueError("detection doesn't exist for test file: " + test.name)