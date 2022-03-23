import re

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
            self.ssa_check_observables_exists_in_search(factory_output_dto.detections)        


        # validate detections

        # validate tests
        self.validate_detection_exist_for_test(factory_output_dto.tests, factory_output_dto.detections)
        

    def validate_detection_exist_for_test(self, tests : list, detections: list) -> None:
        for test in tests:
            found_detection = False
            for detection in detections:
                if test.tests[0].file in detection.file_path:
                     found_detection = True

            if not found_detection:
                ValueError("detection doesn't exist for test file: " + test.name)

    def ssa_check_observables_exists_in_search(self, detections: list) -> None:
        for detection in detections:
            if 'ssa_' in detection.file_path:
                regex_patterns = [
                    r'([a-z._]+)=lower\(ucast\(map_get\(input_event,\s?\"([a-z._]+)',
                    r'([a-z._]+)=ucast\(map_get\(input_event,\s?"([a-z._]+)'
                ]
                parsed_fields = list()

                for regex_pattern in regex_patterns:
                    pattern = re.compile(regex_pattern)
                    for match in pattern.finditer(detection.search):
                        if str(match.group(1)) != str(match.group(2)):
                            raise ValueError('Please do not rename input field ' + str(match.group(2)) + ' to ' + str(match.group(1)) + ' for detection: ' + detection.name)
                        else:
                            parsed_fields.append(str(match.group(1)))

                for observable in detection.tags.observable:
                    if not observable['name'] in parsed_fields:
                        raise ValueError('Observable ' + observable['name'] + ' not used in search for detection: ' + detection.name)
