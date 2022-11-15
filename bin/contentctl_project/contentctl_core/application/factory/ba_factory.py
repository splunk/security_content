import os
import sys
from webbrowser import get



from pydantic import ValidationError
from pydantic.error_wrappers import ErrorWrapper
from dataclasses import dataclass
from typing import Sequence, Tuple
import pathlib

from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_core.domain.entities.detection_tags import DetectionTags
from bin.contentctl_project.contentctl_core.application.builder.basic_builder import BasicBuilder
from bin.contentctl_project.contentctl_core.application.builder.detection_builder import DetectionBuilder
from bin.contentctl_project.contentctl_core.application.builder.story_builder import StoryBuilder
from bin.contentctl_project.contentctl_core.application.builder.director import Director
from bin.contentctl_project.contentctl_core.application.factory.utils.utils import Utils


@dataclass(frozen=True)
class BAFactoryInputDto:
    input_path: str
    basic_builder: BasicBuilder
    detection_builder: DetectionBuilder
    director: Director

@dataclass(frozen=True)
class BAFactoryOutputDto:
     detections: list
     tests: list

class BAFactory():
    input_dto: BAFactoryInputDto
    output_dto: BAFactoryOutputDto
    ids: dict[str,list[pathlib.Path]] = {}

    def __init__(self, output_dto: BAFactoryOutputDto) -> None:
        self.output_dto = output_dto

    def execute(self, input_dto: BAFactoryInputDto) -> None:
        self.input_dto = input_dto
        print("Creating Security Content - SSA. This may take some time...")
        validation_errors = self.createSecurityContent(SecurityContentType.unit_tests)
        validation_errors.extend(self.createSecurityContent(SecurityContentType.detections))
        validation_errors.extend(Utils.check_ids_for_duplicates(self.ids))

        
        if len(validation_errors) != 0:
            print(f"There were [{len(validation_errors)}] error(s) found while parsing security_content")
            for ve in validation_errors:
                file_path = ve[0]
                error = ve[1]
                print(f'\nValidation Error for file [{file_path}]:\n{str(error)}')
            #raise(Exception("Error(s) validating Security Content"))
        

        

    def createSecurityContent(self, type: SecurityContentType) -> list[Tuple[pathlib.Path,  ValidationError]]:
        objects = []
        if type == SecurityContentType.unit_tests:
            files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.input_path, 'tests'))
        else:
            files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.input_path, str(type.name)))

        validation_errors:list[Tuple[pathlib.Path,  ValidationError]] = []

        files_with_ssa = [f for f in files if f.name.startswith('ssa___')]

        already_ran = False
        progress_percent = 0
        type_string = "UNKNOWN TYPE"
        for index,file in enumerate(files_with_ssa):
          
            #Index + 1 because we are zero indexed, not 1 indexed.  This ensures
            # that printouts end at 100%, not some other number 
            progress_percent = ((index+1)/len(files_with_ssa)) * 100
        
            
            progress_percent = ((index+1)/len(files_with_ssa)) * 100
            try:
                type_string = "UNKNOWN TYPE"
                if type == SecurityContentType.detections:
                    type_string = "Detections"    
                    self.input_dto.director.constructDetection(self.input_dto.detection_builder, file, [], [], [], self.output_dto.tests, {}, [], [])
                    detection = self.input_dto.detection_builder.getObject()
                    Utils.add_id(self.ids, detection, file)
                    
                    tag_and_nist_errors = []
                    
                    if detection.tags.cis20 == None:
                        error = TypeError(f"Detection Tags missing cis20 field")
                        tag_and_nist_errors.append(ErrorWrapper(error, loc="cis20"))
                        
                    if detection.tags.nist == None:
                        error = TypeError(f"Detection Tags missing nist field")
                        tag_and_nist_errors.append(ErrorWrapper(error, loc="nist"))
                        
                    if len(tag_and_nist_errors) > 0:
                        raise ValidationError( tag_and_nist_errors , DetectionTags)



                    if not detection.deprecated and not detection.experimental:
                        self.output_dto.detections.append(detection)
                elif type == SecurityContentType.unit_tests:
                    type_string = "Unit Tests"
                    self.input_dto.director.constructTest(self.input_dto.basic_builder, str(file))
                    test = self.input_dto.basic_builder.getObject()
                    Utils.add_id(self.ids, test, file)
                    self.output_dto.tests.append(test)
                else:
                    raise(Exception(f"Unsupported content type: [{type}]"))

                if (sys.stdout.isatty() and sys.stdin.isatty() and sys.stderr.isatty()) or not already_ran:
                    already_ran = True
                    print(f"\r{f'{type_string} Progress'.rjust(23)}: [{progress_percent:3.0f}%]...", end="", flush=True)

            except ValidationError as e:
                validation_errors.append((pathlib.Path(file), e))
            except Exception as e:
                print(f"Unknown exception caught while Creating BA Security Content: {str(e)}")
                sys.exit(1)

        
        

        print(f"\r{f'{type_string} Progress'.rjust(23)}: [{progress_percent:3.0f}%]...", end="", flush=True)                    
        print("Done!")

        return validation_errors