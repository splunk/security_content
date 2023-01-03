import os
import sys

from pydantic import ValidationError
from dataclasses import dataclass
import pathlib
from typing import Tuple
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentProduct
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_core.application.builder.basic_builder import BasicBuilder
from bin.contentctl_project.contentctl_core.application.builder.detection_builder import DetectionBuilder
from bin.contentctl_project.contentctl_core.application.builder.story_builder import StoryBuilder
from bin.contentctl_project.contentctl_core.application.builder.baseline_builder import BaselineBuilder
from bin.contentctl_project.contentctl_core.application.builder.investigation_builder import InvestigationBuilder
from bin.contentctl_project.contentctl_core.application.builder.playbook_builder import PlaybookBuilder
from bin.contentctl_project.contentctl_core.application.builder.director import Director
from bin.contentctl_project.contentctl_core.application.factory.utils.utils import Utils
from bin.contentctl_project.contentctl_core.domain.entities.link_validator import LinkValidator
from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject

@dataclass(frozen=True)
class FactoryInputDto:
    input_path: str
    basic_builder: BasicBuilder
    detection_builder: DetectionBuilder
    story_builder: StoryBuilder
    baseline_builder: BaselineBuilder
    investigation_builder: InvestigationBuilder
    playbook_builder: PlaybookBuilder
    director: Director
    attack_enrichment: dict
    force_cached_or_offline: bool = True
    

@dataclass()
class FactoryOutputDto:
     detections: list
     stories: list
     baselines: list
     investigations: list
     playbooks: list
     deployments: list
     macros: list
     lookups: list


class Factory():
     input_dto: FactoryInputDto
     output_dto: FactoryOutputDto
     ids: dict[str,list[pathlib.Path]] = {}

     def __init__(self, output_dto: FactoryOutputDto) -> None:
        self.output_dto = output_dto

     def execute(self, input_dto: FactoryInputDto) -> None:
          self.input_dto = input_dto
          print("Creating Security Content - ESCU. This may take some time...")
          #Accumulate any validation errors that may occur while creating security_contnet
          validation_errors = []
          # order matters to load and enrich security content types
          validation_errors.extend(self.createSecurityContent(SecurityContentType.lookups))
          validation_errors.extend(self.createSecurityContent(SecurityContentType.macros))
          validation_errors.extend(self.createSecurityContent(SecurityContentType.deployments))
          validation_errors.extend(self.createSecurityContent(SecurityContentType.baselines))
          validation_errors.extend(self.createSecurityContent(SecurityContentType.investigations))
          validation_errors.extend(self.createSecurityContent(SecurityContentType.playbooks))
          validation_errors.extend(self.createSecurityContent(SecurityContentType.detections))
          validation_errors.extend(self.createSecurityContent(SecurityContentType.stories))
          validation_errors.extend(Utils.check_ids_for_duplicates(self.ids))
          LinkValidator.print_link_validation_errors()
          
          if len(validation_errors) != 0:
               print(f"There were [{len(validation_errors)}] error(s) found while parsing security_content")
               for ve in validation_errors:
                    file_path = ve[0]
                    error = ve[1]
                    print(f'\nValidation Error for file [{file_path}]:\n{str(error)}')
               raise(Exception("Error(s) validating Security Content"))

     def createSecurityContent(self, type: SecurityContentType) -> list[Tuple[pathlib.Path,  ValidationError]]:
          objects = []
          if type == SecurityContentType.deployments:
               files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.input_path, str(type.name)))
          elif type == SecurityContentType.detections:
               files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.input_path, 'detections'))
          else:
               files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.input_path, str(type.name)))
          
          # Instead of failing on the first error, just keep track of 
          # of all the exceptions that we generate.  These exceptions
          # will be returned from the function and should be printed
          # by the caller.
          validation_errors:list[Tuple[pathlib.Path,  ValidationError]] = []
                    
          already_ran = False
          progress_percent = 0
          type_string = "UNKNOWN TYPE"

          #Non threaded, production version of the construction code
          files_without_ssa = [f for f in files if not f.name.startswith('ssa___')]
          for index,file in enumerate(files_without_ssa):
          
               #Index + 1 because we are zero indexed, not 1 indexed.  This ensures
               # that printouts end at 100%, not some other number 
               progress_percent = ((index+1)/len(files_without_ssa)) * 100
#               try:
               type_string = "UNKNOWN TYPE"
               if type == SecurityContentType.lookups:
                    type_string = "Lookups"
                    self.input_dto.director.constructLookup(self.input_dto.basic_builder, str(file))
                    lookup = self.input_dto.basic_builder.getObject()
                    Utils.add_id(self.ids, lookup, file)
                    self.output_dto.lookups.append(lookup)
               
               elif type == SecurityContentType.macros:
                    type_string = "Macros"
                    self.input_dto.director.constructMacro(self.input_dto.basic_builder, str(file))
                    macro = self.input_dto.basic_builder.getObject()
                    Utils.add_id(self.ids, macro, file)
                    self.output_dto.macros.append(macro)
               
               elif type == SecurityContentType.deployments:
                    type_string = "Deployments"
                    self.input_dto.director.constructDeployment(self.input_dto.basic_builder, str(file))
                    deployment = self.input_dto.basic_builder.getObject()
                    Utils.add_id(self.ids, deployment, file)
                    self.output_dto.deployments.append(deployment)
               
               elif type == SecurityContentType.playbooks:
                    type_string = "Playbooks"
                    self.input_dto.director.constructPlaybook(self.input_dto.playbook_builder, str(file))
                    playbook = self.input_dto.playbook_builder.getObject()
                    Utils.add_id(self.ids, playbook, file)
                    self.output_dto.playbooks.append(playbook)                    
               
               elif type == SecurityContentType.baselines:
                    type_string = "Baselines"
                    self.input_dto.director.constructBaseline(self.input_dto.baseline_builder, str(file), self.output_dto.deployments)
                    baseline = self.input_dto.baseline_builder.getObject()
                    Utils.add_id(self.ids, baseline, file)
                    self.output_dto.baselines.append(baseline)
               
               elif type == SecurityContentType.investigations:
                    type_string = "Investigations"
                    self.input_dto.director.constructInvestigation(self.input_dto.investigation_builder, file)
                    investigation = self.input_dto.investigation_builder.getObject()
                    Utils.add_id(self.ids, investigation, file)
                    self.output_dto.investigations.append(investigation)

               elif type == SecurityContentType.stories:
                    type_string = "Stories"
                    self.input_dto.director.constructStory(self.input_dto.story_builder, str(file), 
                         self.output_dto.detections, self.output_dto.baselines, self.output_dto.investigations)
                    story = self.input_dto.story_builder.getObject()
                    Utils.add_id(self.ids, story, file)
                    self.output_dto.stories.append(story)
          
               elif type == SecurityContentType.detections:
                    type_string = "Detections"
                    self.input_dto.director.constructDetection(self.input_dto.detection_builder, file, 
                         self.output_dto.deployments, self.output_dto.playbooks, self.output_dto.baselines,
                         self.input_dto.attack_enrichment, self.output_dto.macros,
                         self.output_dto.lookups, self.input_dto.force_cached_or_offline)
                    detection = self.input_dto.detection_builder.getObject()
                    Utils.add_id(self.ids, detection, file)
                    self.output_dto.detections.append(detection)

               else:
                    raise Exception(f"Unsupported type: [{type}]")
               
               if (sys.stdout.isatty() and sys.stdin.isatty() and sys.stderr.isatty()) or not already_ran:
                    already_ran = True
                    print(f"\r{f'{type_string} Progress'.rjust(23)}: [{progress_percent:3.0f}%]...", end="", flush=True)
               
               # except ValidationError as e:
               #      validation_errors.append((pathlib.Path(file), e))
               # except Exception as e:
               #      print(f"Unknown exception caught while Creating Security Content: {str(e)}")
               #      sys.exit(1)
                    
               
                   


          print(f"\r{f'{type_string} Progress'.rjust(23)}: [{progress_percent:3.0f}%]...", end="", flush=True)
          print("Done!")

          return validation_errors