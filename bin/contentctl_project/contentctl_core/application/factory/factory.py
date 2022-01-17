import os

from dataclasses import dataclass

from contentctl_core.domain.entities.enums.enums import SecurityContentProduct
from contentctl_core.domain.entities.enums.enums import SecurityContentType
from contentctl_core.application.builder.basic_builder import BasicBuilder
from contentctl_core.application.builder.detection_builder import DetectionBuilder
from contentctl_core.application.builder.story_builder import StoryBuilder
from contentctl_core.application.builder.baseline_builder import BaselineBuilder
from contentctl_core.application.builder.investigation_builder import InvestigationBuilder
from contentctl_core.application.builder.director import Director
from contentctl_core.application.factory.utils.utils import Utils


@dataclass(frozen=True)
class FactoryInputDto:
    input_path: str
    basic_builder: BasicBuilder
    detection_builder: DetectionBuilder
    story_builder: StoryBuilder
    baseline_builder: BaselineBuilder
    investigation_builder: InvestigationBuilder
    director: Director
    product: SecurityContentProduct


@dataclass(frozen=True)
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


     def __init__(self, output_dto: FactoryOutputDto) -> None:
        self.output_dto = output_dto


     def execute(self, input_dto: FactoryInputDto) -> None:
          self.input_dto = input_dto

          # order matters to load and enrich security content types
          self.createSecurityContent(SecurityContentType.lookups)
          self.createSecurityContent(SecurityContentType.macros)
          self.createSecurityContent(SecurityContentType.deployments)
          self.createSecurityContent(SecurityContentType.playbooks)
          self.createSecurityContent(SecurityContentType.baselines)
          self.createSecurityContent(SecurityContentType.investigations)
          self.createSecurityContent(SecurityContentType.detections)
          self.createSecurityContent(SecurityContentType.stories)


     def createSecurityContent(self, type: SecurityContentType) -> list:
          objects = []
          if type == SecurityContentType.deployments:
               files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.input_path, str(type.name), str(self.input_dto.product.name)))
          else:
               files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.input_path, str(type.name)))
          
          for file in files:
               if type == SecurityContentType.lookups:
                    self.input_dto.director.constructLookup(self.input_dto.basic_builder, file)
                    self.output_dto.lookups.append(self.input_dto.basic_builder.getObject())
               
               elif type == SecurityContentType.macros:
                    self.input_dto.director.constructMacro(self.input_dto.basic_builder, file)
                    self.output_dto.macros.append(self.input_dto.basic_builder.getObject())
               
               elif type == SecurityContentType.deployments:
                    self.input_dto.director.constructDeployment(self.input_dto.basic_builder, file)
                    self.output_dto.deployments.append(self.input_dto.basic_builder.getObject())
               
               elif type == SecurityContentType.playbooks:
                    self.input_dto.director.constructPlaybook(self.input_dto.basic_builder, file)
                    self.output_dto.playbooks.append(self.input_dto.basic_builder.getObject())                    
               
               elif type == SecurityContentType.baselines:
                    self.input_dto.director.constructBaseline(self.input_dto.baseline_builder, file, self.output_dto.deployments)
                    self.output_dto.baselines.append(self.input_dto.baseline_builder.getObject())
               
               elif type == SecurityContentType.investigations:
                    self.input_dto.director.constructInvestigation(self.input_dto.investigation_builder, file)
                    self.output_dto.investigations.append(self.input_dto.investigation_builder.getObject())
               
               elif type == SecurityContentType.detections:
                    self.input_dto.director.constructDetection(self.input_dto.detection_builder, file, 
                         self.output_dto.deployments, self.output_dto.playbooks, self.output_dto.baselines)
                    self.output_dto.detections.append(self.input_dto.detection_builder.getObject())
               
               elif type == SecurityContentType.stories:
                    self.input_dto.director.constructStory(self.input_dto.story_builder, file, 
                         self.output_dto.detections, self.output_dto.baselines, self.output_dto.investigations)
                    self.output_dto.stories.append(self.input_dto.story_builder.getObject())

