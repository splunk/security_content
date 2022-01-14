import os

from contentctl.contentctl.application.builder.director import Director
from contentctl.contentctl.application.builder.basic_builder import BasicBuilder
from contentctl.contentctl.application.builder.detection_builder import DetectionBuilder
from contentctl.contentctl.application.builder.story_builder import StoryBuilder
from contentctl.contentctl.application.builder.investigation_builder import InvestigationBuilder
from contentctl.contentctl.application.builder.baseline_builder import BaselineBuilder
from contentctl.contentctl.domain.entities.enums.enums import SecurityContentType
from contentctl.contentctl.domain.entities.enums.enums import SecurityContentProduct

class SecurityContentDirector(Director):

    def constructDetection(self, builder: DetectionBuilder, path: str, deployments: list, playbooks: list, baselines: list) -> None:
        builder.reset()
        builder.setObject(os.path.join(os.path.dirname(__file__), path))
        builder.addDeployment(deployments)
        builder.addRBA()
        builder.addNesFields()
        builder.addAnnotations()
        builder.addMappings()
        builder.addBaseline(baselines)
        builder.addPlaybook(playbooks)


    def constructStory(self, builder: StoryBuilder, path: str, detections: list, baselines: list, investigations: list) -> None:
        builder.reset()
        builder.setObject(os.path.join(os.path.dirname(__file__), path))
        builder.addDetections(detections)
        builder.addInvestigations(investigations)
        builder.addBaselines(baselines)
        builder.addAuthorCompanyName()


    def constructBaseline(self, builder: BaselineBuilder, path: str, deployments: list) -> None:
        builder.reset()
        builder.setObject(os.path.join(os.path.dirname(__file__), path))
        builder.addDeployment(deployments)


    def constructDeployment(self, builder: BasicBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(os.path.join(os.path.dirname(__file__), path), SecurityContentType.deployments)


    def constructLookup(self, builder: BasicBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(os.path.join(os.path.dirname(__file__), path), SecurityContentType.lookups)


    def constructMacro(self, builder: BasicBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(os.path.join(os.path.dirname(__file__), path), SecurityContentType.macros)


    def constructPlaybook(self, builder: BasicBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(os.path.join(os.path.dirname(__file__), path), SecurityContentType.playbooks)


    def constructInvestigation(self, builder: InvestigationBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(os.path.join(os.path.dirname(__file__), path))
        builder.addInputs()
        builder.addLowercaseName()

    def constructObjects(self, builder: BasicBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(os.path.join(os.path.dirname(__file__), path))