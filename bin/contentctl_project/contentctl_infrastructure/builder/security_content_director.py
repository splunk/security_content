import os

from bin.contentctl_project.contentctl_core.application.builder.director import Director
from bin.contentctl_project.contentctl_core.application.builder.basic_builder import BasicBuilder
from bin.contentctl_project.contentctl_core.application.builder.detection_builder import DetectionBuilder
from bin.contentctl_project.contentctl_core.application.builder.story_builder import StoryBuilder
from bin.contentctl_project.contentctl_core.application.builder.investigation_builder import InvestigationBuilder
from bin.contentctl_project.contentctl_core.application.builder.baseline_builder import BaselineBuilder
from bin.contentctl_project.contentctl_core.application.builder.playbook_builder import PlaybookBuilder
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentProduct

class SecurityContentDirector(Director):

    def constructDetection(self, builder: DetectionBuilder, path: str, deployments: list, playbooks: list, baselines: list, tests: list, attack_enrichment: dict, macros: list, lookups: list) -> None:
        builder.reset()
        builder.setObject(os.path.join(os.path.dirname(__file__), path))
        builder.addDeployment(deployments)
        builder.addRBA()
        builder.addNesFields()
        builder.addAnnotations()
        builder.addMappings()
        builder.addBaseline(baselines)
        builder.addPlaybook(playbooks)
        builder.addUnitTest(tests)
        builder.addMitreAttackEnrichment(attack_enrichment)
        builder.addMacros(macros)
        builder.addLookups(lookups)
        builder.addCve()
        builder.addSplunkApp()


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


    def constructPlaybook(self, builder: PlaybookBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(os.path.join(os.path.dirname(__file__), path))
        builder.addDetections()


    def constructTest(self, builder: BasicBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(os.path.join(os.path.dirname(__file__), path), SecurityContentType.unit_tests)


    def constructInvestigation(self, builder: InvestigationBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(os.path.join(os.path.dirname(__file__), path))
        builder.addInputs()
        builder.addLowercaseName()

    def constructObjects(self, builder: BasicBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(os.path.join(os.path.dirname(__file__), path))