import abc

from bin.contentctl_project.contentctl_core.application.builder.basic_builder import BasicBuilder
from bin.contentctl_project.contentctl_core.application.builder.detection_builder import DetectionBuilder
from bin.contentctl_project.contentctl_core.application.builder.baseline_builder import BaselineBuilder
from bin.contentctl_project.contentctl_core.application.builder.investigation_builder import InvestigationBuilder
from bin.contentctl_project.contentctl_core.application.builder.story_builder import StoryBuilder
from bin.contentctl_project.contentctl_core.application.builder.playbook_builder import PlaybookBuilder
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentProduct

class Director(abc.ABC):

    @abc.abstractmethod
    def constructDetection(self, builder: DetectionBuilder, path: str, deployments: list, playbooks: list, baselines: list, tests: list, attack_enrichment: dict, macros: list) -> None:
        pass

    @abc.abstractmethod
    def constructBaseline(self, builder: BaselineBuilder, path: str, deployments: list) -> None:
        pass

    @abc.abstractmethod
    def constructDeployment(self, builder: BasicBuilder, path: str) -> None:
        pass

    @abc.abstractmethod
    def constructLookup(self, builder: BasicBuilder, path: str) -> None:
        pass

    @abc.abstractmethod
    def constructMacro(self, builder: BasicBuilder, path: str) -> None:
        pass

    @abc.abstractmethod
    def constructPlaybook(self, builder: PlaybookBuilder, path: str, detections: list) -> None:
        pass

    @abc.abstractmethod
    def constructTest(self, builder: BasicBuilder, path: str) -> None:
        pass

    @abc.abstractmethod
    def constructStory(self, builder: StoryBuilder, path: str, detections: list, baselines: list, investigations: list) -> None:
        pass

    @abc.abstractmethod
    def constructInvestigation(self, builder: InvestigationBuilder, path: str) -> None:
        pass
    
    @abc.abstractmethod
    def constructObjects(self, builder: BasicBuilder, path: str) -> None:
        pass