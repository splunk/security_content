import abc

from contentctl.contentctl.application.builder.basic_builder import BasicBuilder
from contentctl.contentctl.application.builder.detection_builder import DetectionBuilder
from contentctl.contentctl.application.builder.baseline_builder import BaselineBuilder
from contentctl.contentctl.application.builder.investigation_builder import InvestigationBuilder
from contentctl.contentctl.application.builder.story_builder import StoryBuilder
from contentctl.contentctl.domain.entities.enums.enums import SecurityContentProduct

class Director(abc.ABC):

    @abc.abstractmethod
    def constructDetection(self, builder: DetectionBuilder, path: str, deployments: list, playbooks: list, baselines: list) -> None:
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
    def constructPlaybook(self, builder: BasicBuilder, path: str) -> None:
        pass

    @abc.abstractmethod
    def constructStory(self, builder: StoryBuilder, path: str, detections: list, baselines: list, investigations: list) -> None:
        pass

    @abc.abstractmethod
    def constructInvestigation(self, builder: InvestigationBuilder, path: str) -> None:
        pass
    