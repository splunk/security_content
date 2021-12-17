import abc

from contentctl.contentctl.domain.entities.security_content_object import SecurityContentObject
from contentctl.contentctl.domain.entities.enums.enums import SecurityContentType

# https://refactoring.guru/design-patterns/builder

class Builder(abc.ABC):

    @abc.abstractmethod
    def setObject(self, path: str, type: SecurityContentType) -> None:
        pass

    @abc.abstractmethod
    def addDeployment(self, deployments: list) -> None:
        pass

    @abc.abstractmethod
    def addRBA(self) -> None:
        pass

    @abc.abstractmethod
    def addAnnotations(self) -> None:
        pass

    @abc.abstractmethod
    def addPlaybook(self, playbooks: list) -> None:
        pass

    @abc.abstractmethod
    def addBaseline(self, baselines: list) -> None:
        pass

    @abc.abstractmethod
    def addDetections(self, detections: list) -> None:
        pass

    @abc.abstractmethod
    def addInvestigations(self, investigations: list) -> None:
        pass

    @abc.abstractmethod
    def reset(self) -> None:
        pass

    @abc.abstractmethod
    def getResult(self) -> SecurityContentObject:
        pass