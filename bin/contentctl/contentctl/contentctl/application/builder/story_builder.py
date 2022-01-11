import abc

from contentctl.contentctl.domain.entities.security_content_object import SecurityContentObject
from contentctl.contentctl.domain.entities.enums.enums import SecurityContentType


class StoryBuilder(abc.ABC):

    @abc.abstractmethod
    def addDetections(self, detections: list) -> None:
        pass

    @abc.abstractmethod
    def addInvestigations(self, investigations: list) -> None:
        pass

    @abc.abstractmethod
    def addAuthorCompanyName(self) -> None:
        pass

    @abc.abstractmethod
    def addBaselines(self, baselines: list) -> None:
        pass
    
    @abc.abstractmethod
    def addInvestigations(self, investigations: list) -> None:
        pass

    @abc.abstractmethod
    def setObject(self, path: str, type: SecurityContentType) -> None:
        pass

    @abc.abstractmethod
    def reset(self) -> None:
        pass

    @abc.abstractmethod
    def getObject(self) -> SecurityContentObject:
        pass