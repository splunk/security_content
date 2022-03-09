import abc

from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject

# https://refactoring.guru/design-patterns/builder

class PlaybookBuilder(abc.ABC):

    @abc.abstractmethod
    def setObject(self, path: str) -> None:
        pass

    @abc.abstractmethod
    def addDetections(self, detections : list) -> None:
        pass

    @abc.abstractmethod
    def reset(self) -> None:
        pass

    @abc.abstractmethod
    def getObject(self) -> SecurityContentObject:
        pass
