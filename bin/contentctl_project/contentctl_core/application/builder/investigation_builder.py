import abc

from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject

class InvestigationBuilder(abc.ABC):

    @abc.abstractmethod
    def setObject(self, path: str) -> None:
        pass

    @abc.abstractmethod
    def reset(self) -> None:
        pass

    @abc.abstractmethod
    def getObject(self) -> SecurityContentObject:
        pass

    @abc.abstractmethod
    def addInputs(self) -> None:
        pass

    @abc.abstractmethod
    def addLowercaseName(self) -> None:
        pass