import abc

from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType

# https://refactoring.guru/design-patterns/builder

class BasicBuilder(abc.ABC):

    @abc.abstractmethod
    def setObject(self, path: str, type: SecurityContentType) -> None:
        pass

    @abc.abstractmethod
    def reset(self) -> None:
        pass

    @abc.abstractmethod
    def getObject(self) -> SecurityContentObject:
        pass

    