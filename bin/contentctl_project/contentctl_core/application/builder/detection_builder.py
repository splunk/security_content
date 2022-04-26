import abc

from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentProduct
from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType

# https://refactoring.guru/design-patterns/builder

class DetectionBuilder(abc.ABC):

    @abc.abstractmethod
    def addDeployment(self, deployments: list) -> None:
        pass

    @abc.abstractmethod
    def addRBA(self) -> None:
        pass

    @abc.abstractmethod
    def addNesFields(self) -> None:
        pass

    @abc.abstractmethod
    def addMappings(self) -> None:
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
    def addUnitTest(self, tests: list) -> None:
        pass

    @abc.abstractmethod
    def addMitreAttackEnrichment(self) -> None:
        pass

    @abc.abstractmethod
    def addMacros(self, macros: list) -> None:
        pass

    @abc.abstractmethod
    def addLookups(self, lookups: list) -> None:
        pass

    @abc.abstractmethod
    def addCve(self) -> None:
        pass

    @abc.abstractmethod
    def addSplunkApp(self) -> None:
        pass

    @abc.abstractmethod
    def setObject(self, path: str) -> None:
        pass

    @abc.abstractmethod
    def reset(self) -> None:
        pass

    @abc.abstractmethod
    def getObject(self) -> SecurityContentObject:
        pass