import abc

from contentctl.contentctl.domain.entities.enums.enums import SecurityContentProduct

# https://refactoring.guru/design-patterns/builder

class DetectionBuilder(abc.ABC):

    @abc.abstractmethod
    def addDeployment(self, deployments: list, product: SecurityContentProduct) -> None:
        pass

    @abc.abstractmethod
    def addRBA(self) -> None:
        pass

    @abc.abstractmethod
    def addNesFields(self) -> None:
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
