import abc

from contentctl.contentctl.domain.entities.enums.enums import SecurityContentType
from contentctl.contentctl.domain.entities.baseline import Baseline
from contentctl.contentctl.domain.entities.enums.enums import SecurityContentProduct
from contentctl.contentctl.domain.entities.security_content_object import SecurityContentObject


class BaselineBuilder(abc.ABC):

    @abc.abstractmethod
    def addDeployment(self, deployments: list) -> None:
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