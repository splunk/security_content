import abc

from contentctl.contentctl.domain.entities.security_content_object import SecurityContentObject
from contentctl.contentctl.domain.entities.enums.enums import SecurityContentType
class SecurityContentRepository(abc.ABC):

    @abc.abstractmethod
    def get(str, path: str, type: SecurityContentType) -> SecurityContentObject:
        pass

    @abc.abstractmethod
    def convert(self, security_content_obj: SecurityContentObject) -> None:
        pass
