import abc

from contentctl.contentctl.domain.entities.security_content_object import SecurityContentObject

class SecurityContentRepository(abc.ABC):

    @abc.abstractmethod
    def get(str, path: str) -> SecurityContentObject:
        pass

    @abc.abstractmethod
    def convert(self, security_content_obj: SecurityContentObject) -> None:
        pass
