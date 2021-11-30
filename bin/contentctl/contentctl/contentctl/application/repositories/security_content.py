import abc

from contentctl.contentctl.domain.entities.security_content_object import SecurityContentObject

class SecurityContentRepository(abc.ABC):

    @abc.abstractmethod
    def get(self, input_path: str) -> SecurityContentObject:
        pass

    @abc.abstractmethod
    def save(self,security_content_obj: SecurityContentObject) -> None:
        pass