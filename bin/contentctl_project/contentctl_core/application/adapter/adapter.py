import abc

from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType

class Adapter(abc.ABC):

    @abc.abstractmethod
    def writeObjects(self, objects: list, output_path: str, type: SecurityContentType = None) -> None:
        pass
