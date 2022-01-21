import abc

class Adapter(abc.ABC):

    @abc.abstractmethod
    def writeHeaders(self, output_folder: str) -> None:
        pass

    @abc.abstractmethod
    def writeDetections(self, detections: list, output_folder: str) -> None:
        pass

    @abc.abstractmethod
    def writeStories(self, stories: list, output_folder: str) -> None:
        pass

    @abc.abstractmethod
    def writeBaselines(self, baselines: list, output_folder: str) -> None:
        pass

    @abc.abstractmethod
    def writeInvestigations(self, investigations: list, output_folder: str) -> None:
        pass

    @abc.abstractmethod
    def writeLookups(self, lookups: list, output_folder: str, security_content_path: str) -> None:
        pass

    @abc.abstractmethod
    def writeMacros(self, macros: list, output_folder: str) -> None:
        pass

    @abc.abstractmethod
    def writeObjectsInPlace(self, objects: list) -> None:
        pass

    @abc.abstractmethod
    def writeObjects(self, objects: list, security_content_folder: str) -> None:
        pass