import abc

class Adapter(abc.ABC):

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
    def writeObjects(self, objects: list, output_folder: str) -> None:
        pass