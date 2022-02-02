import os

from contentctl_infrastructure.adapter.yml_writer import YmlWriter
from contentctl_core.application.adapter.adapter import Adapter


class ObjToYmlAdapter(Adapter):

    def writeHeaders(self, output_folder: str) -> None:
        pass

    def writeDetections(self, detections: list, output_folder: str) -> None:
        pass

    def writeStories(self, stories: list, output_folder: str) -> None:
        pass

    def writeBaselines(self, baselines: list, output_folder: str) -> None:
        pass

    def writeInvestigations(self, investigations: list, output_folder: str) -> None:
        pass

    def writeLookups(self, lookups: list, output_folder: str, security_content_path: str) -> None:
        pass

    def writeMacros(self, macros: list, output_folder: str) -> None:
        pass

    def writeObjectsInPlace(self, objects: list) -> None:
        for object in objects:
            file_path = object['file_path']
            object.pop('file_path')
            object.pop('deprecated')
            object.pop('experimental') 
            YmlWriter.writeYmlFile(file_path, object)

    def writeObjects(self, objects: list, security_content_folder: str) -> None:
        for obj in objects:
            file_name = "ssa___" + self.convertNameToFileName(obj)
            file_path = os.path.join(security_content_folder, file_name)
            # remove unncessary fields
            YmlWriter.writeYmlFile(file_path, object)

    def convertNameToFileName(self, obj: dict):
        file_name = obj['name'] \
            .replace(' ', '_') \
            .replace('-','_') \
            .replace('.','_') \
            .replace('/','_') \
            .lower()
        file_name = file_name + '.yml'
        return file_name