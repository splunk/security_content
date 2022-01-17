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

    def writeObjects(self, objects: list) -> None:
        for object in objects:
            file_path = object['file_path']
            object.pop('file_path')
            object.pop('deprecated')
            YmlWriter.writeYmlFile(file_path, object)

    # def convertNameToFileName(self, obj: dict):
    #     file_name = obj['name'] \
    #         .replace(' ', '_') \
    #         .replace('-','_') \
    #         .replace('.','_') \
    #         .replace('/','_') \
    #         .lower()
    #     file_name = file_name + '.yml'
    #     return file_name