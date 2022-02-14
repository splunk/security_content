import os


from contentctl_core.application.adapter.adapter import Adapter
from contentctl_infrastructure.adapter.json_writer import JsonWriter


class ObjToJsonAdapter(Adapter):

    def writeHeaders(self, output_folder: str) -> None:
        pass


    def writeDetections(self, detections: list, output_folder: str) -> None:
        obj_array = []
        for detection in detections:
            obj_array.append(detection.dict(
                exclude =
                {
                    "deprecated": True,
                    "experimental": True,
                    "annotations": True,
                    "risk": True,
                    "playbooks": True,
                    "baselines": True,
                    "mappings": True,
                    "test": True,
                    "deployment": True
                }
            ))
        
        JsonWriter.writeJsonObject(os.path.join(output_folder, 'detections.json'), obj_array)


    def writeStories(self, stories: list, output_folder: str) -> None:
        obj_array = []
        for story in stories:
           obj_array.append(story.dict(exclude_none=True))

        JsonWriter.writeJsonObject(os.path.join(output_folder, 'stories.json'), obj_array)


    def writeBaselines(self, baselines: list, output_folder: str) -> None:
        obj_array = []
        for baseline in baselines:
            obj_array.append(baseline.dict(
                exclude =
                {
                    "deployment": True
                }
            ))

        JsonWriter.writeJsonObject(os.path.join(output_folder, 'baselines.json'), obj_array)


    def writeInvestigations(self, investigations: list, output_folder: str) -> None:
        obj_array = []
        for investigation in investigations:
           obj_array.append(investigation.dict(exclude_none=True))

        JsonWriter.writeJsonObject(os.path.join(output_folder, 'response_tasks.json'), obj_array)


    def writeLookups(self, lookups: list, output_folder: str, security_content_path: str) -> None:
        obj_array = []
        for lookup in lookups:
           obj_array.append(lookup.dict(exclude_none=True))

        JsonWriter.writeJsonObject(os.path.join(output_folder, 'lookups.json'), obj_array)


    def writeMacros(self, macros: list, output_folder: str) -> None:
        obj_array = []
        for macro in macros:
           obj_array.append(macro.dict(exclude_none=True))

        JsonWriter.writeJsonObject(os.path.join(output_folder, 'macros.json'), obj_array)


    def writeDeployments(self, deployments: list, output_folder: str) -> None:
        obj_array = []
        for deployment in deployments:
           obj_array.append(deployment.dict(exclude_none=True))

        JsonWriter.writeJsonObject(os.path.join(output_folder, 'deployments.json'), obj_array)


    def writeObjectsInPlace(self, objects: list) -> None:
        pass


    def writeObjects(self, objects: list, output_path: str) -> None:
        pass