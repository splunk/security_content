import os


from bin.contentctl_project.contentctl_core.application.adapter.adapter import Adapter
from bin.contentctl_project.contentctl_infrastructure.adapter.json_writer import JsonWriter
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType


class ObjToJsonAdapter(Adapter):


    def writeObjects(self, objects: list, output_path: str, type: SecurityContentType = None) -> None:
        if type == SecurityContentType.detections:
            obj_array = []
            for detection in objects:
                obj_array.append(detection.dict(exclude_none=True, 
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
            
            JsonWriter.writeJsonObject(os.path.join(output_path, 'detections.json'), obj_array)
        
        elif type == SecurityContentType.stories:
            obj_array = []
            for story in objects:
                obj_array.append(story.dict(exclude_none=True))

            JsonWriter.writeJsonObject(os.path.join(output_path, 'stories.json'), obj_array)

        elif type == SecurityContentType.baselines:
            obj_array = []
            for baseline in objects:
                obj_array.append(baseline.dict(
                    exclude =
                    {
                        "deployment": True
                    }
                ))

            JsonWriter.writeJsonObject(os.path.join(output_path, 'baselines.json'), obj_array)

        elif type == SecurityContentType.investigations:
            obj_array = []
            for investigation in objects:
                obj_array.append(investigation.dict(exclude_none=True))

            JsonWriter.writeJsonObject(os.path.join(output_path, 'response_tasks.json'), obj_array)
        
        elif type == SecurityContentType.lookups:
            obj_array = []
            for lookup in objects:
                obj_array.append(lookup.dict(exclude_none=True))

            JsonWriter.writeJsonObject(os.path.join(output_path, 'lookups.json'), obj_array)

        elif type == SecurityContentType.macros:      
            obj_array = []
            for macro in objects:
                obj_array.append(macro.dict(exclude_none=True))

            JsonWriter.writeJsonObject(os.path.join(output_path, 'macros.json'), obj_array)

        elif type == SecurityContentType.deployments:
            obj_array = []
            for deployment in objects:
                obj_array.append(deployment.dict(exclude_none=True))

            JsonWriter.writeJsonObject(os.path.join(output_path, 'deployments.json'), obj_array)

