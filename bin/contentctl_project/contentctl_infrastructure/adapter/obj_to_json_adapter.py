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
                        "deployment": True,
                        "file_path": True
                    }
                ))
            obj_dict={}
            obj_dict['detections'] = obj_array
            JsonWriter.writeJsonObject(os.path.join(output_path, 'detections.json'), obj_dict)
        
        elif type == SecurityContentType.stories:
            obj_array = []
            for story in objects:
                obj_array.append(story.dict(exclude_none=True))

            obj_dict={}
            obj_dict['stories'] = obj_array
            JsonWriter.writeJsonObject(os.path.join(output_path, 'stories.json'), obj_dict)

        elif type == SecurityContentType.baselines:
            obj_array = []
            for baseline in objects:
                obj_array.append(baseline.dict(
                    exclude =
                    {
                        "deployment": True
                    }
                ))
            obj_dict={}
            obj_dict['baselines'] = obj_array
            JsonWriter.writeJsonObject(os.path.join(output_path, 'baselines.json'), obj_dict)

        elif type == SecurityContentType.investigations:
            obj_array = []
            for investigation in objects:
                obj_array.append(investigation.dict(exclude_none=True))
            obj_dict={}
            obj_dict['response_tasks'] = obj_array
            JsonWriter.writeJsonObject(os.path.join(output_path, 'response_tasks.json'), obj_dict)
        
        elif type == SecurityContentType.lookups:
            obj_array = []
            for lookup in objects:
                obj_array.append(lookup.dict(exclude_none=True))

            obj_dict={}
            obj_dict['lookups'] = obj_array
            JsonWriter.writeJsonObject(os.path.join(output_path, 'lookups.json'), obj_dict)

        elif type == SecurityContentType.macros:      
            obj_array = []
            for macro in objects:
                obj_array.append(macro.dict(exclude_none=True))
            obj_dict={}
            obj_dict['macros'] = obj_array
            JsonWriter.writeJsonObject(os.path.join(output_path, 'macros.json'), obj_dict)

        elif type == SecurityContentType.deployments:
            obj_array = []
            for deployment in objects:
                obj_array.append(deployment.dict(exclude_none=True))
            obj_dict={}
            obj_dict['deployments'] = obj_array
            JsonWriter.writeJsonObject(os.path.join(output_path, 'deployments.json'), obj_dict)

