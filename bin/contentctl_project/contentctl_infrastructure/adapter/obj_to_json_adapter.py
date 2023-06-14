import os
import json


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
            
            JsonWriter.writeJsonObject(os.path.join(output_path, 'detections.json'), {'detections': obj_array })

            ### Code to be added to contentctl to ship filter macros to macros.json

            array_of_objects = []
    
            for detection in objects:
                detection_dict = detection.dict()
                if "macros" in detection_dict:
                    for macro in detection_dict["macros"]:
                        array_of_objects.append(macro)

            uniques:set[str] = set()
            for obj in array_of_objects:
                if obj.get("arguments",None) != None:
                    uniques.add(json.dumps(obj,sort_keys=True))
                else:
                    obj.pop("arguments")
                    uniques.add(json.dumps(obj, sort_keys=True))
            output = []
            for item in uniques:
                output.append(json.loads(item))

            JsonWriter.writeJsonObject(os.path.join(output_path, 'macros.json'), {'macros': output})

        
        elif type == SecurityContentType.stories:
            obj_array = []
            for story in objects:
                obj_array.append(story.dict(exclude_none=True,
                    exclude =
                    {
                        "investigations": True
                    }
                ))

            JsonWriter.writeJsonObject(os.path.join(output_path, 'stories.json'), {'stories': obj_array })

        elif type == SecurityContentType.baselines:
            obj_array = []
            for baseline in objects:
                obj_array.append(baseline.dict(
                    exclude =
                    {
                        "deployment": True
                    }
                ))

            JsonWriter.writeJsonObject(os.path.join(output_path, 'baselines.json'), {'baselines': obj_array })

        elif type == SecurityContentType.investigations:
            obj_array = []
            for investigation in objects:
                obj_array.append(investigation.dict(exclude_none=True))

            JsonWriter.writeJsonObject(os.path.join(output_path, 'response_tasks.json'), {'response_tasks': obj_array })
        
        elif type == SecurityContentType.lookups:
            obj_array = []
            for lookup in objects:

                obj_array.append(lookup.dict(exclude_none=True))


            JsonWriter.writeJsonObject(os.path.join(output_path, 'lookups.json'), {'lookups': obj_array })

        # elif type == SecurityContentType.macros:      
        #     obj_array = []
        #     for macro in objects:
        #         obj_array.append(macro.dict(exclude_none=True))

        #     JsonWriter.writeJsonObject(os.path.join(output_path, 'macros.json'), {'macros222': obj_array })

            

        elif type == SecurityContentType.deployments:
            obj_array = []
            for deployment in objects:
                obj_array.append(deployment.dict(exclude_none=True))

            JsonWriter.writeJsonObject(os.path.join(output_path, 'deployments.json'), {'deployments': obj_array })

