import os
import re

from contentctl_infrastructure.adapter.yml_writer import YmlWriter
from contentctl_core.application.adapter.adapter import Adapter
from contentctl_core.domain.entities.enums.enums import SecurityContentType


class ObjToYmlAdapter(Adapter):

    def writeObjectsInPlace(self, objects: list) -> None:
        for object in objects:
            file_path = object['file_path']
            object.pop('file_path')
            object.pop('deprecated')
            object.pop('experimental') 
            YmlWriter.writeYmlFile(file_path, object)


    def writeObjects(self, objects: list, output_path: str, type: SecurityContentType = None) -> None:
        for obj in objects:
            file_name = "ssa___" + self.convertNameToFileName(obj.name)
            if self.isComplexBARule(obj.search):
                file_path = os.path.join(output_path, 'complex', file_name)
            else:
                file_path = os.path.join(output_path, 'srs', file_name)

            # remove unncessary fields
            YmlWriter.writeYmlFile(file_path, obj.dict(
                include =
                    {
                        "name": True,
                        "id": True,
                        "version": True,
                        "description": True,
                        "search": True,
                        "how_to_implement": True,
                        "known_false_positives": True,
                        "references": True,
                        "tags": 
                            {
                                "analytic_story": True,
                                "cis20" : True,
                                "nist": True,
                                "kill_chain_phases": True,
                                "mitre_attack_id": True,
                                "risk_severity": True,
                                "security_domain": True,
                                "required_fields": True
                            },
                        "test": 
                            {
                                "name": True,
                                "tests": {
                                    '__all__': 
                                        {
                                            "name": True,
                                            "file": True,
                                            "pass_condition": True,
                                            "attack_data": {
                                                '__all__': 
                                                {
                                                    "file_name": True,
                                                    "data": True,
                                                    "source": True
                                                }
                                            }
                                        }
                                }
                            }
                    }
                ))



    def writeObjectNewContent(self, object: dict, type: SecurityContentType) -> None:
        if type == SecurityContentType.detections:
            file_path = os.path.join(os.path.dirname(__file__), '../../../../detections', object['source'], self.convertNameToFileName(object['name']))
            test_obj = {}
            test_obj['name'] = object['name'] + ' Unit Test'
            test_obj['tests'] = [
                {
                    'name': object['name'],
                    'file': object['source'] + '/' + self.convertNameToFileName(object['name']),
                    'pass_condition': '| stats count | where count > 0',
                    'earliest_time': '-24h',
                    'latest_time': 'now',
                    'attack_data': [
                        {
                            'file_name': 'UPDATE',
                            'data': 'UPDATE',
                            'source': 'UPDATE',
                            'sourcetype': 'UPDATE'
                        }
                    ]
                }
            ]
            file_path_test = os.path.join(os.path.dirname(__file__), '../../../../tests', object['source'], self.convertNameToFileName(object['name']))
            YmlWriter.writeYmlFile(file_path_test, test_obj)
            object.pop('source')
        elif type == SecurityContentType.stories:
            file_path = os.path.join(os.path.dirname(__file__), '../../../../stories', self.convertNameToFileName(object['name']))

        YmlWriter.writeYmlFile(file_path, object)


    def convertNameToFileName(self, name: str):
        file_name = name \
            .replace(' ', '_') \
            .replace('-','_') \
            .replace('.','_') \
            .replace('/','_') \
            .lower()
        file_name = file_name + '.yml'
        return file_name


    def isComplexBARule(self, search):
        return re.findall("stats|first_time_event|adaptive_threshold", search)


