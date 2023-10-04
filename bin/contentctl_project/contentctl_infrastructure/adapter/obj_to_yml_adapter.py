import os
import re

from urllib.parse import urlparse

from bin.contentctl_project.contentctl_infrastructure.adapter.yml_writer import YmlWriter
from bin.contentctl_project.contentctl_core.application.adapter.adapter import Adapter
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_infrastructure.adapter.finding_report_writer import FindingReportObject
from bin.contentctl_project.contentctl_core.domain.entities.unit_test_old import UnitTestOld


class ObjToYmlAdapter(Adapter):
    input_path: str

    def __init__(self, input_path:str):
        self.input_path = input_path

    def writeObjectsInPlace(self, objects: list) -> None:
        for object in objects:

            file_path = object['file_path']
            object.pop('file_path')
            object.pop('deprecated')
            object.pop('experimental') 
            YmlWriter.writeYmlFile(file_path, object)


    def writeObjects(self, objects: list, output_path: str, type: SecurityContentType = None) -> None:
        for obj in objects: 
            file_name = "ssa___" + self.convertNameToFileName(obj.name, obj.tags)
            if self.isComplexBARule(obj.search):
                file_path = os.path.join(output_path, 'complex', file_name)
            else:
                file_path = os.path.join(output_path, 'srs', file_name)
            
            # add research object
            RESEARCH_SITE_BASE = 'https://research.splunk.com/'
            research_site_url = RESEARCH_SITE_BASE + obj.source + "/" + obj.id + "/"
            obj.tags.research_site_url = research_site_url

            # add ocsf schema tag
            obj.tags.event_schema = 'ocsf'

            body = FindingReportObject.writeFindingReport(obj)
            
            if obj.test:
                test_dict = {
                    "name": obj.name + " Unit Test",
                    "tests": [obj.test.dict()]
                }
                test_dict["tests"][0]["name"] = obj.name
                for count in range(len(test_dict["tests"][0]["attack_data"])):
                    a = urlparse(test_dict["tests"][0]["attack_data"][count]["data"])
                    test_dict["tests"][0]["attack_data"][count]["file_name"] = os.path.basename(a.path)
                test = UnitTestOld.parse_obj(test_dict)

                obj.test = test

            # create annotations object
            obj.tags.annotations = {
                "analytic_story": obj.tags.analytic_story,
                "cis20": obj.tags.cis20,
                "kill_chain_phases": obj.tags.kill_chain_phases,
                "mitre_attack_id": obj.tags.mitre_attack_id,
                "nist": obj.tags.nist
            }

            obj.runtime = "SPL2"
            obj.internalVersion = 2

            # remove unncessary fields
            YmlWriter.writeYmlFile(file_path, obj.dict(
                exclude_none=True,
                include =
                    {
                        "name": True,
                        "id": True,
                        "eventSchema": True,
                        "version": True,
                        "status": True,
                        "description": True,
                        "search": True,
                        "how_to_implement": True,
                        "known_false_positives": True,
                        "references": True,
                        "runtime": True,
                        "internalVersion": True,
                        "tags": 
                            {
                                #"analytic_story": True,
                                #"cis20" : True,
                                #"nist": True,
                                #"kill_chain_phases": True,
                                "annotations": True,
                                "mappings": True,
                                #"mitre_attack_id": True,
                                "risk_severity": True,
                                "risk_score": True,
                                "security_domain": True,
                                "required_fields": True,
                                "research_site_url": True,
                                "event_schema": True
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

            # Add Finding Report Object
            with open(file_path, 'r') as file:
               data = file.read().replace('--finding_report--', body)

            f = open(file_path, "w")
            f.write(data)
            f.close()       


    def writeObjectNewContent(self, object: dict, type: SecurityContentType) -> None:
        if type == SecurityContentType.detections:
            file_path = os.path.join(self.input_path, 'detections', object['source'], self.convertNameToFileName(object['name'],object['tags']['product']))
            object.pop('source')
        elif type == SecurityContentType.stories:
            file_path = os.path.join(self.input_path, 'stories', self.convertNameToFileName(object['name'],object['tags']['product']))
        else:
            raise(Exception(f"Object Must be Story or Detection, but is not: {object}"))

        YmlWriter.writeYmlFile(file_path, object)


    def convertNameToFileName(self, name: str, product: list):
        file_name = name \
            .replace(' ', '_') \
            .replace('-','_') \
            .replace('.','_') \
            .replace('/','_') \
            .lower()
        if 'Splunk Behavioral Analytics' in product:
            
            file_name = 'ssa___' + file_name + '.yml'
        else:
            file_name = file_name + '.yml'
        return file_name

    def convertNameToTestFileName(self, name: str, product: list):
        file_name = name \
            .replace(' ', '_') \
            .replace('-','_') \
            .replace('.','_') \
            .replace('/','_') \
            .lower()
        if 'Splunk Behavioral Analytics' in product:          
            file_name = 'ssa___' + file_name + '.test.yml'
        else:
            file_name = file_name + '.test.yml'
        return file_name


    def isComplexBARule(self, search):
        return re.findall("stats|first_time_event|adaptive_threshold", search)


