import sys

from pydantic import ValidationError

from contentctl_core.application.builder.detection_builder import DetectionBuilder
from contentctl_infrastructure.builder.yml_reader import YmlReader
from contentctl_core.domain.entities.detection import Detection
from contentctl_core.domain.entities.story import Story
from contentctl_core.domain.entities.deployment import Deployment
from contentctl_core.domain.entities.macro import Macro
from contentctl_core.domain.entities.lookup import Lookup
from contentctl_core.domain.entities.enums.enums import SecurityContentType
from contentctl_core.domain.entities.enums.enums import AnalyticsType
from contentctl_core.domain.entities.enums.enums import SecurityContentProduct
from contentctl_core.domain.entities.security_content_object import SecurityContentObject


class SecurityContentDetectionBuilder(DetectionBuilder):
    security_content_obj : SecurityContentObject
    
    def setObject(self, path: str) -> None:
        yml_dict = YmlReader.load_file(path)
        yml_dict["tags"]["name"] = yml_dict["name"]
        try:
            self.security_content_obj = Detection.parse_obj(yml_dict)
        except ValidationError as e:
            print('Validation Error for file ' + path)
            print(e)
            sys.exit(1)

    def addDeployment(self, deployments: list) -> None:
        matched_deployments = []

        for d in deployments:
            d_tags = dict(d.tags)
            for d_tag in d_tags.keys():
                for attr in dir(self.security_content_obj):
                    if not (attr.startswith('__') or attr.startswith('_')):
                        if attr == d_tag:
                            if type(self.security_content_obj.__getattribute__(attr)) is str:
                                attr_values = [self.security_content_obj.__getattribute__(attr)]
                            else:
                                attr_values = self.security_content_obj.__getattribute__(attr)
                            
                            for attr_value in attr_values:
                                if attr_value == d_tags[d_tag]:
                                    matched_deployments.append(d)

        if len(matched_deployments) == 0:
             self.security_content_obj.deployment = None
        else:
            self.security_content_obj.deployment = matched_deployments[-1]


    def addRBA(self) -> None:

        risk_objects = []
        risk_object_user_types = {'user', 'username', 'email address'}
        risk_object_system_types = {'device', 'endpoint', 'hostname', 'ip address'}

        if hasattr(self.security_content_obj.tags, 'observable') and hasattr(self.security_content_obj.tags, 'risk_score'):
            for entity in self.security_content_obj.tags.observable:
                risk_object = dict()
                if entity['type'].lower() in risk_object_user_types:
                    for r in entity['role']:
                        if 'attacker' == r.lower() or 'victim' ==r.lower():
                            risk_object['risk_object_type'] = 'user'
                            risk_object['risk_object_field'] = entity['name']
                            risk_object['risk_score'] = self.security_content_obj.tags.risk_score
                            risk_objects.append(risk_object)

                elif entity['type'].lower() in risk_object_system_types:
                    for r in entity['role']:
                        if 'attacker' == r.lower() or 'victim' ==r.lower():
                            risk_object['risk_object_type'] = 'system'
                            risk_object['risk_object_field'] = entity['name']
                            risk_object['risk_score'] = self.security_content_obj.tags.risk_score
                            risk_objects.append(risk_object)
                else:
                    risk_object['threat_object_field'] = entity['name']
                    risk_object['threat_object_type'] = entity['type'].lower()
                    risk_objects.append(risk_object)
                    continue

        if self.security_content_obj.tags.risk_score >= 80:
            self.security_content_obj.tags.risk_severity = 'high'
        elif (self.security_content_obj.tags.risk_score >= 50 and self.security_content_obj.tags.risk_score <= 79):
            self.security_content_obj.tags.risk_severity = 'medium'
        else:
            self.security_content_obj.tags.risk_severity = 'low'

        self.security_content_obj.risk = risk_objects


    def addNesFields(self) -> None:
        nes_fields_matches = []
        if self.security_content_obj.deployment:
            if self.security_content_obj.deployment.notable:
                for nes_field in self.security_content_obj.deployment.notable.nes_fields:
                    if (self.security_content_obj.search.find(nes_field + ' ') != -1):
                        nes_fields_matches.append(nes_field)
            
                self.security_content_obj.deployment.notable.nes_fields = nes_fields_matches


    def addMappings(self) -> None:
        keys = ['mitre_attack', 'kill_chain_phases', 'cis20', 'nist']
        mappings = {}
        for key in keys:
            if key == 'mitre_attack':
                if getattr(self.security_content_obj.tags, 'mitre_attack_id'):
                    mappings[key] = getattr(self.security_content_obj.tags, 'mitre_attack_id')
            elif getattr(self.security_content_obj.tags, key):
                mappings[key] = getattr(self.security_content_obj.tags, key)
        self.security_content_obj.mappings = mappings


    def addAnnotations(self) -> None:
        annotations = {}
        annotation_keys = ['mitre_attack', 'kill_chain_phases', 'cis20', 'nist', 
            'analytic_story', 'observable', 'context', 'impact', 'confidence', 'cve']
        for key in annotation_keys:
            if key == 'mitre_attack':
                if getattr(self.security_content_obj.tags, 'mitre_attack_id'):
                    annotations[key] = getattr(self.security_content_obj.tags, 'mitre_attack_id')
            try:
                if getattr(self.security_content_obj.tags, key):
                    annotations[key] = getattr(self.security_content_obj.tags, key)
            except AttributeError as e:
                continue
        self.security_content_obj.annotations = annotations    


    def addPlaybook(self, playbooks: list) -> None:
        matched_playbooks = []
        for playbook in playbooks:
            if playbook.tags.detections:
                for detection in playbook.tags.detections:
                    if detection == self.security_content_obj.name:
                        matched_playbooks.append(playbook)

        self.security_content_obj.playbooks = matched_playbooks


    def addBaseline(self, baselines: list) -> None:
        matched_baselines = []
        for baseline in baselines:
            for detection in baseline.tags.detections:
                if detection == self.security_content_obj.name:
                    matched_baselines.append(baseline)

        self.security_content_obj.baselines = matched_baselines


    def addUnitTest(self, tests: list) -> None:
        for test in tests:
            if test.tests[0].name == self.security_content_obj.name:
                self.security_content_obj.test = test
                return


    def reset(self) -> None:
        self.security_content_obj = None


    def getObject(self) -> SecurityContentObject:
        return self.security_content_obj