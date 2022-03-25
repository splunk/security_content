import re
import uuid

from dataclasses import dataclass

from bin.contentctl_project.contentctl_core.application.factory.object_factory import ObjectFactory, ObjectFactoryInputDto
from bin.contentctl_project.contentctl_core.application.adapter.adapter import Adapter


@dataclass(frozen=True)
class ContentChangerInputDto:
    adapter : Adapter
    factory_input_dto : ObjectFactoryInputDto
    converter_func_name : str


class ContentChanger:

    def execute(self, input_dto: ContentChangerInputDto) -> None:
        objects = list()
        factory = ObjectFactory(objects)
        factory.execute(input_dto.factory_input_dto)

        converter_func = getattr(self, input_dto.converter_func_name)
        converter_func(objects)
    
        input_dto.adapter.writeObjectsInPlace(objects)


    # Define Converter Functions here

    def example_converter_func(self, objects : list) -> None:
        for obj in objects:
            obj['author'] = obj['author'].upper()

    def add_default_risk_values(self, objects : list) -> None:
        for obj in objects:
            if not 'confidence' in obj['tags']:
                obj['tags']['confidence'] = 50
            if not 'impact' in obj['tags']:
                obj['tags']['impact'] = 50
            if not 'risk_score' in obj['tags']:
                obj['tags']['risk_score'] = 25

    def add_unknown_context(self, objects : list) -> None:
        for obj in objects:
            if not 'context' in obj['tags']:
                obj['tags']['context'] = ['Unknown']

    def add_default_message(self, objects : list) -> None:
        for obj in objects:
            if not 'message' in obj['tags']:
                obj['tags']['message'] = 'tbd'

    def add_default_observable(self, objects : list) -> None:
        for obj in objects:
            if not 'observable' in obj['tags'] or ('observable' in obj['tags'] and len(obj['tags']['observable']) == 0):
                observables = []
                regexp_user = re.compile(r'user')
                if regexp_user.search(obj['search']):
                    observables.append({'name': 'user', 'type': 'User', 'role': ['Victim']})
                regexp_user = re.compile(r'dest')
                if regexp_user.search(obj['search']):
                    observables.append({'name': 'dest', 'type': 'Hostname', 'role': ['Victim']})
                if len(observables) == 0:
                    observables.append({'name': 'dest', 'type': 'Other', 'role': ['Other']})
                obj['tags']['observable'] = observables

    def add_default_cis(self, objects : list) -> None:
        for obj in objects:
            if not 'cis20' in obj['tags']:
                obj['tags']['cis20'] = ['CIS 3', 'CIS 5', 'CIS 16']   

    def add_default_nist(self, objects : list) -> None:
        for obj in objects:
            if not 'nist' in obj['tags']:
                obj['tags']['nist'] = ['DE.CM']

    def fix_broken_uuids(self, objects : list) -> None:
        for obj in objects:
            try:
                uuid.UUID(str(obj['id']))
            except:
                obj['id'] = str(uuid.uuid4())

    def fix_wrong_kill_chain_phases(self, objects : list) -> None:
        valid_kill_chain_phases = [
            'Reconnaissance', 'Weaponization', 'Delivery', 
            'Exploitation', 'Installation', 'Command and Control', 
            'Actions on Objectives']
        for obj in objects:
            if 'kill_chain_phases' in obj['tags']:
                for value in obj['tags']['kill_chain_phases']:
                    if value not in valid_kill_chain_phases:
                        obj['tags']['kill_chain_phases'] = ['Exploitation']
                        break

    def add_default_kill_chain_phases(self, objects : list) -> None:
        for obj in objects:
            if 'kill_chain_phases' not in obj['tags']:
                obj['tags']['kill_chain_phases'] = ['Exploitation']
            if obj['tags']['kill_chain_phases'] == ['Privilege Escalation']:
                obj['tags']['kill_chain_phases'] = ['Exploitation']

    def fix_wrong_calculated_risk_score(self, objects : list) -> None:
        for obj in objects:
            calculated_risk_score = (int(obj['tags']['impact']))*(int(obj['tags']['confidence']))/100
            if calculated_risk_score != int(obj['tags']['risk_score']):
                obj['tags']['risk_score'] = calculated_risk_score

    def add_asset_type_to_endpoint_detections(self, objects : list) -> None:
        for obj in objects:
            if 'asset_type' not in obj['tags']:
                if '/endpoint/' in obj['file_path']:
                    obj['tags']['asset_type'] = 'Endpoint'

    def fix_observables(self, objects : list) -> None:
        for obj in objects:
            if 'observable' in obj['tags']:
                for observable in obj['tags']['observable']:
                    if observable['type'] == 'Parent Process':
                        observable['type'] = 'Process'
                    if observable['type'] == 'user':
                        observable['type'] = 'User'
                    if observable['type'] == 'process name':
                        observable['type'] = 'Process'

    def fix_context(self, objects : list) -> None:
        for obj in objects:
            if 'context' in obj['tags']:
                new_context = []
                for context in obj['tags']['context']:
                    if context == 'Stage:Exploitation':
                        context = 'Stage:Execution'
                    new_context.append(context)

                obj['tags']['context'] = list(dict.fromkeys(new_context))

    def add_default_values_deprecated(self, objects : list) -> None:
        for obj in objects:
            if 'context' not in obj['tags']:
                obj['tags']['context'] = ['Unknown']
            if 'message' not in obj['tags']:
                obj['tags']['message'] = 'tbd'
            if 'observable' not in obj['tags']:
                obj['tags']['observable'] = [{'name': 'field', 'type': 'Unknown', 'role': ['Unknown']}]

    def fix_story(self, objects : list) -> None:
        for obj in objects:
            if 'type' not in obj:
                print(obj['name'])
                if isinstance(obj['tags']['analytic_story'], list):
                    obj['tags']['analytic_story'] = obj['tags']['analytic_story'][0]

    def remove_SAAWS(self, objects : list) -> None:
        for obj in objects:
            if 'Splunk Security Analytics for AWS' in obj['tags']['product']:
                obj['tags']['product'].remove('Splunk Security Analytics for AWS')

    def remove_testing_passed(self, objects : list) -> None:
        for obj in objects:
            if 'automated_detection_testing' in obj['tags']:
                obj['tags'].pop('automated_detection_testing')

    def change_test_file_format(self, objects : list) -> None:
        for obj in objects:
            obj['name'] = obj['name'] + ' Unit Test'
            
    def fix_kill_chain(self, objects : list) -> None:
        for obj in objects:
            if 'kill_chain_phases' in obj['tags']:
                if obj['tags']['kill_chain_phases'] == 'Exploitation':
                    obj['tags']['kill_chain_phases'] = ['Exploitation']

    def add_default_confidence_impact_risk_score(self, objects : list) -> None:
        for obj in objects:
            if 'confidence' not in obj['tags']:
                obj['tags']['confidence'] = 50
            if 'impact' not in obj['tags']:
                obj['tags']['impact'] = 50
            if 'risk_score' not in obj['tags']:
                calculated_risk_score = (int(obj['tags']['impact']))*(int(obj['tags']['confidence']))/100
                obj['tags']['risk_score'] = calculated_risk_score

    def fix_cc(self, objects : list) -> None:
        for obj in objects:
            if 'Command & Control' in obj['tags']['analytic_story']:
                obj['tags']['analytic_story'].remove('Command & Control')
                obj['tags']['analytic_story'].append('Command and Control')