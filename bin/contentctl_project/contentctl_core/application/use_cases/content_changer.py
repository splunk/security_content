import re

from dataclasses import dataclass

from contentctl_core.application.factory.object_factory import ObjectFactory, ObjectFactoryInputDto
from contentctl_core.application.adapter.adapter import Adapter


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

        input_dto.adapter.writeObjects(objects)


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

