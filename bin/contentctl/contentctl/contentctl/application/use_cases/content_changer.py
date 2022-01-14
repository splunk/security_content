
from dataclasses import dataclass

from contentctl.contentctl.application.factory.object_factory import ObjectFactory, ObjectFactoryInputDto
from contentctl.contentctl.application.adapter.adapter import Adapter


@dataclass(frozen=True)
class ContentChangerInputDto:
    output_path: str
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

        input_dto.adapter.writeObjects(objects, input_dto.output_path)


    # Define Converter Functions here

    def example_converter_func(self, objects : list) -> None:
        for obj in objects:
            obj['author'] = obj['author'].upper()

