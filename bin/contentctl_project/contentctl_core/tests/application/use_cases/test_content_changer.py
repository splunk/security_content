import os

from bin.contentctl_project.contentctl_core.application.use_cases.content_changer import ContentChanger, ContentChangerInputDto
from bin.contentctl_project.contentctl_core.application.factory.object_factory import ObjectFactoryInputDto
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_object_builder import SecurityContentObjectBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_director import SecurityContentDirector
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_yml_adapter import ObjToYmlAdapter
from bin.contentctl_project.contentctl_infrastructure.builder.yml_reader import YmlReader

def test_content_changer_author_uppercase():

    input_path = os.path.join(os.path.dirname(__file__), 
        'data_content_changer')
    output_path = os.path.join(os.path.dirname(__file__), 
        'data_content_changer_ref')

    factory_input_dto = ObjectFactoryInputDto(
        input_path,
        SecurityContentObjectBuilder(),
        SecurityContentDirector()
    )

    input_dto = ContentChangerInputDto(
        ObjToYmlAdapter(),
        factory_input_dto,
        'example_converter_func'
    )

    content_changer = ContentChanger()
    content_changer.execute(input_dto)

    yml_obj = YmlReader.load_file(os.path.join(output_path, 'attempted_credential_dump_from_registry_via_reg_exe.yml'))

    assert yml_obj['author'] == 'PATRICK BAREISS, SPLUNK'