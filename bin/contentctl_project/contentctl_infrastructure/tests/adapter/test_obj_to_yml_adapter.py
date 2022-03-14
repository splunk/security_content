import os
import filecmp

from bin.contentctl_project.contentctl_infrastructure.builder.yml_reader import YmlReader
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_yml_adapter import ObjToYmlAdapter
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_director import SecurityContentDirector
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_detection_builder import SecurityContentDetectionBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_basic_builder import SecurityContentBasicBuilder


def test_read_and_write_yml():
    file_path = os.path.join(os.path.dirname(__file__), 
        'obj_to_yml_data/attempted_credential_dump_from_registry_via_reg_exe.yml')
    yml_obj = YmlReader.load_file(file_path)
    adapter = ObjToYmlAdapter()
    adapter.writeObjectsInPlace([yml_obj])

    ref_file_path = os.path.join(os.path.dirname(__file__), 
        'obj_to_yml_data_ref/attempted_credential_dump_from_registry_via_reg_exe.yml')

    assert filecmp.cmp(file_path, ref_file_path, shallow=False)


def test_write_ssa_detection():
    director = SecurityContentDirector()

    unit_test_builder = SecurityContentBasicBuilder()
    director.constructTest(unit_test_builder, os.path.join(os.path.dirname(__file__), 
        'obj_to_yml_data/ssa___anomalous_usage_of_archive_tools.test.yml'))
    test = unit_test_builder.getObject()

    detection_builder = SecurityContentDetectionBuilder()
    director.constructDetection(detection_builder, os.path.join(os.path.dirname(__file__), 
        'obj_to_yml_data/ssa___anomalous_usage_of_archive_tools.yml'), [], [], [], [test],
        {}, [], [])
    detection = detection_builder.getObject()

    adapter = ObjToYmlAdapter()
    adapter.writeObjects([detection], os.path.join(os.path.dirname(__file__), 'obj_to_yml_data'))

    detection_file_path = os.path.join(os.path.dirname(__file__), 
        'obj_to_yml_data/srs/ssa___anomalous_usage_of_archive_tools.yml')
    ref_file_path = os.path.join(os.path.dirname(__file__), 
        'obj_to_yml_data_ref/srs/ssa___anomalous_usage_of_archive_tools.yml')

    assert filecmp.cmp(detection_file_path, ref_file_path, shallow=False)