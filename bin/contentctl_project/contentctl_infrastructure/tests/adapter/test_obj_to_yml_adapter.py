import os
import filecmp

from bin.contentctl_project.contentctl_infrastructure.builder.yml_reader import YmlReader
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_yml_adapter import ObjToYmlAdapter


def test_read_and_write_yml():
    file_path = os.path.join(os.path.dirname(__file__), 
        'obj_to_yml_data/attempted_credential_dump_from_registry_via_reg_exe.yml')
    yml_obj = YmlReader.load_file(file_path)
    adapter = ObjToYmlAdapter()
    adapter.writeObjectsInPlace([yml_obj])

    ref_file_path = os.path.join(os.path.dirname(__file__), 
        'obj_to_yml_data_ref/attempted_credential_dump_from_registry_via_reg_exe.yml')

    assert filecmp.cmp(file_path, ref_file_path, shallow=False)