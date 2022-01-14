import os
import filecmp

from contentctl_infrastructure.contentctl_infrastructure.builder.yml_reader import YmlReader
from contentctl_infrastructure.contentctl_infrastructure.adapter.obj_to_yml_adapter import ObjToYmlAdapter


def test_read_and_write_yml():
    yml_obj = YmlReader.load_file(os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/detection/valid.yml'))

    output_path = os.path.join(os.path.dirname(__file__), 'data/yml_file')
    adapter = ObjToYmlAdapter()
    adapter.writeObjects([yml_obj], output_path)

    file_name = yml_obj['name'] \
            .replace(' ', '_') \
            .replace('-','_') \
            .replace('.','_') \
            .replace('/','_') \
            .lower()
    file_name = file_name + '.yml'
    file_path = os.path.join(output_path, file_name)

    ref_file_path = os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/detection/valid.yml')

    assert filecmp.cmp(file_path, ref_file_path, shallow=False)