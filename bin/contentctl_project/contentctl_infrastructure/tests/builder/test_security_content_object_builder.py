
import os


from bin.contentctl_project.contentctl_infrastructure.builder.security_content_object_builder import SecurityContentObjectBuilder
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType


def test_read_detection():
    object_builder = SecurityContentObjectBuilder()
    object_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'))
    obj = object_builder.getObject()

    assert obj['name'] == "Attempted Credential Dump From Registry via Reg exe"