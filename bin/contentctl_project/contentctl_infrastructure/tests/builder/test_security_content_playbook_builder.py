import os

from bin.contentctl_project.contentctl_infrastructure.builder.security_content_playbook_builder import SecurityContentPlaybookBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_detection_builder import SecurityContentDetectionBuilder


def test_read_playbook():
    playbook_builder = SecurityContentPlaybookBuilder()
    playbook_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/playbook/example_playbook.yml'))
    playbook = playbook_builder.getObject()

    assert playbook.name == "Ransomware Investigate and Contain"


def test_enrich_detections():

    playbook_builder = SecurityContentPlaybookBuilder()
    playbook_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/playbook/example_playbook.yml'))
    playbook_builder.addDetections()
    playbook = playbook_builder.getObject()

    assert playbook.tags.detection_objects[0]['path'] == "detections/endpoint/attempted_credential_dump_from_registry_via_reg_exe.yml"