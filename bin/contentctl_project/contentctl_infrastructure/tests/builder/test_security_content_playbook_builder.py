import os

from contentctl_infrastructure.builder.security_content_playbook_builder import SecurityContentPlaybookBuilder
from contentctl_infrastructure.builder.security_content_detection_builder import SecurityContentDetectionBuilder


def test_read_playbook():
    playbook_builder = SecurityContentPlaybookBuilder()
    playbook_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/playbook/example_playbook.yml'))
    playbook = playbook_builder.getObject()

    assert playbook.name == "Ransomware Investigate and Contain"


def test_enrich_detections():
    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'))
    detection = security_content_builder.getObject()

    playbook_builder = SecurityContentPlaybookBuilder()
    playbook_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/playbook/example_playbook.yml'))
    playbook_builder.addDetections([detection])
    playbook = playbook_builder.getObject()

    assert playbook.tags.detection_objects[0].name == "Attempted Credential Dump From Registry via Reg exe"