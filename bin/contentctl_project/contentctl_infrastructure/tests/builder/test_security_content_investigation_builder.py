import os

from bin.contentctl_project.contentctl_infrastructure.builder.security_content_investigation_builder import SecurityContentInvestigationBuilder
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType


def test_read_investigation():
    investigation_builder = SecurityContentInvestigationBuilder()
    investigation_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/investigation/investigation.yml'))
    investigation = investigation_builder.getObject()

    assert investigation.name == "Get Parent Process Info"


def test_add_inputs():
    investigation_builder = SecurityContentInvestigationBuilder()
    investigation_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/investigation/investigation.yml'))
    investigation_builder.addInputs()
    investigation = investigation_builder.getObject()

    assert investigation.inputs == ["parent_process_name", "dest"]


def test_add_lowercase_name():
    investigation_builder = SecurityContentInvestigationBuilder()
    investigation_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/investigation/investigation.yml'))
    investigation_builder.addLowercaseName()
    investigation = investigation_builder.getObject()

    assert investigation.lowercase_name == "get_parent_process_info"