import pytest
import os

from contentctl.contentctl.domain.entities.enums.enums import SecurityContentProduct
from contentctl_infrastructure.contentctl_infrastructure.builder.security_content_basic_builder import SecurityContentBasicBuilder
from contentctl.contentctl.domain.entities.enums.enums import SecurityContentType
from contentctl_infrastructure.contentctl_infrastructure.builder.yml_reader import YmlReader


def test_read_deployment():
    security_content_builder = SecurityContentBasicBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/deployment/ESCU/00_default_ttp.yml'), SecurityContentType.deployments)
    deployment = security_content_builder.getObject()   

    assert deployment.name == "ESCU Default Configuration TTP"
    assert deployment.author == "Patrick Bareiss"
    assert deployment.scheduling.schedule_window == "auto"
    assert deployment.notable.rule_description == "%description%"


def test_read_lookup():
    security_content_builder = SecurityContentBasicBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/lookup/previously_seen_aws_regions.yml'), SecurityContentType.lookups)
    lookup = security_content_builder.getObject()    

    assert lookup.name == "previously_seen_aws_regions"
    assert lookup.filename == "previously_seen_aws_regions.csv"


def test_read_macro():
    security_content_builder = SecurityContentBasicBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/macro/powershell.yml'), SecurityContentType.macros)
    macro = security_content_builder.getObject()    

    assert macro.name == "powershell"


def test_read_playbook():
    security_content_builder = SecurityContentBasicBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/playbook/example_playbook.yml'), SecurityContentType.playbooks)
    playbook = security_content_builder.getObject()   

    assert playbook.name == "Ransomware Investigate and Contain"
    assert playbook.tags.detections[0] == "Conti Common Exec parameter"