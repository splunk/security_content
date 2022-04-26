import os

from bin.contentctl_project.contentctl_infrastructure.builder.security_content_story_builder import SecurityContentStoryBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_detection_builder import SecurityContentDetectionBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_basic_builder import SecurityContentBasicBuilder
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_investigation_builder import SecurityContentInvestigationBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_baseline_builder import SecurityContentBaselineBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.attack_enrichment import AttackEnrichment


def test_read_story():
    story_builder = SecurityContentStoryBuilder()
    story_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/story/ransomware_darkside.yml'))
    story = story_builder.getObject()

    assert story.name == "DarkSide Ransomware"
    assert story.tags.usecase == "Advanced Threat Detection"


def test_add_detections():
    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'))
    security_content_builder.addMitreAttackEnrichment(AttackEnrichment.get_attack_lookup())
    detection = security_content_builder.getObject()

    story_builder = SecurityContentStoryBuilder()
    story_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/story/ransomware_darkside.yml'))
    story_builder.addDetections([detection])
    story = story_builder.getObject()

    assert story.detection_names == ["ESCU - Attempted Credential Dump From Registry via Reg exe - Rule"]
    assert story.tags.datamodels == ['Endpoint']
    assert story.tags.kill_chain_phases == ['Actions on Objectives']


def test_add_baselines():
    baseline_builder = SecurityContentBaselineBuilder()
    baseline_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/baseline/baseline2.yml'))
    baseline = baseline_builder.getObject()

    story_builder = SecurityContentStoryBuilder()
    story_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/story/ransomware_darkside.yml'))
    story_builder.addBaselines([baseline])
    story = story_builder.getObject()

    assert story.baseline_names == ["ESCU - Baseline Of Cloud Instances Launched"]


def test_add_investigations():
    investigation_builder = SecurityContentInvestigationBuilder()
    investigation_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/investigation/investigation.yml'))
    investigation = investigation_builder.getObject()

    story_builder = SecurityContentStoryBuilder()
    story_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/story/ransomware_darkside.yml'))
    story_builder.addInvestigations([investigation])
    story = story_builder.getObject()

    assert story.investigation_names == ["ESCU - Get Parent Process Info - Response Task"]


def test_parse_authorr():
    story_builder = SecurityContentStoryBuilder()
    story_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/story/ransomware_darkside.yml'))
    story_builder.addAuthorCompanyName()
    story = story_builder.getObject()

    assert story.author_company == "Splunk"
    assert story.author_name == "Bhavin Patel"