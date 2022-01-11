import os

from contentctl_infrastructure.contentctl_infrastructure.builder.security_content_story_builder import SecurityContentStoryBuilder
from contentctl_infrastructure.contentctl_infrastructure.builder.security_content_detection_builder import SecurityContentDetectionBuilder
from contentctl_infrastructure.contentctl_infrastructure.builder.security_content_basic_builder import SecurityContentBasicBuilder
from contentctl.contentctl.domain.entities.enums.enums import SecurityContentType
from contentctl_infrastructure.contentctl_infrastructure.builder.security_content_investigation_builder import SecurityContentInvestigationBuilder
from contentctl_infrastructure.contentctl_infrastructure.builder.security_content_baseline_builder import SecurityContentBaselineBuilder


def test_read_story():
    story_builder = SecurityContentStoryBuilder()
    story_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/story/ransomware_darkside.yml'), SecurityContentType.stories)
    story = story_builder.getObject()

    assert story.name == "DarkSide Ransomware"
    assert story.tags.usecase == "Advanced Threat Detection"


def test_add_detections():
    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'), SecurityContentType.detections)
    detection = security_content_builder.getObject()

    story_builder = SecurityContentStoryBuilder()
    story_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/story/ransomware_darkside.yml'), SecurityContentType.stories)
    story_builder.addDetections([detection])
    story = story_builder.getObject()

    assert story.detection_names == ["ESCU - Attempted Credential Dump From Registry via Reg exe - Rule"]


def test_add_baselines():
    baseline_builder = SecurityContentBaselineBuilder()
    baseline_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/baseline/baseline2.yml'), SecurityContentType.baselines)
    baseline = baseline_builder.getObject()

    story_builder = SecurityContentStoryBuilder()
    story_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/story/ransomware_darkside.yml'), SecurityContentType.stories)
    story_builder.addBaselines([baseline])
    story = story_builder.getObject()

    assert story.baseline_names == ["ESCU - Baseline Of Cloud Instances Launched"]


def test_add_investigations():
    investigation_builder = SecurityContentInvestigationBuilder()
    investigation_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/investigation/investigation.yml'), SecurityContentType.investigations)
    investigation = investigation_builder.getObject()

    story_builder = SecurityContentStoryBuilder()
    story_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/story/ransomware_darkside.yml'), SecurityContentType.stories)
    story_builder.addInvestigations([investigation])
    story = story_builder.getObject()

    assert story.investigation_names == ["ESCU - Get Parent Process Info - Response Task"]


def test_parse_authorr():
    story_builder = SecurityContentStoryBuilder()
    story_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/story/ransomware_darkside.yml'), SecurityContentType.stories)
    story_builder.addAuthorCompanyName()
    story = story_builder.getObject()

    assert story.author_company == "Splunk"
    assert story.author_name == "Bhavin Patel"