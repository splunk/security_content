import os
import datetime
import pytest
import filecmp

from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_conf_adapter import ObjToConfAdapter
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_director import SecurityContentDirector
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_basic_builder import SecurityContentBasicBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_detection_builder import SecurityContentDetectionBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_story_builder import SecurityContentStoryBuilder
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_investigation_builder import SecurityContentInvestigationBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_baseline_builder import SecurityContentBaselineBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.attack_enrichment import AttackEnrichment
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_playbook_builder import SecurityContentPlaybookBuilder


FAKE_TIME = datetime.datetime(2020, 12, 25, 17, 5, 55)

@pytest.fixture
def patch_datetime_now(monkeypatch):

    class mydatetime():
        @classmethod
        def utcnow(cls):
            return FAKE_TIME

    monkeypatch.setattr(datetime, 'datetime', mydatetime)


def test_write_conf_files(patch_datetime_now):
    director = SecurityContentDirector()

    lookup_builder = SecurityContentBasicBuilder()
    director.constructLookup(lookup_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/lookups/previously_seen_aws_regions.yml'))
    lookup = lookup_builder.getObject()    

    macro_builder = SecurityContentBasicBuilder()
    director.constructMacro(macro_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/macro/security_content_ctime.yml'))
    macro = macro_builder.getObject()    

    deployment_builder = SecurityContentBasicBuilder()
    director.constructDeployment(deployment_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/deployment/ESCU/00_default_ttp.yml'))
    deployment = deployment_builder.getObject()

    director.constructDeployment(deployment_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/deployment/ESCU/00_default_baseline.yml'))
    deployment_baseline = deployment_builder.getObject()

    playbook_builder = SecurityContentPlaybookBuilder()
    director.constructPlaybook(playbook_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/playbook/example_playbook.yml'))
    playbook = playbook_builder.getObject()    

    baseline_builder = SecurityContentBaselineBuilder()
    director.constructBaseline(baseline_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/baseline/baseline.yml'), [deployment_baseline])
    baseline = baseline_builder.getObject()

    unit_test_builder = SecurityContentBasicBuilder()
    director.constructTest(unit_test_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/test/attempted_credential_dump_from_registry_via_reg_exe.test.yml'))
    test = unit_test_builder.getObject()

    detection_builder = SecurityContentDetectionBuilder()
    director.constructDetection(detection_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/detection/valid.yml'), [deployment], [playbook], [baseline], [test],
        {}, [], [])
    detection = detection_builder.getObject()

    director.constructDetection(detection_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/detection/deprecated/detect_new_user_aws_console_login.yml'), [deployment], [playbook], [baseline], [test],
        {}, [], [])
    detection_deprecated = detection_builder.getObject()

    investigation_builder = SecurityContentInvestigationBuilder()
    director.constructInvestigation(investigation_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/investigation/investigation.yml'))
    investigation = investigation_builder.getObject()

    story_builder = SecurityContentStoryBuilder()
    director.constructStory(story_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/story/ransomware_darkside.yml'),
        [detection], [baseline], [investigation])
    story = story_builder.getObject()

    output_path = os.path.join(os.path.dirname(__file__), 'data')
    adapter = ObjToConfAdapter()
    adapter.writeHeaders(output_path)
    adapter.writeObjects([detection, detection_deprecated], output_path, SecurityContentType.detections)
    adapter.writeObjects([story], output_path, SecurityContentType.stories)
    adapter.writeObjects([baseline], output_path, SecurityContentType.baselines)
    adapter.writeObjects([investigation], output_path, SecurityContentType.investigations)
    adapter.writeObjects([lookup], output_path, SecurityContentType.lookups)
    adapter.writeObjects([macro], output_path, SecurityContentType.macros)

    files_to_compare = [
        'data/ui/panels/workbench_panel_get_parent_process_info___response_task.xml',
        'analyticstories.conf',
        'collections.conf',
        'es_investigations.conf',
        'macros.conf',
        'savedsearches.conf',
        'transforms.conf',
        'workflow_actions.conf'
    ]

    for file in files_to_compare:
        path = os.path.join(os.path.dirname(__file__), 'data/default', file)
        path_ref = os.path.join(os.path.dirname(__file__), 'data/default_reference', file)
        assert filecmp.cmp(path, path_ref, shallow=False)
