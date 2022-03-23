import os
import filecmp

from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_md_adapter import ObjToMdAdapter
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_director import SecurityContentDirector
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_basic_builder import SecurityContentBasicBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_detection_builder import SecurityContentDetectionBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_story_builder import SecurityContentStoryBuilder
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_investigation_builder import SecurityContentInvestigationBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_baseline_builder import SecurityContentBaselineBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_playbook_builder import SecurityContentPlaybookBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.attack_enrichment import AttackEnrichment
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_md_adapter import ObjToMdAdapter


def test_md_writer():
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

    baseline_builder = SecurityContentBaselineBuilder()
    director.constructBaseline(baseline_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/baseline/baseline.yml'), [deployment_baseline])
    baseline = baseline_builder.getObject()

    unit_test_builder = SecurityContentBasicBuilder()
    director.constructTest(unit_test_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/test/attempted_credential_dump_from_registry_via_reg_exe.test.yml'))
    test = unit_test_builder.getObject()

    playbook_builder = SecurityContentPlaybookBuilder()
    director.constructPlaybook(playbook_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/playbook/example_playbook.yml'))
    playbook = playbook_builder.getObject()

    detection_builder = SecurityContentDetectionBuilder()
    director.constructDetection(detection_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/detection/valid.yml'), [deployment], [playbook], [baseline], [test],
        AttackEnrichment.get_attack_lookup(), [], [])
    detection = detection_builder.getObject()

    director.constructDetection(detection_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/detection/deprecated/detect_new_user_aws_console_login.yml'), [deployment], [playbook], [baseline], [test],
        AttackEnrichment.get_attack_lookup(), [], [])
    detection_deprecated = detection_builder.getObject()

    playbook_builder = SecurityContentPlaybookBuilder()
    director.constructPlaybook(playbook_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/playbook/example_playbook.yml'))
    playbook = playbook_builder.getObject()    

    investigation_builder = SecurityContentInvestigationBuilder()
    director.constructInvestigation(investigation_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/investigation/investigation.yml'))
    investigation = investigation_builder.getObject()

    story_builder = SecurityContentStoryBuilder()
    director.constructStory(story_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/story/ransomware_darkside.yml'),
        [detection], [baseline], [investigation])
    story = story_builder.getObject()

    output_path = os.path.join(os.path.dirname(__file__), 'obj_to_md_data')
    adapter = ObjToMdAdapter()
    adapter.writeObjects([[story], [detection, detection_deprecated], [playbook]], output_path)

    files_to_compare = [
        '_data/navigation.yml',
        '_pages/credential_access.md',
        '_pages/defense_evasion.md',
        '_pages/endpoint.md',
        '_pages/initial_access.md',
        '_pages/malware.md',
        '_pages/persistence.md',
        '_pages/privilege_escalation.md',
        '_pages/stories.md',
        '_pages/detections.md',
        '_stories/darkside_ransomware.md',
        '_posts/2020-07-21-detect_new_user_aws_console_login.md',
        '_posts/2021-09-16-attempted_credential_dump_from_registry_via_reg_exe.md'
    ]

    for file in files_to_compare:
        path = os.path.join(os.path.dirname(__file__), 'obj_to_md_data', file)
        path_ref = os.path.join(os.path.dirname(__file__), 'obj_to_md_data_ref', file)
        assert filecmp.cmp(path, path_ref, shallow=False)