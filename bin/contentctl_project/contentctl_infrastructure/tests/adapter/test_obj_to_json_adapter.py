import os
import filecmp

from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_json_adapter import ObjToJsonAdapter
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_basic_builder import SecurityContentBasicBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_detection_builder import SecurityContentDetectionBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_baseline_builder import SecurityContentBaselineBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_investigation_builder import SecurityContentInvestigationBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_story_builder import SecurityContentStoryBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_director import SecurityContentDirector
from bin.contentctl_project.contentctl_infrastructure.builder.attack_enrichment import AttackEnrichment
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_playbook_builder import SecurityContentPlaybookBuilder


def test_write_detections():
    director = SecurityContentDirector()

    macro_builder = SecurityContentBasicBuilder()
    director.constructMacro(macro_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/macro/process_reg.yml'))
    macro = macro_builder.getObject()  

    lookup_builder = SecurityContentBasicBuilder()
    director.constructLookup(lookup_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/lookups/previously_seen_aws_regions.yml'))
    lookup = lookup_builder.getObject()    

    detection_builder = SecurityContentDetectionBuilder()
    director.constructDetection(detection_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/detection/valid.yml'), [], [], [], [],
        AttackEnrichment.get_attack_lookup(), [macro], [lookup])
    detection = detection_builder.getObject()
    
    output_path = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data')
    adapter = ObjToJsonAdapter()
    adapter.writeObjects([detection], output_path, SecurityContentType.detections)

    path = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data/detections.json')
    path_ref = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data/detections_ref.json')
    #assert filecmp.cmp(path, path_ref, shallow=False)


def test_write_baselines():
    director = SecurityContentDirector()

    deployment_builder = SecurityContentBasicBuilder()
    director.constructDeployment(deployment_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/deployment/ESCU/00_default_baseline.yml'))
    deployment = deployment_builder.getObject()

    baseline_builder = SecurityContentBaselineBuilder()
    director.constructBaseline(baseline_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/baseline/baseline.yml'), [deployment])
    baseline = baseline_builder.getObject()

    output_path = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data')
    adapter = ObjToJsonAdapter()
    adapter.writeObjects([baseline], output_path, SecurityContentType.baselines)

    path = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data/baselines.json')
    path_ref = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data/baselines_ref.json')
    assert filecmp.cmp(path, path_ref, shallow=False)


def test_write_deployments():
    director = SecurityContentDirector()

    deployment_builder = SecurityContentBasicBuilder()
    director.constructDeployment(deployment_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/deployment/ESCU/00_default_baseline.yml'))
    deployment = deployment_builder.getObject()

    output_path = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data')
    adapter = ObjToJsonAdapter()
    adapter.writeObjects([deployment], output_path, SecurityContentType.deployments)

    path = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data/deployments.json')
    path_ref = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data/deployments_ref.json')
    assert filecmp.cmp(path, path_ref, shallow=False)


def test_write_lookups():
    director = SecurityContentDirector()

    lookup_builder = SecurityContentBasicBuilder()
    director.constructLookup(lookup_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/lookups/previously_seen_aws_regions.yml'))
    lookup = lookup_builder.getObject()

    output_path = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data')
    adapter = ObjToJsonAdapter()
    adapter.writeObjects([lookup], output_path, SecurityContentType.lookups)

    path = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data/lookups.json')
    path_ref = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data/lookups_ref.json')
    assert filecmp.cmp(path, path_ref, shallow=False)


def test_write_macros():
    director = SecurityContentDirector()
    macro_builder = SecurityContentBasicBuilder()
    director.constructMacro(macro_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/macro/powershell.yml'))
    macro = macro_builder.getObject()

    output_path = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data')
    adapter = ObjToJsonAdapter()
    adapter.writeObjects([macro], output_path, SecurityContentType.macros)

    path = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data/macros.json')
    path_ref = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data/macros_ref.json')
    assert filecmp.cmp(path, path_ref, shallow=False)


def test_write_investigations():
    director = SecurityContentDirector()
    investigation_builder = SecurityContentInvestigationBuilder()
    director.constructInvestigation(investigation_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/investigation/investigation.yml'))
    investigation = investigation_builder.getObject()

    output_path = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data')
    adapter = ObjToJsonAdapter()
    adapter.writeObjects([investigation], output_path, SecurityContentType.investigations)

    path = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data/response_task.json')
    path_ref = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data/response_task_ref.json')
    assert filecmp.cmp(path, path_ref, shallow=False)


def test_write_stories():
    director = SecurityContentDirector()
    
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
        '../builder/test_data/baseline/baseline2.yml'), [deployment_baseline])
    baseline = baseline_builder.getObject()

    unit_test_builder = SecurityContentBasicBuilder()
    director.constructTest(unit_test_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/test/attempted_credential_dump_from_registry_via_reg_exe.test.yml'))
    test = unit_test_builder.getObject()

    detection_builder = SecurityContentDetectionBuilder()
    director.constructDetection(detection_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/detection/valid.yml'), [deployment], [playbook], [baseline], [test],
        AttackEnrichment.get_attack_lookup(), [], [])
    detection = detection_builder.getObject()

    investigation_builder = SecurityContentInvestigationBuilder()
    director.constructInvestigation(investigation_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/investigation/investigation.yml'))
    investigation = investigation_builder.getObject()
   
    story_builder = SecurityContentStoryBuilder()
    director.constructStory(story_builder, os.path.join(os.path.dirname(__file__), 
        '../builder/test_data/story/ransomware_darkside.yml'),
        [detection], [baseline], [investigation])
    story = story_builder.getObject()

    output_path = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data')
    adapter = ObjToJsonAdapter()
    adapter.writeObjects([story], output_path, SecurityContentType.stories)

    path = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data/story.json')
    path_ref = os.path.join(os.path.dirname(__file__), 'obj_to_json_adapter_data/story_ref.json')
    assert filecmp.cmp(path, path_ref, shallow=False)