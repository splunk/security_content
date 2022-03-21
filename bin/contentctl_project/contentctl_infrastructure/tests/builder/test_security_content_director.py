import os

from bin.contentctl_project.contentctl_infrastructure.builder.security_content_director import SecurityContentDirector
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_basic_builder import SecurityContentBasicBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_detection_builder import SecurityContentDetectionBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_story_builder import SecurityContentStoryBuilder
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentProduct
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_investigation_builder import SecurityContentInvestigationBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_baseline_builder import SecurityContentBaselineBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_object_builder import SecurityContentObjectBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.attack_enrichment import AttackEnrichment
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_playbook_builder import SecurityContentPlaybookBuilder


def test_construct_deployments():
    director = SecurityContentDirector()
    deployment_builder = SecurityContentBasicBuilder()
    director.constructDeployment(deployment_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/deployment/ESCU/00_default_ttp.yml'))
    deployment = deployment_builder.getObject()

    assert deployment.name == "ESCU Default Configuration TTP"
    assert deployment.author == "Patrick Bareiss"
    assert deployment.scheduling.schedule_window == "auto"
    assert deployment.notable.rule_description == "%description%"


def test_construct_lookups():
    director = SecurityContentDirector()
    lookup_builder = SecurityContentBasicBuilder()
    director.constructLookup(lookup_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/lookups/previously_seen_aws_regions.yml'))
    lookup = lookup_builder.getObject()    

    assert lookup.name == "previously_seen_aws_regions"
    assert lookup.filename == "previously_seen_aws_regions.csv"


def test_construct_macros():
    director = SecurityContentDirector()
    macro_builder = SecurityContentBasicBuilder()
    director.constructMacro(macro_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/macro/powershell.yml'))
    macro = macro_builder.getObject()    

    assert macro.name == "powershell"


def test_construct_playbooks():
    director = SecurityContentDirector()
    playbook_builder = SecurityContentPlaybookBuilder()
    director.constructPlaybook(playbook_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/playbook/example_playbook.yml'))
    playbook = playbook_builder.getObject()     

    assert playbook.name == "Ransomware Investigate and Contain"
    assert playbook.tags.detections[0] == "Attempted Credential Dump From Registry via Reg exe"


def test_construct_unit_tests():
    director = SecurityContentDirector()
    unit_test_builder = SecurityContentBasicBuilder()
    director.constructTest(unit_test_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/test/example.test.yml'))
    test = unit_test_builder.getObject()

    assert test.name == "Cloud Compute Instance Created By Previously Unseen User Unit Test"
    assert test.tests[0].baselines[0].name == "Previously Seen Cloud Compute Creations By User - Initial"
    assert test.tests[0].attack_data[0].source == "aws_cloudtrail"


def test_construct_baselines():
    director = SecurityContentDirector()

    deployment_builder = SecurityContentBasicBuilder()
    director.constructDeployment(deployment_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/deployment/ESCU/00_default_baseline.yml'))
    deployment = deployment_builder.getObject()

    baseline_builder = SecurityContentBaselineBuilder()
    director.constructBaseline(baseline_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/baseline/baseline.yml'), [deployment])
    baseline = baseline_builder.getObject()

    assert baseline.name == "Previously Seen Users In CloudTrail - Update"

    director.constructBaseline(baseline_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/baseline/baseline2.yml'), [deployment])
    baseline = baseline_builder.getObject()

    assert baseline.name == "Baseline Of Cloud Instances Launched"


def test_construct_investigations():
    director = SecurityContentDirector()
    investigation_builder = SecurityContentInvestigationBuilder()
    director.constructInvestigation(investigation_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/investigation/investigation.yml'))
    investigation = investigation_builder.getObject()

    assert investigation.name == "Get Parent Process Info"


def test_construct_detections():
    director = SecurityContentDirector()

    lookup_builder = SecurityContentBasicBuilder()
    director.constructLookup(lookup_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/lookups/previously_seen_aws_regions.yml'))
    lookup = lookup_builder.getObject()    

    deployment_builder = SecurityContentBasicBuilder()
    director.constructDeployment(deployment_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/deployment/ESCU/00_default_ttp.yml'))
    deployment = deployment_builder.getObject()

    director.constructDeployment(deployment_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/deployment/ESCU/00_default_baseline.yml'))
    deployment_baseline = deployment_builder.getObject() 

    playbook_builder = SecurityContentPlaybookBuilder()
    director.constructPlaybook(playbook_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/playbook/example_playbook.yml'))
    playbook = playbook_builder.getObject()    

    baseline_builder = SecurityContentBaselineBuilder()
    director.constructBaseline(baseline_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/baseline/baseline.yml'), [deployment_baseline])
    baseline = baseline_builder.getObject()

    unit_test_builder = SecurityContentBasicBuilder()
    director.constructTest(unit_test_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/test/attempted_credential_dump_from_registry_via_reg_exe.test.yml'))
    test = unit_test_builder.getObject()

    macro_builder = SecurityContentBasicBuilder()
    director.constructMacro(macro_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/macro/process_reg.yml'))
    macro = macro_builder.getObject()  

    detection_builder = SecurityContentDetectionBuilder()
    director.constructDetection(detection_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'), [deployment], [playbook], [baseline], [test],
        AttackEnrichment.get_attack_lookup(), [macro], [lookup])
    detection = detection_builder.getObject()

    valid_annotations = {'mitre_attack': ['T1003.002', 'T1003'], 
        'kill_chain_phases': ['Actions on Objectives'], 
        'cis20': ['CIS 3', 'CIS 5', 'CIS 16'], 
        'nist': ['DE.CM'], 
        'analytic_story': ['Credential Dumping', 'DarkSide Ransomware'], 
        'observable': [{'name': 'user', 'type': 'User', 'role': ['Victim']}, 
            {'name': 'dest', 'type': 'Hostname', 'role': ['Victim']}, 
            {'name': 'parent_process_name', 'type': 'Process', 'role': ['Parent Process']}, 
            {'name': 'process_name', 'type': 'Process', 'role': ['Child Process']}], 
        'context': ['Source:Endpoint', 'Stage:Credential Access'], 
        'impact': 90, 'confidence': 100}

    valid_risk = [{'risk_object_type': 'user', 'risk_object_field': 'user', 'risk_score': 90}, 
        {'risk_object_type': 'system', 'risk_object_field': 'dest', 'risk_score': 90}, 
        {'threat_object_field': 'parent_process_name', 'threat_object_type': 'process'}, 
        {'threat_object_field': 'process_name', 'threat_object_type': 'process'}]

    assert detection.name == "Attempted Credential Dump From Registry via Reg exe"
    assert detection.author == "Patrick Bareiss, Splunk"
    assert detection.deployment.name == "ESCU Default Configuration TTP" 
    assert detection.deployment.notable.nes_fields == ['user', 'dest']
    assert detection.annotations == valid_annotations
    assert detection.risk == valid_risk
    assert detection.playbooks[0].name == "Ransomware Investigate and Contain"
    assert detection.baselines[0].name == "Previously Seen Users In CloudTrail - Update"
    assert detection.test.name == "Attempted Credential Dump From Registry via Reg exe Unit Test"
    assert detection.macros[0].name == 'process_reg'
    assert detection.macros[1].name == 'attempted_credential_dump_from_registry_via_reg_exe_filter'


def test_construct_stories():
    director = SecurityContentDirector()

    deployment_builder = SecurityContentBasicBuilder()  
    director.constructDeployment(deployment_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/deployment/ESCU/00_default_ttp.yml'))
    deployment = deployment_builder.getObject()

    director.constructDeployment(deployment_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/deployment/ESCU/00_default_baseline.yml'))
    deployment_baseline = deployment_builder.getObject() 

    playbook_builder = SecurityContentPlaybookBuilder()
    director.constructPlaybook(playbook_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/playbook/example_playbook.yml'))
    playbook = playbook_builder.getObject()    

    baseline_builder = SecurityContentBaselineBuilder()
    director.constructBaseline(baseline_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/baseline/baseline2.yml'), [deployment_baseline])
    baseline = baseline_builder.getObject()

    unit_test_builder = SecurityContentBasicBuilder()
    director.constructTest(unit_test_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/test/attempted_credential_dump_from_registry_via_reg_exe.test.yml'))
    test = unit_test_builder.getObject()

    detection_builder = SecurityContentDetectionBuilder()
    director.constructDetection(detection_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'), [deployment], [playbook], [baseline], [test],
        AttackEnrichment.get_attack_lookup(), [], [])
    detection = detection_builder.getObject()

    investigation_builder = SecurityContentInvestigationBuilder()
    director.constructInvestigation(investigation_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/investigation/investigation.yml'))
    investigation = investigation_builder.getObject()

    story_builder = SecurityContentStoryBuilder()
    director.constructStory(story_builder, os.path.join(os.path.dirname(__file__), 
        'test_data/story/ransomware_darkside.yml'),
        [detection], [baseline], [investigation])
    story = story_builder.getObject()

    assert story.name == "DarkSide Ransomware"
    assert story.tags.usecase == "Advanced Threat Detection"
    assert story.detection_names == ["ESCU - Attempted Credential Dump From Registry via Reg exe - Rule"]
    assert story.baseline_names == ["ESCU - Baseline Of Cloud Instances Launched"]
    assert story.investigation_names == ["ESCU - Get Parent Process Info - Response Task"]
    assert story.author_company == "Splunk"
    assert story.author_name == "Bhavin Patel"    


def test_construct_objects():
    director = SecurityContentDirector()

    object_builder = SecurityContentObjectBuilder()
    director.constructObjects(object_builder,os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'))
    obj = object_builder.getObject()

    assert obj['name'] == "Attempted Credential Dump From Registry via Reg exe"