import pytest
import os

from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentProduct
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_detection_builder import SecurityContentDetectionBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_basic_builder import SecurityContentBasicBuilder
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_infrastructure.builder.yml_reader import YmlReader
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_investigation_builder import SecurityContentInvestigationBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_baseline_builder import SecurityContentBaselineBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.attack_enrichment import AttackEnrichment
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_playbook_builder import SecurityContentPlaybookBuilder


def test_read_detection():
    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'))
    detection = security_content_builder.getObject()
    
    assert detection.name == "Attempted Credential Dump From Registry via Reg exe"
    assert detection.author == "Patrick Bareiss, Splunk"


def test_add_deployment_to_detection():
    security_content_builder_deployment = SecurityContentBasicBuilder()
    security_content_builder_deployment.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/deployment/ESCU/00_default_ttp.yml'), SecurityContentType.deployments)
    deployment = security_content_builder_deployment.getObject()   

    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'))
    security_content_builder.addDeployment([deployment])
    detection = security_content_builder.getObject()

    assert detection.deployment.name == "ESCU Default Configuration TTP"  


def test_detection_nes_field_enrichment():
    security_content_builder_deployment = SecurityContentBasicBuilder()
    security_content_builder_deployment.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/deployment/ESCU/00_default_ttp.yml'), SecurityContentType.deployments)
    deployment = security_content_builder_deployment.getObject()

    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'))
    security_content_builder.addDeployment([deployment])
    security_content_builder.addNesFields()
    detection = security_content_builder.getObject()

    assert detection.deployment.notable.nes_fields == ['user', 'dest']


def test_detection_annotation_enrichment():
    security_content_builder_deployment = SecurityContentBasicBuilder()
    security_content_builder_deployment.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/deployment/ESCU/00_default_ttp.yml'), SecurityContentType.deployments)
    deployment = security_content_builder_deployment.getObject()

    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'))
    security_content_builder.addDeployment([deployment])
    security_content_builder.addAnnotations()
    detection = security_content_builder.getObject()

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
    
    assert detection.annotations == valid_annotations


def test_detection_add_mappings():
    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'))
    security_content_builder.addMappings()
    detection = security_content_builder.getObject() 

    valid_mappings = {'mitre_attack': ['T1003.002', 'T1003'], 
        'kill_chain_phases': ['Actions on Objectives'], 
        'cis20': ['CIS 3', 'CIS 5', 'CIS 16'], 
        'nist': ['DE.CM']}

    assert detection.mappings == valid_mappings


def test_detection_add_rba():
    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'))
    security_content_builder.addRBA()
    detection = security_content_builder.getObject()

    valid_risk = [{'risk_object_type': 'user', 'risk_object_field': 'user', 'risk_score': 90}, 
        {'risk_object_type': 'system', 'risk_object_field': 'dest', 'risk_score': 90}, 
        {'threat_object_field': 'parent_process_name', 'threat_object_type': 'process'}, 
        {'threat_object_field': 'process_name', 'threat_object_type': 'process'}]

    assert detection.risk == valid_risk


def test_detection_add_playbooks():
    playbook_builder = SecurityContentPlaybookBuilder()
    playbook_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/playbook/example_playbook.yml'))
    playbook = playbook_builder.getObject()

    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'))
    security_content_builder.addPlaybook([playbook])
    detection = security_content_builder.getObject()

    assert detection.playbooks[0].name == "Ransomware Investigate and Contain"


def test_detection_enrich_baseline():

    baseline_builder = SecurityContentBaselineBuilder()
    baseline_builder.setObject(os.path.join(os.path.dirname(__file__), 'test_data/baseline/baseline.yml'))
    baseline = baseline_builder.getObject()

    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'))
    security_content_builder.addBaseline([baseline])
    detection = security_content_builder.getObject()

    assert detection.baselines[0].name == "Previously Seen Users In CloudTrail - Update"


def test_detection_enrich_unit_test():
    security_content_builder = SecurityContentBasicBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/test/attempted_credential_dump_from_registry_via_reg_exe.test.yml'), SecurityContentType.unit_tests)
    test = security_content_builder.getObject()

    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'))
    security_content_builder.addUnitTest([test])
    detection = security_content_builder.getObject()

    assert detection.test.tests[0].file == "endpoint/attempted_credential_dump_from_registry_via_reg_exe.yml"


def test_attack_enrichment():
    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'))
    security_content_builder.addMitreAttackEnrichment(AttackEnrichment.get_attack_lookup())
    detection = security_content_builder.getObject()

    assert detection.tags.mitre_attack_enrichments[0].dict()['mitre_attack_id'] == 'T1003.002'
    assert detection.tags.mitre_attack_enrichments[0].dict()['mitre_attack_technique'] == 'Security Account Manager'
    assert detection.tags.mitre_attack_enrichments[0].dict()['mitre_attack_tactics'] == ['Credential Access']


def test_macros_enrichment():
    basic_builder = SecurityContentBasicBuilder()
    basic_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/macro/process_reg.yml'), SecurityContentType.macros)
    macro = basic_builder.getObject() 

    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/valid.yml'))
    security_content_builder.addMacros([macro])
    detection = security_content_builder.getObject()
    
    assert detection.macros[0].name == 'process_reg'
    assert detection.macros[1].name == 'attempted_credential_dump_from_registry_via_reg_exe_filter'


def test_lookup_enrichment():
    security_content_builder = SecurityContentBasicBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/lookups/attacker_tools.yml'), SecurityContentType.lookups)
    lookup = security_content_builder.getObject()    

    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/attacker_tools_on_endpoint.yml'))
    security_content_builder.addLookups([lookup])
    detection = security_content_builder.getObject()

    assert detection.lookups[0].name == 'attacker_tools'


def test_add_cve():
    security_content_builder = SecurityContentDetectionBuilder()
    security_content_builder.setObject(os.path.join(os.path.dirname(__file__), 
        'test_data/detection/spoolsv_suspicious_loaded_modules.yml'))
    security_content_builder.addCve()
    detection = security_content_builder.getObject()
    
    assert detection.cve_enrichment == [{'id': 'CVE-2021-34527', 'cvss': 9.0, 'summary': 'Windows Print Spooler Remote Code Execution Vulnerability'}]