from bin.contentctl_project.contentctl_infrastructure.tests.test_constants import SECURITY_CONTENT_ROOT

from bin.contentctl_project.contentctl_infrastructure.builder.attack_enrichment import AttackEnrichment



def test_mitre_attack_enrichment():
    attack_enrichment = AttackEnrichment.get_attack_lookup(SECURITY_CONTENT_ROOT)
    assert attack_enrichment["T1003.002"]["technique"] == "Security Account Manager"
