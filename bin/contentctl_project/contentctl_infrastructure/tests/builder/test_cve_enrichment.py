

from bin.contentctl_project.contentctl_infrastructure.builder.cve_enrichment import CveEnrichment


def test_cve_enrichment():
    cve_enrichment = CveEnrichment.enrich_cve('CVE-2021-34527')
    assert cve_enrichment['id'] == 'CVE-2021-34527'
    assert cve_enrichment['cvss'] == 9.0
    assert cve_enrichment['summary'] == 'Windows Print Spooler Remote Code Execution Vulnerability'