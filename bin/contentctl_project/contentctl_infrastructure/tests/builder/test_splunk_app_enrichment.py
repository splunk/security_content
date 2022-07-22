

from bin.contentctl_project.contentctl_infrastructure.builder.splunk_app_enrichment import SplunkAppEnrichment


def test_splunk_app_enrichment():
    splunk_app_enriched = SplunkAppEnrichment.enrich_splunk_app('Splunk_TA_microsoft_sysmon')
    assert splunk_app_enriched['name'] == 'Splunk Add-on for Sysmon'
    assert splunk_app_enriched['url'] == 'https://splunkbase.splunk.com/app/5709'