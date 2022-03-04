
from pycvesearch import CVESearch

CVESSEARCH_API_URL = 'https://cve.circl.lu'


class CveEnrichment():

    @classmethod
    def enrich_cve(self, cve_id: str) -> dict:
        cve = CVESearch(CVESSEARCH_API_URL)
        result = cve.id(cve_id)
        cve_enriched = dict()
        cve_enriched['id'] = cve_id
        cve_enriched['cvss'] = result['cvss']
        cve_enriched['summary'] = result['summary']
        return cve_enriched