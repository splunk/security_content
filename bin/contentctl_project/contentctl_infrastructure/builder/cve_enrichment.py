
from pycvesearch import CVESearch

CVESSEARCH_API_URL = 'https://cve.circl.lu'


class CveEnrichment():

    @classmethod
    def enrich_cve(self, cve_id: str) -> dict:
        cve_enriched = dict()
        try:
            cve = CVESearch(CVESSEARCH_API_URL)
            result = cve.id(cve_id)
            cve_enriched['id'] = cve_id
            cve_enriched['cvss'] = result['cvss']
            cve_enriched['summary'] = result['summary']
        except TypeError as TypeErr:
            # there was a error calling the circl api lets just empty the object
            print("WARNING, issue enriching {0}, with error: {1}".format(cve_id, str(TypeErr)))
            cve_enriched = dict()
    
        return cve_enriched