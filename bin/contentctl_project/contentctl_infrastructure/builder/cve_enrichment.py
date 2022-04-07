
from pycvesearch import CVESearch
import functools
import pickle

CVESSEARCH_API_URL = 'https://cve.circl.lu'


CVE_CACHE_FILENAME = "CVE_CACHE.PICKLE"

@functools.cache
def cvesearch_helper(url:str, cve_id:str):
    cve = cvesearch_id_helper(url)

    try:
        with open(CVE_CACHE_FILENAME, 'rb') as p:
            dat = pickle.load(p)
            if cve_id in dat:
                return dat[cve_id]
    except Exception as e:
        print(f"error loading pickle file {CVE_CACHE_FILENAME}- it probably didn't exist. we will create it")
        dat = {}
    
    result = cve.id(cve_id)
    with open(CVE_CACHE_FILENAME, 'wb') as p:
        dat[cve_id] = result
        pickle.dump(dat, p)
    
    return result

@functools.cache
def cvesearch_id_helper(url:str):
    cve = CVESearch(CVESSEARCH_API_URL)
    return cve


class CveEnrichment():

    @classmethod
    def enrich_cve(self, cve_id: str) -> dict:
        cve_enriched = dict()
        try:
            #cve = CVESearch(CVESSEARCH_API_URL)
            #result = cve.id(cve_id)
            result = cvesearch_helper(CVESSEARCH_API_URL, cve_id)
            cve_enriched['id'] = cve_id
            cve_enriched['cvss'] = result['cvss']
            cve_enriched['summary'] = result['summary']
        except TypeError as TypeErr:
            # there was a error calling the circl api lets just empty the object
            print("WARNING, issue enriching {0}, with error: {1}".format(cve_id, str(TypeErr)))
            cve_enriched = dict()
    
        return cve_enriched