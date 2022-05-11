
from pycvesearch import CVESearch
import functools
import os
import shelve

CVESSEARCH_API_URL = 'https://cve.circl.lu'

CVE_CACHE_FILENAME = "lookups/CVE_CACHE.db"

@functools.cache
def cvesearch_helper(url:str, cve_id:str):
    if not os.path.exists(CVE_CACHE_FILENAME):
        print(f"Reference cache at {CVE_CACHE_FILENAME} not found. Creating it.")
    cache = shelve.open(CVE_CACHE_FILENAME, flag='c', writeback=True)
    if cve_id in cache:
        return cache[cve_id]
    

    
    try:
        cve = cvesearch_id_helper(url)
        result = cve.id(cve_id)
    except Exception as e:
        raise(Exception(f"The option 'force_cached_or_offline' was used, but {cve_id} not found in {CVE_CACHE_FILENAME} and unable to connect to {CVESSEARCH_API_URL}"))
    if result is None:
        raise(Exception(f'CveEnrichment for [ {cve_id} ] failed - CVE does not exist'))
    cache[cve_id] = result
    cache.close()

    return result

@functools.cache
def cvesearch_id_helper(url:str):
    #The initial CVESearch call takes some time.
    #We cache it to avoid making this call each time we need to do a lookup
    cve = CVESearch(CVESSEARCH_API_URL)
    return cve



class CveEnrichment():

    @classmethod
    def enrich_cve(self, cve_id: str, force_cached_or_offline: bool = False) -> dict:
        cve_enriched = dict()
        try:
            if force_cached_or_offline is True:
                result = cvesearch_helper(CVESSEARCH_API_URL, cve_id)
            else:
                cve = CVESearch(CVESSEARCH_API_URL)
                result = cve.id(cve_id)
            cve_enriched['id'] = cve_id
            cve_enriched['cvss'] = result['cvss']
            cve_enriched['summary'] = result['summary']
        except TypeError as TypeErr:
            # there was a error calling the circl api lets just empty the object
            print("WARNING, issue enriching {0}, with error: {1}".format(cve_id, str(TypeErr)))
            cve_enriched = dict()
        except Exception as e:
            print("WARNING - {0}".format(str(e)))
            cve_enriched = dict()
    
        return cve_enriched