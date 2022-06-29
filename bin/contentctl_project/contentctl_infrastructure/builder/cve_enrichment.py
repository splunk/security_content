
from pycvesearch import CVESearch
import functools
import os
import shelve
import time
CVESSEARCH_API_URL = 'https://cve.circl.lu'

CVE_CACHE_FILENAME = "lookups/CVE_CACHE.db"

NON_PERSISTENT_CACHE = {}

@functools.cache
def cvesearch_helper(url:str, cve_id:str, force_cached_or_offline:bool=False):
    if force_cached_or_offline:
        if not os.path.exists(CVE_CACHE_FILENAME):
            print(f"Cache at {CVE_CACHE_FILENAME} not found - Creating it.")
        cache = shelve.open(CVE_CACHE_FILENAME, flag='c', writeback=True)
    else:
        cache = NON_PERSISTENT_CACHE
    if cve_id in cache:
        result = cache[cve_id]
        #print(f"hit cve_enrichment:  {time.time() - start:.2f}")
    else:
        try:
            cve = cvesearch_id_helper(url)
            result = cve.id(cve_id)
        except Exception as e:
            raise(Exception(f"The option 'force_cached_or_offline' was used, but {cve_id} not found in {CVE_CACHE_FILENAME} and unable to connect to {CVESSEARCH_API_URL}"))
        if result is None:
            raise(Exception(f'CveEnrichment for [ {cve_id} ] failed - CVE does not exist'))
        cache[cve_id] = result
    if force_cached_or_offline:
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
            
            result = cvesearch_helper(CVESSEARCH_API_URL, cve_id)
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