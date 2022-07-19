import requests
import xmltodict
import json
import functools
import pickle
import shelve
import os
import time

SPLUNKBASE_API_URL = "https://apps.splunk.com/api/apps/entriesbyid/"

APP_ENRICHMENT_CACHE_FILENAME = "lookups/APP_ENRICHMENT_CACHE.db"

NON_PERSISTENT_CACHE = {}

@functools.cache
def requests_get_helper(url:str, force_cached_or_offline:bool = False)->bytes:
    if force_cached_or_offline:
        if not os.path.exists(APP_ENRICHMENT_CACHE_FILENAME):
            print(f"Cache at {APP_ENRICHMENT_CACHE_FILENAME} not found - Creating it.")
        cache = shelve.open(APP_ENRICHMENT_CACHE_FILENAME, flag='c', writeback=True)
    else:
        cache = NON_PERSISTENT_CACHE
    
    if url in cache:
        req_content = cache[url]
    else:
        try:
            req = requests.get(url)
            req_content = req.content
            cache[url] = req_content
        except Exception as e:
            raise(Exception(f"ERROR - Failed to get Splunk App Enrichment at {SPLUNKBASE_API_URL}"))
    
    if force_cached_or_offline:
        cache.close()
    
    return req_content


class SplunkAppEnrichment():

    @classmethod
    def enrich_splunk_app(self, splunk_ta: str, force_cached_or_offline: bool = False) -> dict:
        
        appurl = SPLUNKBASE_API_URL + splunk_ta
        splunk_app_enriched = dict()
        
        try:
            
            content = requests_get_helper(appurl, force_cached_or_offline)
            response_dict = xmltodict.parse(content)
            
            # check if list since data changes depending on answer
            url, results = self._parse_splunkbase_response(response_dict)
            # grab the app name
            for i in results:
                if i['@name'] == 'appName':
                    splunk_app_enriched['name'] = i['#text']
            # grab out the splunkbase url  
            if 'entriesbyid' in url:
                content = requests_get_helper(url, force_cached_or_offline)
                response_dict = xmltodict.parse(content)
                
                #print(json.dumps(response_dict, indent=2))
                url, results = self._parse_splunkbase_response(response_dict)
                # chop the url so we grab the splunkbase portion but not direct download
                splunk_app_enriched['url'] = url.rsplit('/', 4)[0]
        except requests.exceptions.ConnectionError as connErr:
            print(f"There was a connErr for ta {splunk_ta}: {connErr}")
            # there was a connection error lets just capture the name
            splunk_app_enriched['name'] = splunk_ta
            splunk_app_enriched['url'] = ''
        except Exception as e:
            print(f"There was an unknown error enriching the Splunk TA [{splunk_ta}]: {str(e)}")
            splunk_app_enriched['name'] = splunk_ta
            splunk_app_enriched['url'] = ''


        return splunk_app_enriched

    def _parse_splunkbase_response(response_dict):
        if isinstance(response_dict['feed']['entry'], list):
            url = response_dict['feed']['entry'][0]['link']['@href']
            results = response_dict['feed']['entry'][0]['content']['s:dict']['s:key']
        else:
            url = response_dict['feed']['entry']['link']['@href']
            results = response_dict['feed']['entry']['content']['s:dict']['s:key']
        return url, results

