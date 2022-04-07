import requests
import xmltodict
import json
import functools
import pickle 

SPLUNKBASE_API_URL = "https://apps.splunk.com/api/apps/entriesbyid/"

APP_ENRICHMENT_CACHE_FILENAME = "APP_ENRICHMENT_CACHE.PICKLE"

@functools.cache
def requests_get_helper(url:str)->bytes:
    try:
        with open(APP_ENRICHMENT_CACHE_FILENAME, 'rb') as p:
            dat = pickle.load(p)
            if url in dat:
                return dat[url]
    except Exception as e:
        print(f"error loading pickle file {APP_ENRICHMENT_CACHE_FILENAME}- it probably didn't exist. we will create it")
        dat = {}
    
    req = requests.get(url)
    with open(APP_ENRICHMENT_CACHE_FILENAME, 'wb') as p:
        dat[url] = req.content
        pickle.dump(dat, p)
    
    return req.content


class SplunkAppEnrichment():

    @classmethod
    def enrich_splunk_app(self, splunk_ta: str) -> dict:
        appurl = SPLUNKBASE_API_URL + splunk_ta
        splunk_app_enriched = dict()
        try:
            content = requests_get_helper(appurl)
            
            response_dict = xmltodict.parse(content)
            # check if list since data changes depending on answer
            url, results = self._parse_splunkbase_response(response_dict)
            # grab the app name
            for i in results:
                if i['@name'] == 'appName':
                    splunk_app_enriched['name'] = i['#text']
            # grab out the splunkbase url  
            if 'entriesbyid' in url:
                content = requests_get_helper(url)
                response_dict = xmltodict.parse(content)
                #print(json.dumps(response_dict, indent=2))
                url, results = self._parse_splunkbase_response(response_dict)
                # chop the url so we grab the splunkbase portion but not direct download
                splunk_app_enriched['url'] = url.rsplit('/', 4)[0]
        except requests.exceptions.ConnectionError as connErr:
            # there was a connection error lets just capture the name
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

