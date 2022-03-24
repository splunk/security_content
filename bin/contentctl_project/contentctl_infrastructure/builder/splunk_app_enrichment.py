import requests
import xmltodict
import json

SPLUNKBASE_API_URL = "https://apps.splunk.com/api/apps/entriesbyid/"


class SplunkAppEnrichment():

    @classmethod
    def enrich_splunk_app(self, splunk_ta: str) -> dict:
        appurl = SPLUNKBASE_API_URL + splunk_ta
        splunk_app_enriched = dict()
        try:
            response = requests.get(appurl)
            response_dict = xmltodict.parse(response.content)
            # check if list since data changes depending on answer
            url, results = self._parse_splunkbase_response(response_dict)
            # grab the app name
            for i in results:
                if i['@name'] == 'appName':
                    splunk_app_enriched['name'] = i['#text']
            # grab out the splunkbase url  
            if 'entriesbyid' in url:
                response = requests.get(url)
                response_dict = xmltodict.parse(response.content)
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

