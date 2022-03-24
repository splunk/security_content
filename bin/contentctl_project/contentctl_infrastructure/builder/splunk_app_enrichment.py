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
            # grab out the hosting url but first check if list since data changes depending on answer
            if isinstance(response_dict['feed']['entry'], list):
                url = response_dict['feed']['entry'][0]['link']['@href']
                results = response_dict['feed']['entry'][0]['content']['s:dict']['s:key']
            else:
                url = response_dict['feed']['entry']['link']['@href']
                results = response_dict['feed']['entry']['content']['s:dict']['s:key']
            for i in results:
                if i['@name'] == 'appName':
                    splunk_app_enriched['name'] = i['#text']
            if 'entriesbyid' in url:
                response = requests.get(appurl)
                response_dict = xmltodict.parse(response.content)
                splunk_app_enriched['url'] = url
        except requests.exceptions.ConnectionError as connErr:
            # there was a connection error lets just capture the name
            splunk_app_enriched['name'] = splunk_ta
            splunk_app_enriched['url'] = ''

        return splunk_app_enriched
