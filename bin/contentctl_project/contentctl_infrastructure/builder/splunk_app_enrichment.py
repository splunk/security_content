import requests
import xmltodict

SPLUNKBASE_API_URL = "https://apps.splunk.com/api/apps/entriesbyid/"


class SplunkAppEnrichment():

    @classmethod
    def enrich_splunk_app(splunk_ta: str) -> dict:
        appurl = SPLUNKBASE_API_URL + splunk_ta
        response = requests.get(appurl)
        response_dict = xmltodict.parse(response.content)
        splunk_app_enriched = dict()
        url = response_dict['feed']['entry']['link']['@href']
        for i in response_dict['feed']['entry']['content']['s:dict']['s:key']:
            if i['@name'] == 'appName':
                splunk_app_enriched['name'] = i['#text']
        if 'entriesbyid' in url:
            response = requests.get(appurl)
            response_dict = xmltodict.parse(response.content)
            splunk_app_enriched['url'] = response_dict['feed']['entry']['link']['@href']
        return splunk_app_enriched
