
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration
import sys
import json
import splunk
import splunklib.client
import splunklib.results
from splunklib.searchcommands.validators import Boolean
import splunk.mining.dcutils
# import time
# from datetime import datetime, timedelta
  
@Configuration()
class Investigate(StreamingCommand):

  logger = splunk.mining.dcutils.getLogger()
  def stream(self, records):
    for record in records: 

      search_results = self.search_results_info
      port = splunk.getDefault('port')
      service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port)
      self.logger.info("investigate.py")

      savedsearches = service.saved_searches
      investigative_search_name = []
      investigative_search_fields_required = []
      investigative_search = []
      detection_results = []


      for savedsearch in savedsearches:
        content = savedsearch.content

        if 'action.escu.analytic_story' in content:
          
          if content['action.escu.search_type'] == 'investigative':

            if content['action.escu.full_search_name'] in record['investigative_search_name']:
              investigative_search.append(content['search'])
              record['investigative_search'] = investigative_search
              detection_results.append(record['detection_results'])
              record['detection_resultsssssss'] = detection_results

     
      yield record

if __name__ == "__main__":
  dispatch(Investigate, sys.argv, sys.stdin, sys.stdout, __name__)
