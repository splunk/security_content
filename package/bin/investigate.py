
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration
import sys
import json
import splunk
import splunklib.client
import splunklib.results
from splunklib.searchcommands.validators import Boolean
import splunk.mining.dcutils
import time
from datetime import datetime, timedelta

  
@Configuration()
class Investigate(StreamingCommand):

  logger = splunk.mining.dcutils.getLogger()
  def stream(self, records):

    investigative_search_name = []
    investigative_search_fields_required = []
    investigative_searches = []
    detection_results = []
    risk_object = []
    runstory_results = {}
    entities= []
    search_results = self.search_results_info
    port = splunk.getDefault('port')
    service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port)
    savedsearches = service.saved_searches

    if hasattr(search_results, 'search_et') and hasattr(search_results, 'search_lt'):
          earliest_time = search_results.search_et
          latest_time = search_results.search_lt

    for record in records: 

      detection_results.append(record['detection_results'])
      entities.append(record['entities'])
      investigative_search_name.append(record['investigative_search_name'])
      investigative_searches .append(record['investigative_searches'])
      risk_object.append(record['risk_object'])

      record['WIN'] = entities
      yield record

    self.logger.info("investigate.py - PRINTING THE RECORDS: {0}".format(entities))
    self.logger.info("investigate.py - PRINTING THE RECORDS: {0}".format(investigative_search_name))
    self.logger.info("investigate.py - PRINTING THE RECORDS: {0}".format(investigative_searches)) 





      #replace the values in the searches


      #Run the searches

      # for search in investigative_searches:

      #       kwargs = {"exec_mode": "normal", "earliest_time": earliest_time, "latest_time": latest_time}
      #       if search[0] != "|":
      #           search = "| search %s" % search
      #       job = service.jobs.create(search, **kwargs)


      #       time.sleep(2)
      #       while True:
      #           job.refresh()
      #           if job['isDone'] == "1":
      #               self.logger.info("investigate.py - Finished invesitigate search: {0}".format(search))
      #               break


      #       job_results = splunklib.results.ResultsReader(job.results())
            


     
      

if __name__ == "__main__":
  dispatch(Investigate, sys.argv, sys.stdin, sys.stdout, __name__)
