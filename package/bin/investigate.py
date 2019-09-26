
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
  investigative_searches_to_run = []
  runstory_results={}
  final_search = ""

  def _investigative_searches(self, content):
        investigative_data = {}
        investigative_data['search_name'] = content['action.escu.full_search_name']
        investigative_data['search_description'] = content['description']
        investigative_data['search'] = content['search']
        investigative_data['entities'] = content['action.escu.entities']
        self.investigative_searches_to_run.append(investigative_data)
        return self.investigative_searches_to_run

  def _generate_investigation_objects(self,entity):
        for key, value in entity.items():
            
            for investigative_search in self.investigative_searches_to_run:
                search = investigative_search['search']
                search_name = investigative_search['search_name']
                investigative_entities = json.loads(investigative_search['entities'])
                
                if key in investigative_entities:
                  #self.logger.info("investigate.py - Collection: {0}".format(len(value['entity_results'])))
                  key = "{" + key + "}"
                  for v in value['entity_results']:                
                    self.final_search = (search.replace(key,v))
                    self.logger.info("investigate.py - Collection: {0}".format(self.final_search))

                  return self.final_search 
                    


  def stream(self, records):
    
    search_results = self.search_results_info
    port = splunk.getDefault('port')
    service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port, owner = "nobody")
    savedsearches = service.saved_searches

    if hasattr(search_results, 'search_et') and hasattr(search_results, 'search_lt'):
          earliest_time = search_results.search_et
          latest_time = search_results.search_lt
  
    common_entities = []
    investigative_searches = []
    story = "Malicious PowerShell"
    collection_name = "detectionresults"
    collection = service.kvstore[collection_name]
    

    if collection_name in service.kvstore:
        self.logger.info("investigate.py - Collection: {0}".format(collection_name))

    for savedsearch in savedsearches:
      content = savedsearch.content
      if 'action.escu.analytic_story' in content and story in content['action.escu.analytic_story']:          
          if content['action.escu.search_type'] == 'investigative':                   
              self.investigative_searches_to_run = self._investigative_searches(content)
    
    detection_results = collection.data.query()   
    for detection_result in detection_results:
      
      for each_result in detection_result['detections']:    

        # Loop through values in the entities key 
          for entity in (each_result['entities']):
              final_search = self._generate_investigation_objects(entity)
              #self.logger.info("investigate.py - FINAL SEARCH: {0}".format(final_search))

    for record in records:        
      yield record
            


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
