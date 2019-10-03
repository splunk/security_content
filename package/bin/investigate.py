
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
  final_search = ""
  COLLECTION_NAME = "mp_detect"
  STORY = "Malicious PowerShell"
  collection_results = {}

  def _investigative_searches(self, content):
        investigative_data = {}
        investigative_data['search_name'] = content['action.escu.full_search_name']
        investigative_data['search_description'] = content['description']
        investigative_data['search'] = content['search']
        investigative_data['entities'] = content['action.escu.entities']
        self.investigative_searches_to_run.append(investigative_data)
        return self.investigative_searches_to_run

  # def _parse_results(self, job_results, job):

  #     # if there are results lets process them
  #     investigation_results = []
  #     if job['resultCount'] > "0":
  #         # place to store results and entity results          
  #        # process results
  #         for result in job_results:
  #             # add store detection results
  #             investigation_results.append(dict(result))

  #         return investigation_results

  def _store_collections(self, collection,investigations_results):
        
        self.collection_results['investigations'] = investigations_results
        collection.data.insert(json.dumps(self.collection_results))
        self.logger.info("investigate.py - Entered into KV: {0}")


  def _execute_investigations(self, investigations, earliest_time, latest_time, service):
    investigations_with_results = []   
        

    for investigation in investigations: 
        
        for investigation_name, investigation_value in investigation.items():

            kwargs = {"exec_mode": "normal", "earliest_time": earliest_time, "latest_time": latest_time}
            
            for search in investigation_value['final_search']: 
              
              search = search + "| head 1"
              test = {}   
              if search:
                  job = service.jobs.create(search, **kwargs)
                  time.sleep(1)
                  while True:
                      job.refresh()
                      if job['isDone'] == "1":
                          #self.logger.info("investigate.py - finished investigative search: {0}".format(search))
                          break

                  job_results = splunklib.results.ResultsReader(job.results())

                  investigation_results = []
                  
                  if job['resultCount'] > "0":
                      for result in job_results:
                          # add store detection results
                          investigation_results.append(dict(result))
                      
                      test['search_name'] = investigation_name
                      test['results'] = investigation_results
                      
                      investigations_with_results.append((test))
    #results = self._parse_results(job_results, job)

    self.logger.info("investigate.py - XX Results --------------- : {0}")
        
                      
    
    return investigations_with_results

  def _generate_investigation_objects(self, detected_entities):
      investigations = []

      # iterate through all the investigations
      for investigative_search in self.investigative_searches_to_run:
          
          investigation = dict()

          # get the data we need from the investigative search
          investigative_search_name = investigative_search['search_name']
          search = investigative_search['search']
          investigative_entities = json.loads(investigative_search['entities'])


          investigation[investigative_search_name] = {}          
          investigation[investigative_search_name]['entity'] = []

          final_search   = "" 
          final_search_object = []
          # iterate through all the detection entities and grab their results
          for entity_detected_name, entity_detected_value in detected_entities.items():

              # check if the detected entity matches that of the investigation              
              if entity_detected_name in investigative_entities:
                # store the entity we replaced 
                  entity_name = "{" + entity_detected_name + "}"
                  
                  #replace one one entitiy
                  if len(investigative_entities) == 1:

                      for v in entity_detected_value['entity_results']: 
                          final_search = ""     
                          if final_search == "":
                              final_search = (search.replace(entity_name, v))
                              investigation[investigative_search_name]['entity'].append(v)
                              final_search_object.append(final_search)


                  # # BROKEN - replace 2 different entities. replace all combinations of entities. Currenttly it replace one of the dests

                  if len(investigative_entities) == 2:
                    # grab every value of that entity and perform the replacement, if already processed just overwrite
                         
                      for v in entity_detected_value['entity_results']:
                          if final_search == "":
                              final_search = search.replace(entity_name, v)
                              investigation[investigative_search_name]['entity'].append(v)

                          else:
                              final_search = final_search.replace(entity_name, v)
                              investigation[investigative_search_name]['entity'].append(v)
                              final_search_object.append(final_search)

              investigation[investigative_search_name]['final_search'] = final_search_object

                       
          investigations.append(investigation)
    

      return investigations

  def stream(self, records):
    
    search_results = self.search_results_info
    port = splunk.getDefault('port')
    service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port, owner = "nobody")
    savedsearches = service.saved_searches

    if hasattr(search_results, 'search_et') and hasattr(search_results, 'search_lt'):
        earliest_time = search_results.search_et
        latest_time = search_results.search_lt

    collection = service.kvstore[self.COLLECTION_NAME]

    if self.COLLECTION_NAME in service.kvstore:
        self.logger.info("investigate.py - Collection: {0}".format(self.COLLECTION_NAME))

    for savedsearch in savedsearches:
      content = savedsearch.content
      if 'action.escu.analytic_story' in content and self.STORY in content['action.escu.analytic_story']:          
          if content['action.escu.search_type'] == 'investigative':                   
              self.investigative_searches_to_run = self._investigative_searches(content)
    
    detection_results = (collection.data.query())
    
    # grab investigations to execute
    collection_results = {}
    collection_results['investigations'] = []

    #testing investigation in KV store


    investigate_kvstore = "investigate_kvstore"
    if investigate_kvstore in service.kvstore:
        service.kvstore.delete(investigate_kvstore)
    
    # Let's create it and then make sure it exists    
    service.kvstore.create(investigate_kvstore)
    investigate_collection = service.kvstore[investigate_kvstore]
    
    
    for detection_result in detection_results:   

      for each_result in detection_result['detections']:
                
        # Loop through values in the entities key 
          for entity in each_result['entities']:

              # Generate invetigsation searches to run 
              investigations = self._generate_investigation_objects(entity)
              #self.logger.info("investigate.py - -------Collection: {0}".format(((investigations))))

              # Execute investigation searches          
              investigations_results = self._execute_investigations(investigations, earliest_time, latest_time, service)
              #self.logger.info("investigate.py - YY Results --------------- : {0}".format(investigations_results))

              self._store_collections(investigate_collection,investigations_results)
              #investigation_final_results = []
              
          #     for i in investigations_results:
                
          #       investigation_final_results.append((i))
    
          # self.logger.info("investigate.py - ZZZZZ Results --------------- : {0}".format(investigation_final_results))
          # self.logger.info("investigate.py - Collection Enter: {0}")

              # collection_results['investigations'] = investigation_final_results
              # self.logger.info("investigate.py - Collection Entry: {0}".format(collection_results['investigations']))

              # collection.data.insert((collection_results))
              # self.logger.info("investigate.py - Collection Entry DONE: {0}")


     
    for record in records:
      #record['investigations'] = json.dumps(investigations)

      yield record


if __name__ == "__main__":
  dispatch(Investigate, sys.argv, sys.stdin, sys.stdout, __name__)
