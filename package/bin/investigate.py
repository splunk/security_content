
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

  def _generate_investigation_objects(self, detected_entities):
      investigations = []
      investigation = dict()

      # iterate through all the investigations
      for investigative_search in self.investigative_searches_to_run:

          # get the data we need from the investigative search
          investigative_search_name = investigative_search['search_name']
          search = investigative_search['search']
          investigative_entities = json.loads(investigative_search['entities'])
          investigation[investigative_search_name] = {}
          investigation[investigative_search_name]['final_search'] = ""
          investigation[investigative_search_name]['entity'] = []

          # iterate through all the detection entities and grab their results
          for entity_detected_name, entity_detected_value in detected_entities.items():

              # check if the detected entity matches that of the investigation
              if entity_detected_name in investigative_entities:
                # store the entity we replaced
                investigation[investigative_search_name]['entity'].append(entity_detected_name)
                entity_name = "{" + entity_detected_name + "}"

                # grab every value of that entity and perform the replacement, if already processed just overwrite
                for v in entity_detected_value['entity_results']:
                    if investigation[investigative_search_name]['final_search'] == "":
                        investigation[investigative_search_name]['final_search'] = (search.replace(entity_name, v))
                    else:
                        investigation[investigative_search_name]['final_search'] = investigation[investigative_search_name]['final_search'].replace(entity_name, v)

          # store investigation object in a list of investigations to execute
          #self.logger.info("investigate.py - INVESTIGATION OBJECT: {0} - SEARCH NAME {1}".format(investigation[investigative_search_name], investigative_search['search_name']))
          investigations.append(investigation)

      return investigations

  def _parse_results(self, job_results, job):

      # if there are results lets process them
      if job['resultCount'] > "0":
          # place to store results and entity results
          investigation_results = []

          # process results
          for result in job_results:
              # add store detection results
              investigation_results.append(dict(result))

          return investigation_results

  def _execute_investigations(self, investigations, earliest_time, latest_time, service):
    investigations_with_results = []

    for investigation in investigations:
        for investigation_name, investigation_value in investigation.items():
            kwargs = {"exec_mode": "normal", "earliest_time": earliest_time, "latest_time": latest_time}
            search = investigation_value['final_search']
            if search:
                #self.logger.info("investigate.py - INVESTIGATION SEARCH TO EXEC: {0}".format(json.dumps(search)))
                job = service.jobs.create(search, **kwargs)
                time.sleep(1)
                while True:
                    job.refresh()
                    if job['isDone'] == "1":
                        self.logger.info("investigate.py - finished investigative search: {0}".format(search))
                        break

                job_results = splunklib.results.ResultsReader(job.results())
                results = self._parse_results(job_results, job)
                investigation_value['results'] = results
                investigation_value['search_name'] = investigation_name
                investigations_with_results.append(investigation_value)
    return investigations_with_results


  def stream(self, records):
    
    search_results = self.search_results_info
    port = splunk.getDefault('port')
    service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port, owner = "nobody")
    savedsearches = service.saved_searches

    if hasattr(search_results, 'search_et') and hasattr(search_results, 'search_lt'):
        earliest_time = search_results.search_et
        latest_time = search_results.search_lt

    story = "Malicious PowerShell"
    collection_name = "story_results"
    collection = service.kvstore[collection_name]

    if collection_name in service.kvstore:
        self.logger.info("investigate.py - Collection: {0}".format(collection_name))

    for savedsearch in savedsearches:
      content = savedsearch.content
      if 'action.escu.analytic_story' in content and story in content['action.escu.analytic_story']:          
          if content['action.escu.search_type'] == 'investigative':                   
              self.investigative_searches_to_run = self._investigative_searches(content)
    
    detection_results = collection.data.query()

    # grab investigations to execute
    investigations = []
    for detection_result in detection_results:
      for each_result in detection_result['detections']:
        # Loop through values in the entities key 
          for entity in (each_result['entities']):
              investigations = self._generate_investigation_objects(entity)
              investigations_results = self._execute_investigations(investigations, earliest_time, latest_time, service)
              self.logger.info("investigate.py - INVESTIGATION RESULTS: {0}".format(json.dumps(investigations_results)))

    for record in records:        
      yield record


if __name__ == "__main__":
  dispatch(Investigate, sys.argv, sys.stdin, sys.stdout, __name__)

