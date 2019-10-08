from splunklib.searchcommands import dispatch, StreamingCommand, Configuration
import sys
import json
import splunk
import splunklib.client
import splunklib.results
from splunklib.searchcommands.validators import Boolean
import splunk.mining.dcutils
import time
import re
from datetime import datetime, timedelta


@Configuration()
class Investigate(StreamingCommand):
    logger = splunk.mining.dcutils.getLogger()
    investigative_searches_to_run = []
    final_search = ""
    COLLECTION_NAME = "mp_detect_new"
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

    def _store_collections(self, collection, investigations_results):

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
                                # self.logger.info("investigate.py - finished investigative search: {0}".format(search))
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
        # results = self._parse_results(job_results, job)

        self.logger.info("investigate.py - XX Results --------------- : {0}")

        return investigations_with_results

    def _generate_investigation_objects(self, detected_entities):
        investigations = []

        # iterate through all the investigations
        for investigative_search in self.investigative_searches_to_run:
            # self.logger.info("investigate.py - {0} ".format(investigative_search['search_name']))
            if investigative_search['search_name'] == "ESCU - Get Parent Process Info":

                i = dict()

                # get the data we need from the investigative search
                search_name = investigative_search['search_name']
                search = investigative_search['search']
                investigative_entities = json.loads(investigative_search['entities'])

                for investigative_entity_name in investigative_entities:
                    # iterate through all the detection entities and grab their results
                    self.logger.info("investigate.py - {0} ".format(investigative_entity_name))
                    i[investigative_entity_name] = []

                    for e in sorted(detected_entities):
                        # self.logger.info("investigate.py - search {0} - entities {1} ".format(investigative_search['search_name'],e))
                        for detected_entity_name, detected_entity_value in sorted(e.items()):
                            if investigative_entity_name == detected_entity_name:
                                self.logger.info(
                                    "investigate.py - investigative_entity_name {2} | detected_entity_name {0} | detected_entity_value {1} ".format(
                                        detected_entity_name, detected_entity_value, investigative_entity_name))
                                for v in detected_entity_value['entity_results']:
                                    i[investigative_entity_name].append(v)


                self.logger.info("investigate.py {0} ||| object: {1}".format(search_name, json.dumps(i, indent=4)))
                searches = {}
                searches['searches'] = []
                searches['entities'] = []
                searches['values'] = []
                for entity_name, values in sorted(i.items()):
                    modified_entity_name = "{" + entity_name + "}"
                    for v in values:

                        # check if this is not our first entity and if is not in the list then we must update all our searches
                        if len(searches['entities']) > 0 and entity_name not in searches['entities']:
                            # self.logger.info("investigate.py {0} ||| haven't seen entity: {1} | updated_search: {2}".format(search_name, entity_name, searches['searches']))
                            updated_searches = []

                            # update all searches store
                            for s in searches['searches']:
                                updated_search = s.replace(modified_entity_name, v)
                                updated_searches.append(updated_search)
                            searches['searches'] = updated_searches

                        searches['entities'].append(entity_name)
                        searches['values'].append(v)
                        updated_search = search.replace(modified_entity_name, v)
                        searches['searches'].append(updated_search)
                        # self.logger.info("investigate.py {0} ||| entity: {1} | updated_search: {2}".format(search_name, entity_name, updated_search))

                self.logger.info("investigate.py {0} ||| FINAL OBJECT | entity: {1} | values: {2} | searches: {3}".format(search_name, searches['entities'], searches['values'], json.dumps(searches['searches'], indent=4)))
                investigations.append(searches)
        return investigations


    def stream(self, records):

        search_results = self.search_results_info
        port = splunk.getDefault('port')
        service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port, owner="nobody")
        savedsearches = service.saved_searches

        if hasattr(search_results, 'search_et') and hasattr(search_results, 'search_lt'):
            earliest_time = search_results.search_et
            latest_time = search_results.search_lt

        collection = service.kvstore[self.COLLECTION_NAME]

        if self.COLLECTION_NAME in service.kvstore:
            self.logger.info("investigate.py - Collection: {0}".format(self.COLLECTION_NAME))

        for savedsearch in savedsearches:
            content = savedsearch.content
            if 'action.escu.analytic_story' in content:
                stories = str(content['action.escu.analytic_story']).strip('][').replace('"', '').split(', ')
                for s in stories:
                    if s == self.STORY and content['action.escu.search_type'] == 'investigative':
                        self.investigative_searches_to_run = self._investigative_searches(content)

        detection_results = (collection.data.query())

        # grab investigations to execute
        collection_results = {}
        collection_results['investigations'] = []

        # testing investigation in KV store

        investigate_kvstore = "investigate_kvstore"
        if investigate_kvstore in service.kvstore:
            service.kvstore.delete(investigate_kvstore)

        # Let's create it and then make sure it exists
        service.kvstore.create(investigate_kvstore)
        investigate_collection = service.kvstore[investigate_kvstore]

        for detection_result in detection_results:
            for each_result in detection_result['detections']:

                # Generate invetigsation searches to run
                investigations = self._generate_investigation_objects(each_result['entities'])

                # Execute investigation searches
                # investigations_results = self._execute_investigations(investigations, earliest_time, latest_time, service)
                # self.logger.info("investigate.py - YY Results --------------- : {0}".format(investigations_results))

                    # self._store_collections(investigate_collection, investigations_results)
                    # investigation_final_results = []

                #     for i in investigations_results:

                #       investigation_final_results.append((i))

                # self.logger.info("investigate.py - ZZZZZ Results --------------- : {0}".format(investigation_final_results))
                # self.logger.info("investigate.py - Collection Enter: {0}")

                # collection_results['investigations'] = investigation_final_results
                # self.logger.info("investigate.py - Collection Entry: {0}".format(collection_results['investigations']))

                # collection.data.insert((collection_results))
                # self.logger.info("investigate.py - Collection Entry DONE: {0}")

        for record in records:
            yield record


if __name__ == "__main__":
    dispatch(Investigate, sys.argv, sys.stdin, sys.stdout, __name__)
