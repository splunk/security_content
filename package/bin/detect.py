import sys
import json
import splunk
import splunklib.client
import splunklib.results
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option
from splunklib.searchcommands.validators import Boolean
import splunk.mining.dcutils
import time
from datetime import datetime, timedelta
import re


@Configuration(streaming=True, local=True)
class DetectCommand(GeneratingCommand):
    logger = splunk.mining.dcutils.getLogger()
    story = Option(require=True)

    # global variables
    detection_searches_to_run = []
    investigative_searches_to_run = []
    support_searches_to_run = []
    story_results = {}
    collection_names = []
    COLLECTION_NAME = "mp_detect_new"
    DETECT_INDEX = "detect_index"
    collection_results = {}

    def _support_searches(self, content):
        support_data = {}
        support_data['search_name'] = content['action.escu.full_search_name']
        support_data['search_description'] = content['description']
        support_data['search'] = content['search']
        self.support_searches_to_run.append(support_data)
        # self.logger.info("detect.py - prepping to run support search: {0}".format(support_data['search_name']))
        return self.support_searches_to_run

    def _investigative_searches(self, content):
        investigative_data = {}
        investigative_data['search_name'] = content['action.escu.full_search_name']
        investigative_data['search_description'] = content['description']
        investigative_data['search'] = content['search']
        investigative_data['fields_required'] = content['action.escu.fields_required']
        self.investigative_searches_to_run.append(investigative_data)
        return self.investigative_searches_to_run

    def _detection_searches(self, content):
        detection_data = {}
        detection_data['search_name'] = content['action.escu.full_search_name']
        detection_data['search_description'] = content['description']
        detection_data['search'] = content['search']
        detection_data['entities'] = content['action.escu.entities']
        detection_data['mappings'] = json.loads(content['action.escu.mappings'])
        self.detection_searches_to_run.append(detection_data)
        #self.logger.info("detect.py - prepping to run detection search: {0}".format(detection_data['search_name']))
        return self.detection_searches_to_run

    def _run_support(self, support_searches_to_run, service, earliest_time, latest_time):
        # Run all Support searches
        support_search_name = []

        for search in support_searches_to_run:
            # setup service job
            latest_support_time = earliest_time

            earliest_utc = datetime.utcfromtimestamp(earliest_time).strftime('%Y-%m-%d %H:%M:%S.%f')
            support_earliest_time = datetime.strptime(earliest_utc, '%Y-%m-%d %H:%M:%S.%f') - timedelta(days=30)
            support_earliest_time = support_earliest_time.strftime('%s')
            kwargs = {"exec_mode": "normal", "earliest_time": support_earliest_time, "latest_time": latest_support_time}
            spl = search['search']
            if spl[0] != "|":
                spl = "| search %s" % spl
            #self.logger.info("detect.py - running support search: {0}".format(search['search_name']))
            job = service.jobs.create(spl, **kwargs)
            if job['isFailed'] == True:
                self.logger.info("detect.py - NO support search: {0}".format(spl))
            while True:
                job.refresh()
                if job['isDone'] == "1":
                    self.logger.info("detect.py - completed support search: {0}".format(search['search_name']))
                    break
            # append each completed support search
            support_search_name.append(search['search_name'])

        return support_search_name

    def _process_entities(self, result, search, entity_results):
        for key, value in result.items():

            # Convert search['entities'] to a list
            entities = str(search['entities']).strip('][').replace('"', '').split(', ')

            # if the key exists lets append to it

            if key in entity_results:

                # if the result back is a list and its name is a entity lets store each value
                if type(value) == list and key in entities:
                    for i in value:
                        # if we haven't stored this value lets add it
                        if i not in entity_results[key]:
                            entity_results[key].append(i)

                # if the result is a string and is name is a entity of the detection lets store it

                if type(value) == str and key in entities and value not in entity_results[key]:
                    entity_results[key].append(value)

            else:
                # its the first time we see this entity lets create a list its values
                entity_results[key] = []
                if type(value) == list and key in entities:
                    for i in value:
                        # if we haven't stored this value lets add it
                        if i not in entity_results[key]:
                            entity_results[key].append(i)

                if type(value) == str and key in entities and value not in entity_results[key]:
                    entity_results[key].append(value)

        # lets build an entity object from the results and a list to store them in
        entity = {}
        for entity_name, entity_value in entity_results.items():

            # first check that the entity result is not empty
            if entity_value:
                if entity_name in entity.keys():
                    # self.logger.info( "detect.py - ENTITY name {0} EXISTS | ENTITY value {1} | SEARCH: {2}".format(entity_name,entity_value,search['search_name']))
                    for v in entity_value:
                        entity[entity_name]['count'] += 1
                        entity[entity_name]['entity_results'].append(v)
                else:
                    # self.logger.info("detect.py - ENTITY name {0} DOES NOT EXISTS | ENTITY value {1} | SEARCH: {2}".format(entity_name,entity_value,search['search_name']))
                    entity[entity_name] = {}
                    for v in entity_value:
                        if 'count' in entity[entity_name].keys():
                            entity[entity_name]['count'] += 1
                        else:
                            entity[entity_name]['count'] = 1
                        if 'entity_results' in entity[entity_name].keys():
                            entity[entity_name]['entity_results'].append(v)
                        else:
                            entity[entity_name]['entity_results'] = []
                            entity[entity_name]['entity_results'].append(v)
        return entity

    # Store Data in an index, not using this function
    def _store_index(self, service):

        indexes = service.indexes
        index = []
        for i in indexes:
            index.append(i.name)
        # Create an index if it doesnt exist
        if self.DETECT_INDEX not in index:
           detect_index = service.indexes.create(self.DETECT_INDEX)
        detect_index = service.indexes[self.DETECT_INDEX]
        mysocket = detect_index.attach()
        mysocket.send(json.dumps(self.collection_results))
        mysocket.close()

        self.logger.info("detect.py - DONE -----")

    def _store_collections(self, collection):

        self.collection_results['story'] = self.story
        self.collection_results['detections'] = self.story_results['detections']
        self.collection_results['executed_by'] = self.story_results['executed_by']
        collection.data.insert(json.dumps(self.collection_results))
        
    def _get_username(self, service):
        search = '| rest /services/authentication/current-context/context | fields + username'
        results = service.jobs.oneshot(search)
        username_results = splunklib.results.ResultsReader(results)
        username = next(iter(username_results))['username']
        self.story_results['executed_by'] = username

    def _process_job_results(self, job, job_results, search, support_search_name):

        # if there are results lets process them
        if job['resultCount'] > "0":
            # place to store results and entity results
            detection_results = []

            entities = []
            entity_results = dict()
            # process results
           
            epoch = []
            for result in job_results:
                for k,v in result.items():
                    if k == "firstTime":
                        first = int(time.mktime(time.strptime(v, '%m/%d/%Y %H:%M:%S')))
                        epoch.append(first)

                    if k == "lastTime":
                        last = int(time.mktime(time.strptime(v, '%m/%d/%Y %H:%M:%S')))
                        epoch.append(last)
                # add store detection results
                detection_results.append(dict(result))

                # lets process entity results now
                entity = self._process_entities(result, search, entity_results)

            entities.append(entity)

            #self.logger.info("detect.py - PROCESSED ENTITY {0} | SEARCH: {1}".format(entity, search['search_name']))
            if epoch:
                first_detection_time = min(epoch)
                first_detection_time = datetime.utcfromtimestamp(first_detection_time).strftime('%Y-%m-%d %H:%M:%S')

                last_detection_time= max(epoch)
                last_detection_time = datetime.utcfromtimestamp(last_detection_time).strftime('%Y-%m-%d %H:%M:%S')
            else:
                first_detection_time = ""
                last_detection_time = ""

            detection = {}
            detection['first_detection_time'] = first_detection_time
            detection['last_detection_time'] = last_detection_time
            detection['detection_result_count'] = job['resultCount']
            detection['detection_search_name'] = search['search_name']
            detection['mappings'] = search['mappings']
            detection['detection_results'] = detection_results
            detection['support_search_name'] = support_search_name
            detection['entities'] = entities
            self.story_results['detections'].append(detection)

        # Wondering if we want to tell the users that a particular detection search ran successfully and produced no results. 
        if job['resultCount'] == "0": 
            detection = {}           
            detection['first_detection_time'] = "null"
            detection['last_detection_time'] = "null"
            detection['detection_result_count'] = job['resultCount']
            detection['detection_search_name'] = search['search_name']
            detection['mappings'] = search['mappings']
            detection['detection_results'] = "null"
            detection['support_search_name'] = support_search_name
            detection['entities'] = "null"
            self.story_results['detections'].append(detection)



    def _run_detections(self, detection_searches_to_run, service, earliest_time, latest_time, support_search_name):
        # create an array to store our detections in
        self.story_results['detections'] = []

        # run detection searches
        for search in detection_searches_to_run:

            # set parameters for search
            kwargs = {"exec_mode": "normal", "earliest_time": earliest_time, "latest_time": latest_time}
            spl = search['search']
            #self.logger.info("detect.py - running detection search: {0}".format(search['search_name']))

            # add pipe if is missing
            if spl[0] != "|":
                spl = "| search %s" % spl

            # dispatch job
            job = service.jobs.create(spl, **kwargs)
            
            # we sleep for 2 seconds to not DOS Splunk with submitting searches
            time.sleep(2)


            # check for results, if done we process them
            while True:
                job.refresh()
                if job['isFailed'] == "1":
                    self.logger.info("detect.py - Failed detection search: {0}".format(spl))
                    #raise Exception('detect.py - The search: {0} failed to execute'.format(search['search_name']))
                    break

                if job['isDone'] == "1":
                    self.logger.info("detect.py - Finished Detection search: {0}".format(search['search_name']))
                    # process raw results with reader
                    job_results = splunklib.results.ResultsReader(job.results())

                    # process job results into detection objects extract the necessary keys
                    self._process_job_results(job, job_results, search, support_search_name)
                    break



    def generate(self):

        # connect to splunk and start execution
        port = splunk.getDefault('port')
        service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port, owner="nobody",app="DA-ESS-ContentUpdate")
        self.logger.info("detect.pytime - starting run story - {0} ".format(self.story))

        # get story name
        self.story_results['story'] = self.story

        # get username
        self._get_username(service)

        # get time window
        if hasattr(self.search_results_info, 'search_et') and hasattr(self.search_results_info, 'search_lt'):
            earliest_time = self.search_results_info.search_et
            latest_time = self.search_results_info.search_lt

        # get saved_searches
        savedsearches = service.saved_searches

        # create collection if it does not exists otherwise wipe it
        if self.COLLECTION_NAME in service.kvstore:
            service.kvstore.delete(self.COLLECTION_NAME)
        service.kvstore.create(self.COLLECTION_NAME)

        collection = service.kvstore[self.COLLECTION_NAME]

        detection_searches_to_run = []
        support_searches_to_run = []

        # get all savedsearches content
        for savedsearch in savedsearches:
            content = savedsearch.content
            
            # check we are on the right story
            if 'action.escu.analytic_story' in content:
               stories = str(content['action.escu.analytic_story']).strip('][').replace('"', '').split(', ')
               for s in stories:
        
                    if s == self.story:
    
                        # if it has a support search grab it otherwise replace its value with a message
                        # THIS CAN BE REMOVED AFTER BASELINE MODULE IS CONSTRUCTED
                        if content['action.escu.search_type'] == 'support':
                            support_searches_to_run = self._support_searches(content)
                            

                        # if it has detection searches grab it
                        if content['action.escu.search_type'] == 'detection':
                            detection_searches_to_run = self._detection_searches(content)

        # if detection to run is empty we likely got a incorrect story name
        if len(detection_searches_to_run) < 1:
            self.logger.error("detect.py - No detection searches in this story")

            raise Exception(
                'no detections found for story: {0} .. try a correct story name or check spelling'.format(self.story))
        if support_searches_to_run:
            support_search_name = self._run_support(support_searches_to_run, service,earliest_time,latest_time)
        else:
            support_search_name = ["No Support or Baseline search in this Analytic Story"]


        # now lets run all the detection searches and process their results into story_results['detections']
        self._run_detections(detection_searches_to_run, service, earliest_time, latest_time, support_search_name)
        self.logger.info("detect.py - detection searches run and processed -")

        
        # lets store results in a KVStore to run investigate.py on that store
        self._store_collections(collection)
        self.logger.info("detect.py - detection results added to KVSTore - {0} ".format(self.COLLECTION_NAME))
        self.logger.info("detect.py - COMPLETED")

        # Index the results
        #self._store_index(service)


        # Yield individual results after processing them to preserve field names 
        
        for result in self.story_results['detections']:
            result['executed_by'] = self.story_results['executed_by']
            result['story'] = self.story_results['story']

            yield {

            '_time': time.time(),
            '_raw': result,
            'sourcetype': "_json",
            'story': result['story'],
            'executed_by': result['executed_by'],
            'detection_result_count': result['detection_result_count'],
            'detection_search_name': result['detection_search_name'],
            'first_detection_time': result['first_detection_time'],
            'last_detection_time': result['last_detection_time'],
            'support_search_name': result['support_search_name'],
            'entities': result['entities'],
            'mappings': result['mappings'],
            'detection_results' : result['detection_results']
                  }


        

        

        

    def __init__(self):
        super(DetectCommand, self).__init__()


dispatch(DetectCommand, sys.argv, sys.stdin, sys.stdout, __name__)