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


@Configuration(streaming=True,local=True)
class DetectCommand(GeneratingCommand):

    logger = splunk.mining.dcutils.getLogger()
    story = Option(require=True)
    risk = Option(validate=Boolean(), default=True)
    
    # global variables
    detection_searches_to_run = []
    investigative_searches_to_run = []
    support_searches_to_run = []
    runstory_results = {}
    collection_names = []

    def _support_searches(self, content):
        support_data = {}
        support_data['search_name'] = content['action.escu.full_search_name']
        support_data['search_description'] = content['description']
        support_data['search'] = content['search']
        self.support_searches_to_run.append(support_data)
        #self.logger.info("detect.py - prepping to run support search: {0}".format(support_data['search_name']))
        return self.support_searches_to_run

    def _investigative_searches(self, content):
        investigative_data = {}
        investigative_data['search_name'] = content['action.escu.full_search_name']
        investigative_data['search_description'] = content['description']
        investigative_data['search'] = content['search']
        self.investigative_searches_to_run.append(investigative_data)
        self.logger.info("invest.py - prepping to collect investigative_data: {0}".format(investigative_data['search_name']))
        return self.investigative_searches_to_run

    def _detection_searches(self, content):
        detection_data = {}
        detection_data['search_name'] = content['action.escu.full_search_name']
        detection_data['search_description'] = content['description']
        detection_data['search'] = content['search']
        detection_data['risk_object_type'] = content['action.risk.param._risk_object_type']
        detection_data['risk_score'] = content['action.risk.param._risk_score']
        detection_data['risk_object'] = content['action.risk.param._risk_object']
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
            self.logger.info("detect.py - running support search: {0}".format(search['search_name']))
            job = service.jobs.create(spl, **kwargs)
            while True:
                job.refresh()
                if job['isDone'] == "1":
                    self.logger.info("detect.py - completed support search: {0}".format(search['search_name']))
                    break
            # append each completed support search
            support_search_name.append(search['search_name'])

        return support_search_name

    def generate(self):
        story = self.story
        risk = self.risk      
        search_results = self.search_results_info
        port = splunk.getDefault('port')
        service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port, owner = "nobody")
        self.logger.info("detect.pytime - starting run story")

        if hasattr(search_results, 'search_et') and hasattr(search_results, 'search_lt'):
            earliest_time = search_results.search_et
            latest_time = search_results.search_lt

        savedsearches = service.saved_searches
        collection_name = []

        # for collection in service.kvstore:
        #     collection_name.append(collection.name)

        collection_name = "story_results"
        if collection_name in service.kvstore:
                service.kvstore.delete(collection_name)
    
    # Let's create it and then make sure it exists    
        service.kvstore.create(collection_name)
        collection_name = service.kvstore[collection_name]
            

        for savedsearch in savedsearches:
            content = savedsearch.content

            if 'action.escu.analytic_story' in content and story in content['action.escu.analytic_story']:
                if content['action.escu.search_type'] == 'support':
                    support_searches_to_run = self._support_searches(content)
                    self.runstory_results['support_search_name'] = self._run_support(support_searches_to_run, service,earliest_time,latest_time)
                # else:
                
                #    self.runstory_results['support_search_name'] = "No Support searches in this story"
                if content['action.escu.search_type'] == 'investigative':
                    investigative_searches_to_run = self._investigative_searches(content)
                    investigative_searches = []

                    for search in investigative_searches_to_run:
                        
                        investigative_searches.append(search['search_name'])
                    self.runstory_results['investigative_searches'] = investigative_searches

                if content['action.escu.search_type'] == 'detection':
                    detection_searches_to_run = self._detection_searches(content)

    # run all support searches and store its name to display later
        self.logger.info("detect.py - start support search:")
        
        self.logger.info("detect.py - start detection search:")

        #Running detections without a function in order to yield proper results back in splunk. Havent found a good way around this yet. 
        for search in detection_searches_to_run:

            self.runstory_results['detection_results'] = []
            kwargs = {"exec_mode": "normal", "earliest_time": earliest_time, "latest_time": latest_time}
            spl = search['search']
            self.logger.info("detect.py - running detection search: {0}".format(search['search_name']))
            if spl[0] != "|":
                spl = "| search %s" % spl
            job = service.jobs.create(spl, **kwargs)


            time.sleep(2)
            while True:
                job.refresh()
                if job['isDone'] == "1":
                    self.logger.info("detect.py - Finished Detection search: {0}".format(search['search_name']))
                    break


            job_results = splunklib.results.ResultsReader(job.results())
            

            if job['resultCount'] > "0":
                detection_results = []
                entities = []
                self.runstory_results['entities'] = []

                for result in job_results:
                    detection_results.append(dict(result))
                    for key, value in result.items():
                        if type(value) == list and key in search['risk_object']:
                            for i in value:
                                if i not in entities:
                                    entities.append(i)

                        if type(value) == str and key in search['risk_object'] and value not in entities:
                            entities.append(value)

                if risk == True:
                    for i in entities:
                        create_risk_score = "|makeresults" + "| eval story=\"" + \
                            story + "\""  + "| eval search_name=\"" + \
                            search['search_name'] + "\"" + "| eval risk_object = \"" + \
                            str(i) + "\"" + "| eval risk_score = \"" + search['risk_score'] + \
                            "\"" + "| eval risk_object_type = \"" + search['risk_object_type'] + \
                            "\"" + "| sendalert risk"

                        kwargs = {"exec_mode": "normal"}
                        job = service.jobs.create(create_risk_score, **kwargs)
                        while True:
                            job.refresh()
                            if job['isDone'] == "1":
                                break
                #Adding results to KV store

                collection_name.data.insert(json.dumps({"detection_search_name": search['search_name'], "detection_results": detection_results}))
                

                self.logger.info("detect.py - Results: {0}".format(detection_results))

                self.runstory_results['entities'] = entities
                self.runstory_results['detection_results'] = detection_results
                self.runstory_results['detection_result_count'] = job['resultCount']
                self.runstory_results['detection_search_name'] = search['search_name']
                self.runstory_results['mappings'] = search['mappings']
                self.runstory_results['risk_object_type'] = search['risk_object_type']
                self.runstory_results['risk_score'] = search['risk_score']
                self.runstory_results['risk_object'] = search['risk_object']
                self.runstory_results['collection_name'] = collection_name
                #self.run_story_results['investigative_searches'] = 
                #self.runstory_results['support_search_name'] = support_search_name
                yield {
                        '_time': time.time(),
                        '_raw': self.runstory_results,
                        'sourcetype': "_json",
                        'story': story,
                        'support_search_name': self.runstory_results['support_search_name'],
                        'entities': self.runstory_results['entities'],
                        'mappings': self.runstory_results['mappings'],
                        'detection_results': self.runstory_results['detection_results'],
                        'detection_search_name': self.runstory_results['detection_search_name'],
                        'detection_result_count': self.runstory_results['detection_result_count'],
                        'risk_score': self.runstory_results['risk_score'],
                        'risk_object_type': self.runstory_results['risk_object_type'],
                        'risk_object': self.runstory_results['risk_object'],
                        'investigative_search_name' : self.runstory_results['investigative_searches'],
                        'collection_name' : self.runstory_results['collection_name']
                     }



        self.logger.info("detect.py - FINSIHED detection search:")

        
        #self.logger.info("detect.py - FINAL object: {0}".format(self.runstory_results))

        
    def __init__(self):
            super(DetectCommand, self).__init__()

dispatch(DetectCommand, sys.argv, sys.stdin, sys.stdout, __name__)