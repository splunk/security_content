import sys
import json
import splunk
import splunklib.client
import splunklib.results
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option
import splunk.mining.dcutils
import time


@Configuration(streaming=True,local=True)
class DetectCommand(GeneratingCommand):

    logger = splunk.mining.dcutils.getLogger()
    story = Option(require=True)
    risk = Option(require=True)
    earliest_time = Option(doc='''
        **Syntax:** **domainlist=***<path>*
        **Description:** CSV file from which repeated random samples will be drawn
        ''', name='earliest_time', require=True)
    latest_time = Option(doc='''
        **Syntax:** **domainlist=***<path>*
        **Description:** CSV file from which repeated random samples will be drawn
        ''', name='latest_time', require=True)

    # global variables
    detection_searches_to_run = []
    investigative_searches_to_run = []
    support_searches_to_run = []
    runstory_results = {}

    def _support_searches(self, content):
        support_data = {}
        support_data['search_name'] = content['action.escu.full_search_name']
        support_data['search_description'] = content['description']
        support_data['search'] = content['search']
        self.support_searches_to_run.append(support_data)
        self.logger.info("detect.py - prepping to run support search: {0}".format(support_data['search_name']))
        return self.support_searches_to_run

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
        self.logger.info("detect.py - prepping to run detection search: {0}".format(detection_data['search_name']))
        return self.detection_searches_to_run

    def _run_support(self, support_searches_to_run, service):
        # Run all Support searches
        support_search_name = []
        for search in support_searches_to_run:
            # setup service job
            kwargs = {"exec_mode": "normal", "earliest_time": "-1d", "latest_time": "-1m"}
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

    def _run_detection(self, detection_searches_to_run, service,earliest_time,latest_time):
        # Run all Support searches
        detection_search_name = []
        
        for search in detection_searches_to_run:
            # setup service job
            kwargs = {"exec_mode": "normal", "earliest_time": earliest_time, "latest_time": latest_time}
            spl = search['search']
            if spl[0] != "|":
                spl = "| search %s" % spl
            self.logger.info("detect.py - running detection search: {0}".format(search['search_name']))
            job = service.jobs.create(spl, **kwargs)
            while True:
                job.refresh()
                if job['isDone'] == "1":
                    self.logger.info("detect.py - completed detection search: {0}".format(search['search_name']))
                    break

            job_results = splunklib.results.ResultsReader(job.results())
    
            #detection_results.append(job_results)
            detection_results = []

            # append each completed support search
            if job['resultCount'] > "0": 
                detection_search_name.append(search['search_name'])
                for result in job_results:
                    detection_results.append(dict(result))

        #self.logger.info("detect.py - FINAL object: {0}".format(detection_search_name))
        #self.logger.info("detect.py - FINAL object: {0}".format(detection_results))


        return detection_search_name, detection_results
            

    def generate(self):
        story = self.story
        risk = self.risk
        earliest_time = self.earliest_time
        latest_time = self.latest_time
        port = splunk.getDefault('port')
        service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port)
        self.logger.info("detect.py - starting run story")

        savedsearches = service.saved_searches

        for savedsearch in savedsearches:
            content = savedsearch.content

            if 'action.escu.analytic_story' in content and story in content['action.escu.analytic_story']:
                if content['action.escu.search_type'] == 'support':
                    support_searches_to_run = self._support_searches(content)
                if content['action.escu.search_type'] == 'detection':
                    detection_searches_to_run = self._detection_searches(content)

    # run all support searches and store its name to display later
        self.runstory_results['support_search_name'] = self._run_support(support_searches_to_run, service)

        self.runstory_results['detection_search_name'],self.runstory_results['detection_results'] = self._run_detection(detection_searches_to_run,service,earliest_time,latest_time)

        self.logger.info("detect.py - FINAL object: {0}".format(self.runstory_results['support_search_name']))
        yield {
                        '_time': time.time(),
                        '_raw': self.runstory_results,
                        'sourcetype': "_json",
                        'story': self.story,
                        'support_search_name': self.runstory_results['support_search_name'],
                        'detection_search_name': self.runstory_results['detection_search_name'],
                        'detection_results': self.runstory_results['detection_results']


                        }


        #self.logger.info("detect.py - JOB Results: {0}".format(self.runstory_results['job_results']))


        # Run all Detection searches
       # for search in detection_searches_to_run:
       #      self.runstory_results['detection_results'] = []
       #      kwargs = {"exec_mode": "normal", "earliest_time": earliest_time, "latest_time": latest_time}
       #      spl = search['search']
       #      if spl[0] != "|":
       #          spl = "| search %s" % spl
       #      job = service.jobs.create(spl, **kwargs)

       #      time.sleep(2)
       #      while True:
       #          job.refresh()
       #          if job['isDone'] == "1":
       #              break

       #      job_results = splunklib.results.ResultsReader(job.results())
          
       #      self.runstory_results['detection_result_count'] = job['resultCount']

       #      if job['resultCount'] > "0" and risk == "True":
       #          detection_results = []
       #          common_field = []
       #          self.runstory_results['common_field'] = []

       #          for result in job_results:

       #              detection_results.append(dict(result))

       #              for key, value in result.items():
       #                  if type(value) == list and key in search['risk_object']:
       #                      for i in value:
       #                          if i not in common_field:
       #                              common_field.append(i)

       #                  if type(value) == str and key in search['risk_object'] and value not in common_field:
       #                      common_field.append(value)

       #          for i in common_field:
       #              create_risk_score = "|makeresults" + "| eval search_name=\"" + \
       #                  search['search_name'] + "\"" + "| eval risk_object = \"" + \
       #                  str(i) + "\"" + "| eval risk_score = \"" + search['risk_score'] + \
       #                  "\"" + "| eval risk_object_type = \"" + search['risk_object_type'] + \
       #                  "\"" + "| sendalert risk"

       #              kwargs = {"exec_mode": "normal", "earliest_time": earliest_time, "latest_time": latest_time}

       #              job = service.jobs.create(create_risk_score, **kwargs)

       #              while True:
       #                  job.refresh()
       #                  if job['isDone'] == "1":
       #                      break
       #          self.runstory_results['common_field'] = common_field
       #          self.runstory_results['detection_results'] = detection_results
       #          self.runstory_results['detection_search_name'] = search['search_name']
       #          self.runstory_results['mappings'] = search['mappings']
       #          self.runstory_results['risk_object_type'] = search['risk_object_type']
       #          self.runstory_results['risk_score'] = search['risk_score']
       #          self.runstory_results['risk_object'] = search['risk_object']
       #          yield {
       #                  '_time': time.time(),
       #                  '_raw': self.runstory_results,
       #                  'sourcetype': "_json",
       #                  'story': self.story,
       #                  'support_search_name': self.runstory_results['support_search_name'],
       #                  'common_field': self.runstory_results['common_field'],
       #                  'mappings': self.runstory_results['mappings'],
       #                  'detection_search_name': self.runstory_results['detection_search_name'],
       #                  'detection_result_count': self.runstory_results['detection_result_count'],
       #                  'risk_score': self.runstory_results['risk_score'],
       #                  'risk_object_type': self.runstory_results['risk_object_type'],
       #                  'risk_object': self.runstory_results['risk_object']
       #               }

       #      if job['resultCount'] > "0" and risk == "False":
       #          detection_results = []
       #          common_field = []
       #          runstory_results['common_field'] = []
       #          for result in job_results:
       #              detection_results.append(dict(result))

       #              for key, value in result.items():
       #                  if key in search['risk_object'] and value not in common_field:
       #                      common_field.append(value)

       #                      self.runstory_results['common_field'] = common_field
       #          self.runstory_results['detection_results'] = detection_results
       #          self.runstory_results['detection_search_name'] = search['search_name']
       #          self.runstory_results['mappings'] = search['mappings']
       #          self.runstory_results['risk_object_type'] = search['risk_object_type']
       #          self.runstory_results['risk_score'] = search['risk_score']
       #          self.runstory_results['risk_object'] = search['risk_object']
       #          yield {
       #                  '_time': time.time(),
       #                  '_raw': self.runstory_results,
       #                  'sourcetype': "_json",
       #                  'story': self.story,
       #                  'support_search_name': self.runstory_results['support_search_name'],
       #                  'common_field': self.runstory_results['common_field'],
       #                  'mappings': self.runstory_results['mappings'],
       #                  'detection_search_name': self.runstory_results['detection_search_name'],
       #                  'detection_result_count': self.runstory_results['detection_result_count'],
       #                  'risk_score': self.runstory_results['risk_score'],
       #                  'risk_object_type': self.runstory_results['risk_object_type'],
       #                  'risk_object': self.runstory_results['risk_object']
       #               }
    def __init__(self):
            super(DetectCommand, self).__init__()

dispatch(DetectCommand, sys.argv, sys.stdin, sys.stdout, __name__)