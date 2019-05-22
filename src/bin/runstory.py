import sys
import json
import splunk
import splunklib.client
import splunklib.results
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option
import splunk.mining.dcutils
import time

@Configuration(streaming=True, local=True)
class RunStoryCommand(GeneratingCommand):
    '''
    Class for the runstory SPL command
    '''
    logger = splunk.mining.dcutils.getLogger()

    story = Option(require = True)

    earliest_time = Option(doc='''
        **Syntax:** **domainlist=***<path>*
        **Description:** CSV file from which repeated random samples will be drawn
        ''', name = 'earliest_time', require = True)

    latest_time = Option(doc='''
        **Syntax:** **domainlist=***<path>*
        **Description:** CSV file from which repeated random samples will be drawn
        ''', name = 'latest_time', require = True)

    def generate(self):
        story = self.story
        search_results = self.search_results_info
        earliest_time = self.earliest_time
        latest_time = self.latest_time

        port = splunk.getDefault('port')
        service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port)
        f = open("/opt/splunk/etc/apps/DA-ESS-ContentUpdate/bin/errors2.txt", "w")
        f.write("Starting run story")
        searches_to_run = []
        context_searches_to_run = []
        investigative_searches_to_run = []
        support_searches_to_run = []
        runstory_results = {}
        savedsearches = service.saved_searches


        for savedsearch in savedsearches:
            content = savedsearch.content

            if content.has_key('action.escu.analytic_story') and story in content['action.escu.analytic_story'] and content['action.escu.search_type'] == 'support':
                support_data = {}
                support_data['search_name'] = content['action.escu.full_search_name']
                support_data['search_description'] = content['description']
                support_data['search'] = content['search']
                support_searches_to_run.append(support_data)

            if content.has_key('action.escu.analytic_story') and story in content['action.escu.analytic_story'] and content['action.escu.search_type'] == 'detection':
                search_data = {}
                search_data['search_name'] = content['action.escu.full_search_name']
                search_data['search_description'] = content['description']
                search_data['search'] = content['search']
                search_data['risk_object'] = "dest"
                search_data['mappings'] = json.loads(content['action.escu.mappings'])
                searches_to_run.append(search_data)

            if content.has_key('action.escu.analytic_story') and story in content['action.escu.analytic_story'] and content['action.escu.search_type'] == 'investigative':
                investigative_data = {}
                investigative_data['search_name'] = content['action.escu.full_search_name']
                investigative_data['action.escu.fields_required'] = content['action.escu.fields_required']
                investigative_data['search'] = content['search']
                investigative_searches_to_run.append(investigative_data)

        # Run all Support searches
        yield_results=[]
        support_search_name = []
        for search in support_searches_to_run:
            kwargs = { "exec_mode": "normal", "dispatch.earliest_time": "-1m" , "dispatch.latest_time": "now"}
            spl = search['search']
            #f.write("Support search->>>>> " + spl + "\n" )
            if spl[0] != "|":
                spl = "| search %s" % spl
            job = service.jobs.create(spl, **kwargs)

            #time.sleep(2)
            while True:
                job.refresh()
                if job['isDone'] == "1":
                    break
            support_search_name.append(search['search_name'])
        runstory_results['support_search'] = support_search_name

        # Run all Detection searches

        for search in searches_to_run:
            runstory_results['detection_results'] = []
            item_count = 0

            #if hasattr(search_results, 'search_et') and hasattr(search_results, 'search_lt'):
            kwargs = { "exec_mode": "normal","dispatch.earliest_time": "-1m", "dispatch.latest_time": "now"}
            spl = search['search']
            #f.write("detection search->>>>> " + spl + "\n" )
            if spl[0] != "|":
                spl = "| search %s" % spl
            job = service.jobs.create(spl, **kwargs)

            #time.sleep(2)
            while True:
                job.refresh()
                if job['isDone'] == "1":
                    break

            job_results = splunklib.results.ResultsReader(job.results())
            detection_results=[]
            common_field = []

            # Yield Results back into splunk
            runstory_results['common_field'] = []
            for result in job_results:
                item_count += 1
                detection_results.append(dict(result))

                for key, value in result.items():
                    if key in search['risk_object']:
                        if value not in common_field:
                            common_field.append(value)

            runstory_results['common_field'] = common_field
            runstory_results['detection_results'] = detection_results
            runstory_results['detection_name'] = search['search_name']
            runstory_results['num_search_results'] = item_count


            yield {
                        '_time': time.time(),
                        'support_name' : runstory_results['support_search'],
                        'common_field' : runstory_results['common_field'],
                        'detection_name': runstory_results['detection_name'],
                        'num_search_results': runstory_results['num_search_results'],
                        'detection_results': runstory_results['detection_results']
                }


dispatch(RunStoryCommand, sys.argv, sys.stdin, sys.stdout, __name__)
