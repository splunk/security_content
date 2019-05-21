import sys
import json
import splunk
import splunklib.client
import splunklib.results
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option


@Configuration(streaming=True, local=True)
class RunStoryCommand(GeneratingCommand):
    '''
    Class for the runstory SPL command
    '''
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
        detection = self.detection
        search_results = self.search_results_info
        earliest_time = self.earliest_time
        latest_time = self.latest_time

        port = splunk.getDefault('port')
        service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port)
        f = open("/Users/bpatel/splunk/splunk/etc/apps/DA-ESS-ContentUpdate/bin/demofile.txt", "w")
        f.write("Starting run story")

        searches_to_run = []
        context_searches_to_run = []
        investigative_searches_to_run = []
        support_searches_to_run = []
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
            '''Context and investigate data in splunk'''

            if content.has_key('action.escu.analytic_story') and story in content['action.escu.analytic_story'] and content['action.escu.search_type'] == 'contextual':
                context_data = {}
                context_data['search_name'] = content['action.escu.full_search_name']
                context_data['action.escu.fields_required'] = content['action.escu.fields_required']
                context_data['search'] = content['search']
                context_searches_to_run.append(context_data)

            if content.has_key('action.escu.analytic_story') and story in content['action.escu.analytic_story'] and content['action.escu.search_type'] == 'investigative':
                investigative_data = {}
                investigative_data['search_name'] = content['action.escu.full_search_name']
                investigative_data['action.escu.fields_required'] = content['action.escu.fields_required']
                investigative_data['search'] = content['search']
                investigative_searches_to_run.append(investigative_data)

        '''Open File'''

        #f.write("Context= " + str(context_searches_to_run) + "\n\n" )
        total_results_dict = {}
        test_results = {}
        runstory_results = {}

        for search in support_searches_to_run:

            kwargs = { "dispatch.earliest_time": "-30d@d" , "dispatch.latest_time": "-1d@d"}

            spl = search['search']
            f.write("Support search->>>>> " + spl + "\n" )
            if spl[0] != "|":
                spl = "| search %s" % spl
            job = service.jobs.create(spl, **kwargs)
            runstory_results['support_search'] = search['search_name']


            #time.sleep(2)
            while True:
                job.refresh()
                if job['isDone'] == "1":
                    break


        for search in searches_to_run:
            item_count = 0

            if hasattr(search_results, 'search_et') and hasattr(search_results, 'search_lt'):
                kwargs = { "dispatch.earliest_time": earliest_time, "dispatch.latest_time": latest_time}
            else:
                kwargs = {}

            spl = search['search']
            f.write("detection search->>>>> " + spl + "\n" )
            if spl[0] != "|":
                spl = "| search %s" % spl
            job = service.jobs.create(spl, **kwargs)


            #time.sleep(2)
            while True:
                job.refresh()
                if job['isDone'] == "1":
                    break

                #time.sleep(2)

            job_results = splunklib.results.ResultsReader(job.results())
            count=0
            #f.write(str(search['risk_object']))
            daftpunk=[]
            common_field = []



            for result in job_results:
                count = count + 1
                #f.write(str(dict(result)))
                daftpunk.append(dict(result))
                runstory_results['detection_results'] = daftpunk

                for key, value in result.items():
                    if key in search['risk_object']:
                        common_field.append(value)
                        runstory_results['common_field'] = common_field

            f.write("Checking comon results" +  str(common_field) +"\n\n")



            item_count += 1
            runstory_results['detection_name'] = search['search_name']



            runstory_results['num_search_results'] = item_count

            yield runstory_results

dispatch(RunStoryCommand, sys.argv, sys.stdin, sys.stdout, __name__)