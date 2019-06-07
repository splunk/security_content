import sys
import json
import splunk
import splunklib.client
import splunklib.results
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option
import splunk.mining.dcutils
import time


@Configuration(streaming=True, local=True)
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

    def generate(self):
        story = self.story
        risk = self.risk
        earliest_time = self.earliest_time
        latest_time = self.latest_time
        detection_searches_to_run = []
        # investigative_searches_to_run = []
        support_searches_to_run = []
        runstory_results = {}
        port = splunk.getDefault('port')
        service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port)
        f = open("/opt/splunk/etc/apps/DA-ESS-ContentUpdate/bin/errors2.txt", "w")
        f.write("Starting run story")

        savedsearches = service.saved_searches

        for savedsearch in savedsearches:
            content = savedsearch.content

            if 'action.escu.analytic_story' in content and story in content['action.escu.analytic_story'] and \
                    content['action.escu.search_type'] == 'support':
                support_data = {}
                support_data['search_name'] = content['action.escu.full_search_name']
                support_data['search_description'] = content['description']
                support_data['search'] = content['search']
                support_searches_to_run.append(support_data)

            if 'action.escu.analytic_story' in content and story in content['action.escu.analytic_story'] and \
                    content['action.escu.search_type'] == 'detection':
                search_data = {}
                search_data['search_name'] = content['action.escu.full_search_name']
                search_data['search_description'] = content['description']
                search_data['search'] = content['search']
                search_data['risk_object_type'] = content['action.risk.param._risk_object_type']
                search_data['risk_score'] = content['action.risk.param._risk_score']
                search_data['risk_object'] = content['action.risk.param._risk_object']
                search_data['mappings'] = json.loads(content['action.escu.mappings'])
                detection_searches_to_run.append(search_data)

            # if content.has_key('action.escu.analytic_story') and story in content['action.escu.analytic_story'] and \
            #    content['action.escu.search_type'] == 'investigative':
            #     investigative_data = {}
            #     investigative_data['search_name'] = content['action.escu.full_search_name']
            #     investigative_data['action.escu.fields_required'] = content['action.escu.fields_required']
            #     investigative_data['search'] = content['search']
            #     investigative_searches_to_run.append(investigative_data)
        # Run all Support searches
        support_search_name = []
        for search in support_searches_to_run:
            kwargs = {"exec_mode": "normal", "earliest_time": "-31d", "latest_time": "-1d"}
            spl = search['search']
            # f.write("Support search->>>>> " + spl + "\n" )
            if spl[0] != "|":
                spl = "| search %s" % spl
            job = service.jobs.create(spl, **kwargs)

            # time.sleep(2)
            while True:
                job.refresh()
                if job['isDone'] == "1":
                    break
            support_search_name.append(search['search_name'])
        runstory_results['support_search_name'] = support_search_name

        # Run all Detection searches

        for search in detection_searches_to_run:
            runstory_results['detection_results'] = []
            kwargs = {"exec_mode": "normal", "earliest_time": earliest_time, "latest_time": latest_time}
            spl = search['search']
            # f.write("detection search->>>>> " + spl + "\n" )
            if spl[0] != "|":
                spl = "| search %s" % spl
            job = service.jobs.create(spl, **kwargs)

            time.sleep(2)
            while True:
                job.refresh()
                if job['isDone'] == "1":
                    break

            job_results = splunklib.results.ResultsReader(job.results())
            # f.write(str(type(job_results)))
            runstory_results['detection_result_count'] = job['resultCount']

            if job['resultCount'] > "0" and risk == "true":
                detection_results = []
                common_field = []
                runstory_results['common_field'] = []

                f.write("yess" + search['search_name'] + "\n\n")
                for result in job_results:

                    detection_results.append(dict(result))

                    for key, value in result.items():
                        if type(value) == list and key in search['risk_object']:
                            for i in value:
                                if i not in common_field:
                                    common_field.append(i)

                        if type(value) == str and key in search['risk_object'] and value not in common_field:
                            common_field.append(value)

                for i in common_field:
                    f.write("-------->>>>>>>" + str(i) + "\n\n")
                    create_risk_score = "|makeresults" + "| eval search_name=\"" + \
                        search['search_name'] + "\"" + "| eval risk_object = \"" + \
                        str(i) + "\"" + "| eval risk_score = \"" + search['risk_score'] + \
                        "\"" + "| eval risk_object_type = \"" + search['risk_object_type'] + \
                        "\"" + "| sendalert risk"

                    kwargs = {"exec_mode": "normal", "earliest_time": earliest_time, "latest_time": latest_time}

                    job = service.jobs.create(create_risk_score, **kwargs)

                    while True:
                        job.refresh()
                        if job['isDone'] == "1":
                            break
                runstory_results['common_field'] = common_field
                runstory_results['detection_results'] = detection_results
                runstory_results['detection_search_name'] = search['search_name']
                runstory_results['mappings'] = search['mappings']
                runstory_results['risk_object_type'] = search_data['risk_object_type']
                runstory_results['risk_score'] = search_data['risk_score']
                runstory_results['risk_object'] = search_data['risk_object']
                yield {
                        '_time': time.time(),
                        '_raw': runstory_results,
                        'sourcetype': "_json",
                        'story': story,
                        'support_search_name': runstory_results['support_search_name'],
                        'common_field': runstory_results['common_field'],
                        'mappings': runstory_results['mappings'],
                        'detection_search_name': runstory_results['detection_search_name'],
                        'detection_result_count': runstory_results['detection_result_count'],
                        'risk_score': runstory_results['risk_score'],
                        'risk_object_type': runstory_results['risk_object_type'],
                        'risk_object': runstory_results['risk_object']
                     }

            if job['resultCount'] > "0" and risk == "false":
                detection_results = []
                common_field = []
                runstory_results['common_field'] = []

                f.write("yess" + search['search_name'] + "\n\n")
                for result in job_results:
                    detection_results.append(dict(result))

                    for key, value in result.items():
                        if key in search['risk_object'] and value not in common_field:
                            common_field.append(value)

                runstory_results['common_field'] = common_field
                runstory_results['detection_results'] = detection_results
                runstory_results['detection_search_name'] = search['search_name']
                runstory_results['mappings'] = search['mappings']
                runstory_results['risk_object_type'] = search_data['risk_object_type']
                runstory_results['risk_score'] = search_data['risk_score']
                runstory_results['risk_object'] = search_data['risk_object']
                yield {
                        '_time': time.time(),
                        '_raw': runstory_results,
                        'sourcetype': "_json",
                        'story': story,
                        'support_search_name': runstory_results['support_search_name'],
                        'common_field': runstory_results['common_field'],
                        'mappings': runstory_results['mappings'],
                        'detection_search_name': runstory_results['detection_search_name'],
                        'detection_result_count': runstory_results['detection_result_count'],
                        'risk_score': runstory_results['risk_score'],
                        'risk_object_type': runstory_results['risk_object_type'],
                        'risk_object': runstory_results['risk_object']
                     }

    def __init__(self):
        super(DetectCommand, self).__init__()


dispatch(DetectCommand, sys.argv, sys.stdin, sys.stdout, __name__)
