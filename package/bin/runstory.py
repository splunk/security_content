#!/usr/bin/env python
import sys
import json
import time

import splunk

import splunklib.client
import splunklib.results

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option

@Configuration(streaming=True, local=True)
class RunStoryCommand(GeneratingCommand):
    '''
    Class for the runstory SPL command
    '''
    story = Option(require=True)

    def generate(self):
        story = self.story
        search_results = self.search_results_info

        port = splunk.getDefault('port')

        service = splunklib.client.connect(token=self._metadata.searchinfo.session_key, port=port)

        searches_to_run = []
        savedsearches = service.saved_searches
        for savedsearch in savedsearches:
            content = savedsearch.content
            if content.has_key('action.escu.analytic_story') and story in content['action.escu.analytic_story'] and content['action.escu.search_type'] == 'detection':
                search_data = {}
                search_data['search name'] = content['action.escu.full_search_name']
                search_data['search description'] = content['description']
                search_data['search'] = content['search']
                search_data['mappings'] = json.loads(content['action.escu.mappings'])
                searches_to_run.append(search_data)

        for search in searches_to_run:
            item_count = 0
            runstory_results = {}

            if hasattr(search_results, 'search_et') and hasattr(search_results, 'search_lt'):
                kwargs = {"exec_mode": "normal", "dispatch.earliest_time": search_results.search_et, "dispatch.latest_time": search_results.search_lt}
            else:
                kwargs = {"exec_mode": "normal"}

            spl = search['search']
            if spl[0] != "|":
                spl = "| search %s" % spl
            job = service.jobs.create(spl, **kwargs)
            runstory_results['name'] = search['search name']
            runstory_results['description'] = search['search description']
            runstory_results['kill_chain_phases'] = "-"
            if 'kill_chain_phases' in search['mappings'] and search['mappings']['kill_chain_phases']:
                runstory_results['kill_chain_phases'] = search['mappings']['kill_chain_phases']

            runstory_results['mitre_attack'] = "-"
            if 'mitre_attack' in search['mappings'] and search['mappings']['mitre_attack']:
                runstory_results['att&ck category'] = search['mappings']['mitre_attack']

            time.sleep(2)
            while True:
                job.refresh()
                if job['isDone'] == "1":
                    break

                time.sleep(2)

            job_results = splunklib.results.ResultsReader(job.results())
            for result in job_results:
                item_count += 1

            runstory_results['num_search_results'] = item_count
            yield runstory_results

dispatch(RunStoryCommand, sys.argv, sys.stdin, sys.stdout, __name__)
