"""
Published in response to CVE-2021-44228, this playbook utilizes data already in your Splunk environment to help investigate and remediate impacts caused by this vulnerability in your environment.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_notable_history' block
    get_notable_history(container=container)
    # call 'get_process_info' block
    get_process_info(container=container)
    # call 'get_children_of_java' block
    get_children_of_java(container=container)
    # call 'es_assets' block
    es_assets(container=container)

    return

def get_notable_history(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_notable_history() called")

    template = """%%\n`notable` | search dest={0} | table _time, dest, rule_name, owner, priority, severity, status_description\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ip_or_hostname"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="get_notable_history")

    run_get_notable_history(container=container)

    return


def get_process_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_process_info() called")

    template = """%%\n`security_content_summariesonly` count values(Processes.process)\n  as process min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes\n where earliest=-7d by Processes.user Processes.parent_process_name Processes.process_name Processes.dest\n  | `drop_dm_object_name(\"Processes\")` | search  process_name= \"*java*\" | search\n  dest = {0} | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ip_or_hostname"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="get_process_info")

    run_get_process_info(container=container)

    return


def get_children_of_java(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_children_of_java() called")

    template = """%%\n`security_content_summariesonly` count values(Processes.process)\n  as process min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes\n  where earliest=-7d by Processes.user Processes.parent_process_name Processes.process_name Processes.dest\n  | `drop_dm_object_name(\"Processes\")` | search  parent_process_name= \"*java*\" | search dest = {0} |`security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ip_or_hostname"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="get_children_of_java")

    run_get_children_of_java(container=container)

    return


def es_assets(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("es_assets() called")

    template = """%%\nasset_lookup_by_str | search asset IN (\"{0}\") | eval category = mvjoin(category, \"; \")\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ip_or_hostname"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="es_assets")

    fetch_es_assets(container=container)

    return


def run_get_notable_history(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_get_notable_history() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_notable_history__as_list = phantom.get_format_data(name="get_notable_history__as_list")

    parameters = []

    if get_notable_history__as_list is not None:
        parameters.append({
            "query": get_notable_history__as_list,
            "command": "search",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []
    phantom.debug(get_notable_history__as_list)
    for formatted_item in get_notable_history__as_list:
        parameters.append({
            "query": formatted_item,
            "command": "search",
        })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_get_notable_history", assets=["splunk"])

    return


def run_get_process_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_get_process_info() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_process_info__as_list = phantom.get_format_data(name="get_process_info__as_list")

    parameters = []

    if get_process_info__as_list is not None:
        parameters.append({
            "query": get_process_info__as_list,
            "command": "tstats",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []
    phantom.debug(get_process_info__as_list)
    for formatted_item in get_process_info__as_list:
        parameters.append({
            "query": formatted_item,
            "command": "| tstats",
        })
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_get_process_info", assets=["splunk"])

    return


def run_get_children_of_java(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_get_children_of_java() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_children_of_java__as_list = phantom.get_format_data(name="get_children_of_java__as_list")

    parameters = []

    if get_children_of_java__as_list is not None:
        parameters.append({
            "query": get_children_of_java__as_list,
            "command": "tstats",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################


    parameters = []
    phantom.debug(get_children_of_java__as_list)
    for formatted_item in get_children_of_java__as_list:
        parameters.append({
            "query": formatted_item,
            "command": "| tstats",
        })
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_get_children_of_java", assets=["splunk"])

    return


def fetch_es_assets(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("fetch_es_assets() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    es_assets__as_list = phantom.get_format_data(name="es_assets__as_list")

    parameters = []

    if es_assets__as_list is not None:
        parameters.append({
            "query": es_assets__as_list,
            "command": "| inputlookup",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []
    phantom.debug(es_assets__as_list)
    for formatted_item in es_assets__as_list:
        parameters.append({
            "query": formatted_item,
            "command": "| inputlookup",
        })
        
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="fetch_es_assets", assets=["splunk"])

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return