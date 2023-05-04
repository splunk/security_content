"""
Accepts a file_hash or domain name, and asks CrowdStrike for a list of device IDs that have interacted with each. The list of IDs is then sent back to Crowdstrike to get more information, and then produces a normalized output and summary table.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'input_filter' block
    input_filter(container=container)

    return

@phantom.playbook_block()
def input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("input_filter() called")

    ################################################################################
    # Routing by indicator type
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:file", "!=", None]
        ],
        name="input_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        hunt_file(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:domain", "!=", None]
        ],
        name="input_filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        hunt_domain(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def hunt_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("hunt_file() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_input_0_file = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_1:playbook_input:file"])

    parameters = []

    # build parameters list for 'hunt_file' call
    for filtered_input_0_file_item in filtered_input_0_file:
        if filtered_input_0_file_item[0] is not None:
            parameters.append({
                "hash": filtered_input_0_file_item[0],
                "limit": 1000,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("hunt file", parameters=parameters, name="hunt_file", assets=["crowdstrike_oauth_api"], callback=file_results_filter)

    return


@phantom.playbook_block()
def hunt_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("hunt_domain() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_input_0_domain = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_2:playbook_input:domain"])

    parameters = []

    # build parameters list for 'hunt_domain' call
    for filtered_input_0_domain_item in filtered_input_0_domain:
        if filtered_input_0_domain_item[0] is not None:
            parameters.append({
                "limit": 1000,
                "domain": filtered_input_0_domain_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("hunt domain", parameters=parameters, name="hunt_domain", assets=["crowdstrike_oauth_api"], callback=domain_results_filter)

    return


@phantom.playbook_block()
def file_results_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("file_results_filter() called")

    ################################################################################
    # Only proceed if there are results
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["hunt_file:action_result.summary.device_count", ">", 0]
        ],
        name="file_results_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_systems_from_file(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def domain_results_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("domain_results_filter() called")

    ################################################################################
    # Only proceed if there are results
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["hunt_domain:action_result.summary.device_count", ">", 0]
        ],
        name="domain_results_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_systems_from_domain(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_report_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_report_file() called")

    template = """SOAR searched for occurrences of `{0}` within your environment using CrowdStrike. The table below shows a summary of the information gathered.\n\n| File | Computer | Last IP Address | OS | CrowdStrike AID | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} | {4} | CrowdStrike OAuth API |\n%%\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "hunt_file:action_result.parameter.hash",
        "get_systems_from_file:action_result.data.*.hostname",
        "get_systems_from_file:action_result.data.*.local_ip",
        "get_systems_from_file:action_result.data.*.os_version",
        "get_systems_from_file:action_result.parameter.id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_report_file")

    build_file_output(container=container)

    return


@phantom.playbook_block()
def format_report_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_report_domain() called")

    template = """SOAR searched for occurrences of `{0}` within your environment using CrowdStrike. The table below shows a summary of the information gathered.\n\n| Domain | Computer | Last IP Address | OS | CrowdStrike AID | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} | {4} | CrowdStrike OAuth API |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "hunt_domain:action_result.parameter.domain",
        "get_systems_from_domain:action_result.data.*.hostname",
        "get_systems_from_domain:action_result.data.*.local_ip",
        "get_systems_from_domain:action_result.data.*.os_version",
        "get_systems_from_domain:action_result.parameter.id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_report_domain")

    build_domain_output(container=container)

    return


@phantom.playbook_block()
def build_file_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_file_output() called")

    ################################################################################
    # First constructs a list of devices based upon details returned in previous actions, 
    # and then appends that list to the observable object which includes the context 
    # in which that list makes any sense
    ################################################################################

    hunt_file_result_data = phantom.collect2(container=container, datapath=["hunt_file:action_result.parameter.hash","hunt_file:action_result.summary.device_count"], action_results=results)
    get_systems_from_file_result_data = phantom.collect2(container=container, datapath=["get_systems_from_file:action_result.data"], action_results=results)

    hunt_file_parameter_hash = [item[0] for item in hunt_file_result_data]
    hunt_file_summary_device_count = [item[1] for item in hunt_file_result_data]
    get_systems_from_file_result_item_0 = [item[0] for item in get_systems_from_file_result_data]

    build_file_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################


    build_file_output__observable_array = []
    device_list = []
    indicator = hunt_file_parameter_hash[0]
    count = hunt_file_summary_device_count[0]
    
    # if AIDs that no longer exist saw the artifact, they can still 
    # be included in the middle of the hunt response, but will return
    # empty-ish objects from the `get system info` action, so we need
    # to length check them
        
    # Build devices list
    for item in get_systems_from_file_result_item_0:
        if len(item) > 0:
            device = item[0]
            device_filtered = {
                "name": device['hostname'],
                "id": device['device_id'],
                "ip_address": device['local_ip'],
                "operating_system": device['os_version']
            }
            device_list.append(device_filtered)
            
    
    # Build observable object
    observable_array = {
        "value": indicator,
        "type": "file",
        "total_count": len(device_list),
        "source": "Crowdstrike OAuth",
        "identifier_activity": device_list
    }
    
    build_file_output__observable_array.append(observable_array)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_file_output:observable_array", value=json.dumps(build_file_output__observable_array))

    return


@phantom.playbook_block()
def build_domain_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_domain_output() called")

    ################################################################################
    # First constructs a list of devices based upon details returned in previous actions, 
    # and then appends that list to the observable object which includes the context 
    # in which that list makes any sense
    ################################################################################

    hunt_domain_result_data = phantom.collect2(container=container, datapath=["hunt_domain:action_result.parameter.domain","hunt_domain:action_result.summary.device_count"], action_results=results)
    get_systems_from_domain_result_data = phantom.collect2(container=container, datapath=["get_systems_from_domain:action_result.data"], action_results=results)

    hunt_domain_parameter_domain = [item[0] for item in hunt_domain_result_data]
    hunt_domain_summary_device_count = [item[1] for item in hunt_domain_result_data]
    get_systems_from_domain_result_item_0 = [item[0] for item in get_systems_from_domain_result_data]

    build_domain_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################


    build_domain_output__observable_array = []
    device_list = []
    indicator = hunt_domain_parameter_domain[0]
    count = hunt_domain_summary_device_count[0]
    
    # Build devices list
    for item in get_systems_from_domain_result_item_0:
        
        # if AIDs that no longer exist saw the artifact, they can still 
        # be included in the middle of the hunt response, but will return
        # empty-ish objects from the `get system info` action, so we need
        # to length check them
        
        if len(item) > 0:
            device = item[0]
            device_filtered = {
                "name": device['hostname'],
                "id": device['device_id'],
                "ip_address": device['local_ip'],
                "operating_system": device['os_version']
            }
            device_list.append(device_filtered)
            
    
    # Build observable object
    observable_array = {
        "value": indicator,
        "type": "domain",
        "total_count": len(device_list),
        "source": "Crowdstrike OAuth",
        "identifier_activity": device_list
    }
    
    build_domain_output__observable_array.append(observable_array)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_domain_output:observable_array", value=json.dumps(build_domain_output__observable_array))

    return


@phantom.playbook_block()
def get_systems_from_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_systems_from_file() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_result_0_data_file_results_filter = phantom.collect2(container=container, datapath=["filtered-data:file_results_filter:condition_1:hunt_file:action_result.data.*.device_id"])

    parameters = []

    # build parameters list for 'get_systems_from_file' call
    for filtered_result_0_item_file_results_filter in filtered_result_0_data_file_results_filter:
        if filtered_result_0_item_file_results_filter[0] is not None:
            parameters.append({
                "id": filtered_result_0_item_file_results_filter[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get system info", parameters=parameters, name="get_systems_from_file", assets=["crowdstrike_oauth_api"], callback=format_report_file)

    return


@phantom.playbook_block()
def get_systems_from_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_systems_from_domain() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_result_0_data_domain_results_filter = phantom.collect2(container=container, datapath=["filtered-data:domain_results_filter:condition_1:hunt_domain:action_result.data.*.device_id"])

    parameters = []

    # build parameters list for 'get_systems_from_domain' call
    for filtered_result_0_item_domain_results_filter in filtered_result_0_data_domain_results_filter:
        if filtered_result_0_item_domain_results_filter[0] is not None:
            parameters.append({
                "id": filtered_result_0_item_domain_results_filter[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get system info", parameters=parameters, name="get_systems_from_domain", assets=["crowdstrike_oauth_api"], callback=format_report_domain)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_report_file = phantom.get_format_data(name="format_report_file")
    format_report_domain = phantom.get_format_data(name="format_report_domain")
    build_file_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_file_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    build_domain_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_domain_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    observable_combined_value = phantom.concatenate(build_file_output__observable_array, build_domain_output__observable_array)
    markdown_report_combined_value = phantom.concatenate(format_report_file, format_report_domain)

    output = {
        "observable": observable_combined_value,
        "markdown_report": markdown_report_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return