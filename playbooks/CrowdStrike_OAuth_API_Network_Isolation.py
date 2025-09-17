"""
Accepts a hostname or device id as input and attempts to isolate (quarantine) the device in Crowdstrike. We then generate an observable report as well as a Markdown formatted report from the results. Both reports can be customized based on user preference.
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
def input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("input_filter() called")

    ################################################################################
    # Determines if the provided inputs are present in the dataset.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:device", "!=", ""]
        ],
        name="input_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_fql(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def quarantine_device(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("quarantine_device() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Quarantines device in Crowdstrike given either a Sensor ID (device_id) or hostname.
    ################################################################################

    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.device_id","query_device:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'quarantine_device' call
    for query_device_result_item in query_device_result_data:
        parameters.append({
            "hostname": "",
            "device_id": query_device_result_item[0],
            "context": {'artifact_id': query_device_result_item[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("quarantine device", parameters=parameters, name="quarantine_device", assets=["crowdstrike_oauth_api"], callback=format_quarantine_report)

    return


@phantom.playbook_block()
def host_observables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("host_observables() called")

    ################################################################################
    # Format a normalized output for each host
    ################################################################################

    quarantine_device_result_data = phantom.collect2(container=container, datapath=["quarantine_device:action_result.parameter.device_id","quarantine_device:action_result.status","quarantine_device:action_result.message"], action_results=results)
    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.hostname"], action_results=results)

    quarantine_device_parameter_device_id = [item[0] for item in quarantine_device_result_data]
    quarantine_device_result_item_1 = [item[1] for item in quarantine_device_result_data]
    quarantine_device_result_message = [item[2] for item in quarantine_device_result_data]
    query_device_result_item_0 = [item[0] for item in query_device_result_data]

    host_observables__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    host_observables__observable_array = []
    
    for device_id, hostname, status, status_message in zip(quarantine_device_parameter_device_id, query_device_result_item_0, quarantine_device_result_item_1, quarantine_device_result_message):
        # Initialize the observable dictionary
        observable = {
            "source": "Crowdstrike OAuth API",         
            "type": "Endpoint",     
            "activity_name": "Network Isolation",
            "uid": device_id,
            "hostname": hostname,
            "status": status,
            "status_detail": status_message,
            "d3fend": {
                "d3f_tactic": "Isolate",
                "d3f_technique": "D3-NAM",
                "version": "1.0.0"
            }
        }

        # Add the observable to the array
        host_observables__observable_array.append(observable)
    
    # Debug output for verification
    phantom.debug(host_observables__observable_array)
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="host_observables:observable_array", value=json.dumps(host_observables__observable_array))

    return


@phantom.playbook_block()
def format_fql(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_fql() called")

    ################################################################################
    # Format the FQL query to get the input device information using its ID or hostname.
    ################################################################################

    template = """%%\nhostname:['{0}'],device_id:['{0}']\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:device"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_fql")

    query_device(container=container)

    return


@phantom.playbook_block()
def query_device(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("query_device() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Get information about the device to quarantine using its hostname or device 
    # id.
    ################################################################################

    format_fql__as_list = phantom.get_format_data(name="format_fql__as_list")

    parameters = []

    # build parameters list for 'query_device' call
    for format_fql__item in format_fql__as_list:
        parameters.append({
            "limit": 50,
            "filter": format_fql__item,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("query device", parameters=parameters, name="query_device", assets=["crowdstrike_oauth_api"], callback=quarantine_device)

    return


@phantom.playbook_block()
def format_quarantine_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_quarantine_report() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """An attempt to isolate device(s) was performed via Splunk SOAR. The table below summarizes the information gathered.\n\n| Device ID | DNS Name | Device Path | Quarantine Status |\n| --- | --- | --- | --- |\n%%\n| {0} | {1} | {2} | {3} |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "quarantine_device:action_result.data.*.id",
        "quarantine_device:action_result.parameter.hostname",
        "quarantine_device:action_result.data.*.path",
        "quarantine_device:action_result.status"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_quarantine_report")

    host_observables(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_quarantine_report = phantom.get_format_data(name="format_quarantine_report")
    host_observables__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="host_observables:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "observable": host_observables__observable_array,
        "markdown_report": format_quarantine_report,
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