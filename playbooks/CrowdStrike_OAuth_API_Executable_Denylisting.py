"""
Accepts a hostname or device id as well as a file hash as input and add an indicator (IOC) for a device in Crowdstrike. We then generate an observable report as well as a Markdown formatted report. Both reports can be customized based on user preference.
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
        logical_operator="and",
        conditions=[
            ["playbook_input:device", "!=", ""],
            ["playbook_input:hash", "!=", ""]
        ],
        name="input_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_fql(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def file_observables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("file_observables() called")

    ################################################################################
    # Format a normalized output for each host
    ################################################################################

    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.device_id","query_device:action_result.data.*.hostname"], action_results=results)
    filtered_input_0_hash = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_1:playbook_input:hash"])
    upload_indicator_result_data = phantom.collect2(container=container, datapath=["upload_indicator:action_result.status","upload_indicator:action_result.message"], action_results=results)

    query_device_result_item_0 = [item[0] for item in query_device_result_data]
    query_device_result_item_1 = [item[1] for item in query_device_result_data]
    filtered_input_0_hash_values = [item[0] for item in filtered_input_0_hash]
    upload_indicator_result_item_0 = [item[0] for item in upload_indicator_result_data]
    upload_indicator_result_message = [item[1] for item in upload_indicator_result_data]

    file_observables__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    file_observables__observable_array = []
    
    for device_id, hostname, file_hash, status, status_message in zip(query_device_result_item_0, query_device_result_item_1, filtered_input_0_hash_values, upload_indicator_result_item_0, upload_indicator_result_message):
        # Initialize the observable dictionary
        observable = {
            "source": "Crowdstrike OAuth API",
            "type": "Endpoint",
            "activity_name": "File Execution Prevention",
            "uid": device_id,
            "hostname": hostname,
            "status": status,
            "status_detail": status_message,
            "file": {
                "hashes": [
                    {
                        "algorithm": "SHA-256",
                        "algorithm_id": 3,
                        "value": file_hash 
                    }
                ]
            },
            "d3fend": {
                "d3f_tactic": "Isolate",
                "d3f_technique": "D3-EDL",
                "version": "1.0.0"
            }
        }   

        # Add the observable to the array
        file_observables__observable_array.append(observable)
    
    # Debug output for verification
    phantom.debug(file_observables__observable_array)
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="file_observables:observable_array", value=json.dumps(file_observables__observable_array))

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
    # Get information about the device to unquarantine using its hostname or device 
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

    phantom.act("query device", parameters=parameters, name="query_device", assets=["crowdstrike_oauth_api"], callback=upload_indicator)

    return


@phantom.playbook_block()
def format_executable_denylisting_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_executable_denylisting_report() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """Endpoint Files were denylisted by Splunk SOAR. The table below summarizes the information gathered.\n\n| Device ID | Executable Hash | Action | Denylisting Status | Message |\n| --- | --- | --- | --- | --- |\n%%\n| {0} | {1} | {2} | {3} | {4} |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "query_device:action_result.data.*.device_id",
        "filtered-data:input_filter:condition_1:playbook_input:hash",
        "upload_indicator:action_result.parameter.action",
        "upload_indicator:action_result.status",
        "upload_indicator:action_result.message"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_executable_denylisting_report")

    file_observables(container=container)

    return


@phantom.playbook_block()
def upload_indicator(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("upload_indicator() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Upload indicator that we want CrowdStrike to prevent and watch for all platforms.
    ################################################################################

    filtered_input_0_hash = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_1:playbook_input:hash"])

    parameters = []

    # build parameters list for 'upload_indicator' call
    for filtered_input_0_hash_item in filtered_input_0_hash:
        if filtered_input_0_hash_item[0] is not None:
            parameters.append({
                "ioc": filtered_input_0_hash_item[0],
                "action": "prevent",
                "source": "IOC uploaded via Splunk SOAR",
                "severity": "MEDIUM",
                "platforms": "linux,mac,windows",
                "description": "File Indicator blocked from Splunk SOAR",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("upload indicator", parameters=parameters, name="upload_indicator", assets=["crowdstrike_oauth_api"], callback=format_executable_denylisting_report)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_executable_denylisting_report = phantom.get_format_data(name="format_executable_denylisting_report")
    file_observables__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="file_observables:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "observable": file_observables__observable_array,
        "markdown_report": format_executable_denylisting_report,
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