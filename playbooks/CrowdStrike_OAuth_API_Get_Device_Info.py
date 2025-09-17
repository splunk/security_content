"""
Given either a CrowdStrike device id (agentId) or a hostname, will query the device to get the other missing attribute.  This enables finding the hostname from a device id or the device id from a hostname and can be used in front of other CrowdStrike custom playbooks for added flexibility.
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
def format_fql(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_fql() called")

    ################################################################################
    # Format the FQL query to get the input device information using its Device ID 
    # or hostname.
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
def query_device(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("query_device() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Get information about the CrowdStrike device using its hostname or device id.
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

    phantom.act("query device", parameters=parameters, name="query_device", assets=["crowdstrike_oauth_api"], callback=format_output_data)

    return


@phantom.playbook_block()
def format_output_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_output_data() called")

    ################################################################################
    # This code block removes null values returned in some cases for device_id or 
    # hostname values.  It also provides a default value of "No results found" when 
    # nothing is returned.
    ################################################################################

    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.device_id","query_device:action_result.data.*.hostname"], action_results=results)

    query_device_result_item_0 = [item[0] for item in query_device_result_data]
    query_device_result_item_1 = [item[1] for item in query_device_result_data]

    format_output_data__device_ids = None
    format_output_data__hostnames = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    format_output_data__device_ids = [x for x in query_device_result_item_0 if x is not None] 
    format_output_data__hostnames = [x for x in query_device_result_item_1 if x is not None] 
    if not format_output_data__device_ids:
        format_output_data__device_ids = ["No result found"]
    if not format_output_data__hostnames:
        format_output_data__hostnames = ["No result found"]
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="format_output_data:device_ids", value=json.dumps(format_output_data__device_ids))
    phantom.save_run_data(key="format_output_data:hostnames", value=json.dumps(format_output_data__hostnames))

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_output_data__device_ids = json.loads(_ if (_ := phantom.get_run_data(key="format_output_data:device_ids")) != "" else "null")  # pylint: disable=used-before-assignment
    format_output_data__hostnames = json.loads(_ if (_ := phantom.get_run_data(key="format_output_data:hostnames")) != "" else "null")  # pylint: disable=used-before-assignment

    device_id_combined_value = phantom.concatenate(format_output_data__device_ids, dedup=True)
    hostname_combined_value = phantom.concatenate(format_output_data__hostnames, dedup=True)

    output = {
        "device_id": device_id_combined_value,
        "hostname": hostname_combined_value,
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