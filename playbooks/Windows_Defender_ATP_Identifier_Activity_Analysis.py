"""
Accepts a file_hash or domain name, and asks Windows Defender ATP for a list of devices that have interacted with each. It then produces a normalized output and summary table.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'routing_artifacts' block
    routing_artifacts(container=container)

    return

@phantom.playbook_block()
def routing_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("routing_artifacts() called")

    ################################################################################
    # Route SHA1 file hashes and domains respectively
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:file_hash", "!=", None]
        ],
        name="routing_artifacts:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_file_devices(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:domain", "!=", None]
        ],
        name="routing_artifacts:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        get_domain_devices(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def get_file_devices(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_file_devices() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_input_0_file_hash = phantom.collect2(container=container, datapath=["filtered-data:routing_artifacts:condition_1:playbook_input:file_hash"])

    parameters = []

    # build parameters list for 'get_file_devices' call
    for filtered_input_0_file_hash_item in filtered_input_0_file_hash:
        if filtered_input_0_file_hash_item[0] is not None:
            parameters.append({
                "file_hash": filtered_input_0_file_hash_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get file devices", parameters=parameters, name="get_file_devices", assets=["windows_defender_atp"], callback=filter_file_response)

    return


@phantom.playbook_block()
def get_domain_devices(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_domain_devices() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_input_0_domain = phantom.collect2(container=container, datapath=["filtered-data:routing_artifacts:condition_2:playbook_input:domain"])

    parameters = []

    # build parameters list for 'get_domain_devices' call
    for filtered_input_0_domain_item in filtered_input_0_domain:
        if filtered_input_0_domain_item[0] is not None:
            parameters.append({
                "domain": filtered_input_0_domain_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get domain devices", parameters=parameters, name="get_domain_devices", assets=["windows_defender_atp"], callback=filter_domain_response)

    return


@phantom.playbook_block()
def filter_file_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_file_response() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["get_file_devices:action_result.summary.{summaryVar}", ">", 0]
        ],
        name="filter_file_response:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_report_file(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_domain_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_domain_response() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["get_domain_devices:action_result.summary.{summaryVar}", ">", 0]
        ],
        name="filter_domain_response:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_report_domain(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_report_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_report_file() called")

    template = """SOAR searched for occurrences of `{0}` within your environment using Windows Defender ATP. The table below shows a summary of the information gathered.\n\n| File | Computer | Last IP Address | OS | Defender ATP ID | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} | {4} | Defender ATP |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_file_response:condition_1:get_file_devices:action_result.parameter.file_hash",
        "filtered-data:filter_file_response:condition_1:get_file_devices:action_result.data.*.computerDnsName",
        "filtered-data:filter_file_response:condition_1:get_file_devices:action_result.data.*.lastIpAddress",
        "filtered-data:filter_file_response:condition_1:get_file_devices:action_result.data.*.osPlatform",
        "filtered-data:filter_file_response:condition_1:get_file_devices:action_result.data.*.id"
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

    template = """SOAR searched for occurrences of `{0}` within your environment using Windows Defender ATP. The table below shows a summary of the information gathered.\n\n| Domain | Computer | Last IP Address | OS | Defender ATP ID | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} | {4} | Defender ATP |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_domain_response:condition_1:get_domain_devices:action_result.parameter.domain",
        "filtered-data:filter_domain_response:condition_1:get_domain_devices:action_result.data.*.computerDnsName",
        "filtered-data:filter_domain_response:condition_1:get_domain_devices:action_result.data.*.lastIpAddress",
        "filtered-data:filter_domain_response:condition_1:get_domain_devices:action_result.data.*.osPlatform",
        "filtered-data:filter_domain_response:condition_1:get_domain_devices:action_result.data.*.id"
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
    # Iterates through the objects returned by previous actions to create a list of 
    # devices, which is then appended to the rest of the Observable object that contains 
    # the context for that list
    ################################################################################

    filtered_result_0_data_filter_file_response = phantom.collect2(container=container, datapath=["filtered-data:filter_file_response:condition_1:get_file_devices:action_result.parameter.file_hash","filtered-data:filter_file_response:condition_1:get_file_devices:action_result.data","filtered-data:filter_file_response:condition_1:get_file_devices:action_result.summary.total_devices"])

    filtered_result_0_parameter_file_hash = [item[0] for item in filtered_result_0_data_filter_file_response]
    filtered_result_0_data = [item[1] for item in filtered_result_0_data_filter_file_response]
    filtered_result_0_summary_total_devices = [item[2] for item in filtered_result_0_data_filter_file_response]

    build_file_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    build_file_output__observable_array = []
    device_list = []
    indicator = filtered_result_0_parameter_file_hash[0]
    count = filtered_result_0_summary_total_devices[0]
    
    # Build list of device objects
    
    for item in filtered_result_0_data:
        device = item[0]
        device_filtered = {
            "name": device['computerDnsName'],
            "id": device['id'],
            "ip_address": device['lastIpAddress'],
            "operating_system": device['osPlatform']
        }
        device_list.append(device_filtered)
        
    # Build observable object
    
    observable_array = {
        "value": indicator,
        "type": "file_hash",
        "total_count": count,
        "source": "Defender ATP",
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
    # Iterates through the objects returned by previous actions to create a list of 
    # devices, which is then appended to the rest of the Observable object that contains 
    # the context for that list
    ################################################################################

    filtered_result_0_data_filter_domain_response = phantom.collect2(container=container, datapath=["filtered-data:filter_domain_response:condition_1:get_domain_devices:action_result.parameter.domain","filtered-data:filter_domain_response:condition_1:get_domain_devices:action_result.data","filtered-data:filter_domain_response:condition_1:get_domain_devices:action_result.summary.total_devices"])

    filtered_result_0_parameter_domain = [item[0] for item in filtered_result_0_data_filter_domain_response]
    filtered_result_0_data = [item[1] for item in filtered_result_0_data_filter_domain_response]
    filtered_result_0_summary_total_devices = [item[2] for item in filtered_result_0_data_filter_domain_response]

    build_domain_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    build_domain_output__observable_array = []
    device_list = []
    indicator = filtered_result_0_parameter_domain[0]
    count = filtered_result_0_summary_total_devices[0]
    
    # Build list of device objects
    
    for item in filtered_result_0_data:
        device = item[0]
        device_filtered = {
            "name": device['computerDnsName'],
            "id": device['id'],
            "ip_address": device['lastIpAddress'],
            "operating_system": device['osPlatform']
        }
        device_list.append(device_filtered)
        
    # Build observable object
    
    observable_array = {
        "value": indicator,
        "type": "domain",
        "total_count": count,
        "source": "Defender ATP",
        "identifier_activity": device_list
    }
    
    build_domain_output__observable_array.append(observable_array)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_domain_output:observable_array", value=json.dumps(build_domain_output__observable_array))

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