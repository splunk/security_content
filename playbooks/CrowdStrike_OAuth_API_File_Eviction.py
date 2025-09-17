"""
Accepts a hostname or device id as well as a file path as input and deletes the file from a device in Crowdstrike. We then generate an observable report as well as a Markdown formatted report. Both reports can be customized based on user preference.
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
            ["playbook_input:path", "!=", ""]
        ],
        name="input_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_fql(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def host_observables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("host_observables() called")

    ################################################################################
    # Format a normalized output for each host
    ################################################################################

    create_session_result_data = phantom.collect2(container=container, datapath=["create_session:action_result.parameter.device_id"], action_results=results)
    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.hostname"], action_results=results)
    run_admin_command_rm_result_data = phantom.collect2(container=container, datapath=["run_admin_command_rm:action_result.parameter.data","run_admin_command_rm:action_result.data"], action_results=results)

    create_session_parameter_device_id = [item[0] for item in create_session_result_data]
    query_device_result_item_0 = [item[0] for item in query_device_result_data]
    run_admin_command_rm_parameter_data = [item[0] for item in run_admin_command_rm_result_data]
    run_admin_command_rm_result_item_1 = [item[1] for item in run_admin_command_rm_result_data]

    host_observables__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    host_observables__observable_array = []
    i = 0
    
    for system in run_admin_command_rm_result_item_1:
        # Handle case where multiple files are listed on the same host.
        device_id = create_session_parameter_device_id[i] if i < len(create_session_parameter_device_id) else create_session_parameter_device_id[0]
        hostname = query_device_result_item_0[i] if i < len(query_device_result_item_0) else query_device_result_item_0[0]
        
        # Initialize the observable dictionary
        observable = {
            "source": "Crowdstrike OAuth API",
            "type": "Endpoint",
            "activity_name": "File Eviction",
            "uid": device_id,
            "hostname": hostname,
            "file_artifacts": [],
            "d3fend": {
                "d3f_tactic": "Evict",
                "d3f_technique": "D3-FEV",
                "version": "1.0.0"
            }
        }   
        
        for file in system[0]["resources"]:
            file_name = run_admin_command_rm_parameter_data[i]
            status = "success" if file["stdout"] and not file["stderr"] else "failed"
            status_message = file["stderr"] if file["stderr"] else file["stdout"]
            observable["file_artifacts"].append(
                {
                    "name": file_name,
                    "status": status,
                    "status_detail": status_message
                }
            )
        
        # Add the observable to the array
        host_observables__observable_array.append(observable)
        i+=1
    
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
    # Get information about the device using its hostname or device id.
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

    phantom.act("query device", parameters=parameters, name="query_device", assets=["crowdstrike_oauth_api"], callback=create_session)

    return


@phantom.playbook_block()
def format_file_eviction_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_file_eviction_report() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """Endpoint Files were removed by Splunk SOAR. The table below summarizes the information gathered.\n\n| Device ID | File Path | Eviction Status |\n| --- | --- | --- |\n%%\n| {0} | {1} | {2}{3} |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "query_device:action_result.data.*.device_id",
        "run_admin_command_rm:action_result.parameter.data",
        "run_admin_command_rm:action_result.data.*.resources.*.stdout",
        "run_admin_command_rm:action_result.data.*.resources.*.stderr"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_file_eviction_report")

    host_observables(container=container)

    return


@phantom.playbook_block()
def create_session(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_session() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Creates a Real Time Response (RTR) session to interact with the endpoint
    ################################################################################

    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.device_id","query_device:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'create_session' call
    for query_device_result_item in query_device_result_data:
        if query_device_result_item[0] is not None:
            parameters.append({
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

    phantom.act("create session", parameters=parameters, name="create_session", assets=["crowdstrike_oauth_api"], callback=run_admin_command_rm)

    return


@phantom.playbook_block()
def delete_session(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("delete_session() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Closes a Real Time Response (RTR) session to interact with the endpoint
    ################################################################################

    create_session_result_data = phantom.collect2(container=container, datapath=["create_session:action_result.summary.session_id","create_session:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'delete_session' call
    for create_session_result_item in create_session_result_data:
        if create_session_result_item[0] is not None:
            parameters.append({
                "session_id": create_session_result_item[0],
                "context": {'artifact_id': create_session_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("delete session", parameters=parameters, name="delete_session", assets=["crowdstrike_oauth_api"], callback=format_file_eviction_report)

    return


@phantom.playbook_block()
def run_admin_command_rm(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_admin_command_rm() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Run the rm admin command via Real Time Response (RTR)
    ################################################################################

    playbook_input_path = phantom.collect2(container=container, datapath=["playbook_input:path"])
    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.device_id","query_device:action_result.parameter.context.artifact_id"], action_results=results)
    create_session_result_data = phantom.collect2(container=container, datapath=["create_session:action_result.summary.session_id","create_session:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'run_admin_command_rm' call
    for playbook_input_path_item in playbook_input_path:
        for query_device_result_item in query_device_result_data:
            for create_session_result_item in create_session_result_data:
                if query_device_result_item[0] is not None and create_session_result_item[0] is not None:
                    parameters.append({
                        "data": playbook_input_path_item[0],
                        "command": "rm",
                        "device_id": query_device_result_item[0],
                        "session_id": create_session_result_item[0],
                        "context": {'artifact_id': create_session_result_item[1]},
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run admin command", parameters=parameters, name="run_admin_command_rm", assets=["crowdstrike_oauth_api"], callback=delete_session)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_file_eviction_report = phantom.get_format_data(name="format_file_eviction_report")
    host_observables__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="host_observables:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "observable": host_observables__observable_array,
        "markdown_report": format_file_eviction_report,
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