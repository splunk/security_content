"""
Accepts a hostname or device id as well as a file path as input and restores the file from the File Vault to a device in Crowdstrike. We then generate an observable report as well as a Markdown formatted report. Both reports can be customized based on user preference.
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
            ["playbook_input:file", "!=", ""]
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
    run_admin_command_put_result_data = phantom.collect2(container=container, datapath=["run_admin_command_put:action_result.parameter.data","run_admin_command_put:action_result.status","run_admin_command_put:action_result.message"], action_results=results)
    run_admin_command_cd_result_data = phantom.collect2(container=container, datapath=["run_admin_command_cd:action_result.parameter.data"], action_results=results)

    create_session_parameter_device_id = [item[0] for item in create_session_result_data]
    query_device_result_item_0 = [item[0] for item in query_device_result_data]
    run_admin_command_put_parameter_data = [item[0] for item in run_admin_command_put_result_data]
    run_admin_command_put_result_item_1 = [item[1] for item in run_admin_command_put_result_data]
    run_admin_command_put_result_message = [item[2] for item in run_admin_command_put_result_data]
    run_admin_command_cd_parameter_data = [item[0] for item in run_admin_command_cd_result_data]

    host_observables__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    host_observables__observable_array = []
    
    for device_id, hostname, file_name, file_path, status, status_message in zip(create_session_parameter_device_id, query_device_result_item_0, run_admin_command_put_parameter_data, run_admin_command_cd_parameter_data, run_admin_command_put_result_item_1, run_admin_command_put_result_message):
        # Initialize the observable dictionary
        observable = {
            "source": "Crowdstrike OAuth API",         
            "type": "Endpoint",     
            "activity_name": "File Restore",
            "uid": device_id,
            "hostname": hostname,
            "status": status,
            "status_detail": status_message,
            "file_artifacts": {
                "name": file_name,
                "path": file_path
            },
            "d3fend": {
                "d3f_tactic": "Restore",
                "d3f_technique": "D3-RF",
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

    phantom.act("query device", parameters=parameters, name="query_device", assets=["crowdstrike_oauth_api"], callback=filter_file_artifacts_0)

    return


@phantom.playbook_block()
def format_file_restore_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_file_restore_report() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """Endpoint Files were restored by Splunk SOAR. The table below summarizes the information gathered.\n\n| Device ID | File Path | Restore Status |\n| --- | --- | --- |\n%%\n| {0} | {1} | {2} |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "query_device:action_result.data.*.device_id",
        "run_admin_command_put:action_result.parameter.data",
        "run_admin_command_put:action_result.status"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_file_restore_report")

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

    phantom.act("create session", parameters=parameters, name="create_session", assets=["crowdstrike_oauth_api"], callback=run_admin_command_cd)

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

    phantom.act("delete session", parameters=parameters, name="delete_session", assets=["crowdstrike_oauth_api"], callback=format_file_restore_report)

    return


@phantom.playbook_block()
def run_admin_command_put(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_admin_command_put() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Run the put admin command via Real Time Response (RTR)
    ################################################################################

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.fileName","artifact:*.id"])
    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.device_id","query_device:action_result.parameter.context.artifact_id"], action_results=results)
    create_session_result_data = phantom.collect2(container=container, datapath=["create_session:action_result.summary.session_id","create_session:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'run_admin_command_put' call
    for container_artifact_item in container_artifact_data:
        for query_device_result_item in query_device_result_data:
            for create_session_result_item in create_session_result_data:
                if query_device_result_item[0] is not None and create_session_result_item[0] is not None:
                    parameters.append({
                        "data": container_artifact_item[0],
                        "command": "put",
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

    phantom.act("run admin command", parameters=parameters, name="run_admin_command_put", assets=["crowdstrike_oauth_api"], callback=delete_session)

    return


@phantom.playbook_block()
def filter_file_artifacts_0(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_file_artifacts_0() called")

    ################################################################################
    # Filter to ensure the requested file to restore was found in the vent artifacts. 
    #  This playbook assumes the file to restore has been previously collected by 
    # the CrowdStrike_OAuth_API_File_Collection input playbook.
    # 
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["artifact:*.label", "==", "collected_file"],
            ["playbook_input:file", "in", "artifact:*.cef.fileName"]
        ],
        name="filter_file_artifacts_0:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        upload_put_file(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def upload_put_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("upload_put_file() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Upload the file to restore from the SOAR Vault to Crowdstrike.
    ################################################################################

    filtered_artifact_0_data_filter_file_artifacts_0 = phantom.collect2(container=container, datapath=["filtered-data:filter_file_artifacts_0:condition_1:artifact:*.cef.vaultId","filtered-data:filter_file_artifacts_0:condition_1:artifact:*.cef.fileName","filtered-data:filter_file_artifacts_0:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'upload_put_file' call
    for filtered_artifact_0_item_filter_file_artifacts_0 in filtered_artifact_0_data_filter_file_artifacts_0:
        if filtered_artifact_0_item_filter_file_artifacts_0[0] is not None:
            parameters.append({
                "comment": "File restored from Splunk SOAR",
                "vault_id": filtered_artifact_0_item_filter_file_artifacts_0[0],
                "file_name": filtered_artifact_0_item_filter_file_artifacts_0[1],
                "description": "File restored from Splunk SOAR via the CrowdStrike_OAuth_API_File_Restore playbook.",
                "context": {'artifact_id': filtered_artifact_0_item_filter_file_artifacts_0[2]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("upload put file", parameters=parameters, name="upload_put_file", assets=["crowdstrike_oauth_api"], callback=create_session)

    return


@phantom.playbook_block()
def run_admin_command_cd(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_admin_command_cd() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Run the cd admin command via Real Time Response (RTR) to set the working directory 
    # properly for the following put command.
    ################################################################################

    filtered_artifact_0_data_filter_file_artifacts_0 = phantom.collect2(container=container, datapath=["filtered-data:filter_file_artifacts_0:condition_1:artifact:*.cef.filePath","filtered-data:filter_file_artifacts_0:condition_1:artifact:*.id"])
    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.device_id","query_device:action_result.parameter.context.artifact_id"], action_results=results)
    create_session_result_data = phantom.collect2(container=container, datapath=["create_session:action_result.summary.session_id","create_session:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'run_admin_command_cd' call
    for filtered_artifact_0_item_filter_file_artifacts_0 in filtered_artifact_0_data_filter_file_artifacts_0:
        for query_device_result_item in query_device_result_data:
            for create_session_result_item in create_session_result_data:
                if query_device_result_item[0] is not None and create_session_result_item[0] is not None:
                    parameters.append({
                        "data": filtered_artifact_0_item_filter_file_artifacts_0[0],
                        "command": "cd",
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

    phantom.act("run admin command", parameters=parameters, name="run_admin_command_cd", assets=["crowdstrike_oauth_api"], callback=run_admin_command_put)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_file_restore_report = phantom.get_format_data(name="format_file_restore_report")
    host_observables__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="host_observables:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "observable": host_observables__observable_array,
        "markdown_report": format_file_restore_report,
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