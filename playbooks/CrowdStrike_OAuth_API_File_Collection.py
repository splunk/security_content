"""
Accepts a hostname or device id as well as a file path as input and collects the file to the event File Vault from a device in Crowdstrike. An artifact is created from the collected file.  We then generate an observable report as well as a Markdown formatted report. Both reports can be customized based on user preference.
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
    list_session_files_result_data = phantom.collect2(container=container, datapath=["list_session_files:action_result.data.*.resources.*.sha256","list_session_files:action_result.data.*.resources.*.size"], action_results=results)
    get_session_file_result_data = phantom.collect2(container=container, datapath=["get_session_file:action_result.data.*.vault_document","get_session_file:action_result.summary.vault_id"], action_results=results)
    determine_get_status__file_name = json.loads(_ if (_ := phantom.get_run_data(key="determine_get_status:file_name")) != "" else "null")  # pylint: disable=used-before-assignment
    determine_get_status__status = json.loads(_ if (_ := phantom.get_run_data(key="determine_get_status:status")) != "" else "null")  # pylint: disable=used-before-assignment
    determine_get_status__status_detail = json.loads(_ if (_ := phantom.get_run_data(key="determine_get_status:status_detail")) != "" else "null")  # pylint: disable=used-before-assignment

    create_session_parameter_device_id = [item[0] for item in create_session_result_data]
    query_device_result_item_0 = [item[0] for item in query_device_result_data]
    list_session_files_result_item_0 = [item[0] for item in list_session_files_result_data]
    list_session_files_result_item_1 = [item[1] for item in list_session_files_result_data]
    get_session_file_result_item_0 = [item[0] for item in get_session_file_result_data]
    get_session_file_summary_vault_id = [item[1] for item in get_session_file_result_data]

    host_observables__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    host_observables__observable_array = []
    
    for device_id, hostname, file_hash, file_size, vault_document, vault_id in zip(create_session_parameter_device_id, query_device_result_item_0, list_session_files_result_item_0, list_session_files_result_item_1, get_session_file_result_item_0, get_session_file_summary_vault_id):
        file_artifacts = []
        for file_name, status, status_message in zip(determine_get_status__file_name, determine_get_status__status, determine_get_status__status_detail):
            # Initialize the observable dictionary            
            if status == "success":
                file_artifacts.append({
                    "name": file_name,
                    "status": status,
                    "status_detail": status_message,
                    "hashes": [
                        {
                            "value": file_hash,
                            "algorithm": "SHA-256",
                            "algorithm_id": 3
                        }
                    ],
                    "size": file_size,
                    "vault_document": vault_document,
                    "vault_id": vault_id
                })
            else:
                file_artifacts.append({
                    "name": file_name,
                    "status": status,
                    "status_detail": status_message
                })
        observable = {
            "source": "Crowdstrike OAuth API",         
            "type": "Endpoint",     
            "activity_name": "File Collection",
            "uid": device_id,
            "hostname": hostname,
            "file_artifacts": file_artifacts
        }
        
        # Add the observable to the array
        host_observables__observable_array.append(observable)
    
    # Debug output for verification
    #phantom.debug(host_observables__observable_array)
    
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
def format_file_collection_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_file_collection_report() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """Endpoint Files were collected by Splunk SOAR and an artifact was created. The table below summarizes the information gathered.\n\n| Device ID | Hostname | File Path | File Hash | Vault ID | Artifact ID | Status | Message |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n%%\n| {0} | {1} | `{2}` | {3} | {4} | {5} | {6} | `{7}` |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "create_session:action_result.parameter.device_id",
        "query_device:action_result.data.*.hostname",
        "list_session_files:action_result.data.*.resources.*.name",
        "list_session_files:action_result.data.*.resources.*.sha256",
        "get_session_file:action_result.summary.vault_id",
        "artifact_create:custom_function_result.data.artifact_id",
        "determine_get_status:custom_function:status",
        "determine_get_status:custom_function:status_detail"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_file_collection_report")

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

    phantom.act("create session", parameters=parameters, name="create_session", assets=["crowdstrike_oauth_api"], callback=run_admin_command_get)

    return


@phantom.playbook_block()
def run_admin_command_get(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_admin_command_get() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Gets the specified file based on the playbook input path
    ################################################################################

    playbook_input_path = phantom.collect2(container=container, datapath=["playbook_input:path"])
    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.device_id","query_device:action_result.parameter.context.artifact_id"], action_results=results)
    create_session_result_data = phantom.collect2(container=container, datapath=["create_session:action_result.summary.session_id","create_session:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'run_admin_command_get' call
    for playbook_input_path_item in playbook_input_path:
        for query_device_result_item in query_device_result_data:
            for create_session_result_item in create_session_result_data:
                if query_device_result_item[0] is not None and create_session_result_item[0] is not None:
                    parameters.append({
                        "data": playbook_input_path_item[0],
                        "command": "get",
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

    phantom.act("run admin command", parameters=parameters, name="run_admin_command_get", assets=["crowdstrike_oauth_api"], callback=determine_get_status)

    return


@phantom.playbook_block()
def list_session_files(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_session_files() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Lists the previous file we ran a get command on, which returns its SHA256 hash
    ################################################################################

    create_session_result_data = phantom.collect2(container=container, datapath=["create_session:action_result.summary.session_id","create_session:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'list_session_files' call
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

    phantom.act("list session files", parameters=parameters, name="list_session_files", assets=["crowdstrike_oauth_api"], callback=get_session_file)

    return


@phantom.playbook_block()
def get_session_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_session_file() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Downloads the RTR session file from the endpoint to the SOAR File Vault
    ################################################################################

    list_session_files_result_data = phantom.collect2(container=container, datapath=["list_session_files:action_result.data.*.resources.*.sha256","list_session_files:action_result.parameter.context.artifact_id"], action_results=results)
    playbook_input_path = phantom.collect2(container=container, datapath=["playbook_input:path"])
    create_session_result_data = phantom.collect2(container=container, datapath=["create_session:action_result.summary.session_id","create_session:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_session_file' call
    for list_session_files_result_item in list_session_files_result_data:
        for playbook_input_path_item in playbook_input_path:
            for create_session_result_item in create_session_result_data:
                if list_session_files_result_item[0] is not None and create_session_result_item[0] is not None:
                    parameters.append({
                        "file_hash": list_session_files_result_item[0],
                        "file_name": playbook_input_path_item[0],
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

    phantom.act("get session file", parameters=parameters, name="get_session_file", assets=["crowdstrike_oauth_api"], callback=create_file_artifact)

    return


@phantom.playbook_block()
def delete_session(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("delete_session() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Closes a Real Time Response (RTR) session with the endpoint
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

    phantom.act("delete session", parameters=parameters, name="delete_session", assets=["crowdstrike_oauth_api"], callback=format_file_collection_report)

    return


@phantom.playbook_block()
def create_file_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_file_artifact() called")

    ################################################################################
    # Create the JSON structure from the collected file metadata to create a SOAR 
    # artifact.
    ################################################################################

    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.device_id","query_device:action_result.data.*.hostname"], action_results=results)
    list_session_files_result_data = phantom.collect2(container=container, datapath=["list_session_files:action_result.data.*.resources.*.name","list_session_files:action_result.data.*.resources.*.sha256"], action_results=results)
    get_session_file_result_data = phantom.collect2(container=container, datapath=["get_session_file:action_result.data.*.vault_id"], action_results=results)
    run_admin_command_get_result_data = phantom.collect2(container=container, datapath=["run_admin_command_get:action_result.parameter.data"], action_results=results)

    query_device_result_item_0 = [item[0] for item in query_device_result_data]
    query_device_result_item_1 = [item[1] for item in query_device_result_data]
    list_session_files_result_item_0 = [item[0] for item in list_session_files_result_data]
    list_session_files_result_item_1 = [item[1] for item in list_session_files_result_data]
    get_session_file_result_item_0 = [item[0] for item in get_session_file_result_data]
    run_admin_command_get_parameter_data = [item[0] for item in run_admin_command_get_result_data]

    create_file_artifact__data = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    import os
    
    create_file_artifact__data = []
    for device_id, hostname, origFilepath, filehash, vault_id, fullpath in zip(query_device_result_item_0, query_device_result_item_1, list_session_files_result_item_0, list_session_files_result_item_1, get_session_file_result_item_0, run_admin_command_get_parameter_data):
        filename = os.path.basename(fullpath.replace('\\','/'))
        filepath = os.path.dirname(fullpath.replace('\\','/'))
        create_file_artifact__data = {
            "cef": {
                "deviceExternalId": device_id,
                "hostname": hostname,
                "origFilePath": origFilepath,
                "fileName": filename,
                "filePath": os.path.join(filepath.replace('/','\\'), ''),
                "fileHashSha256": filehash,
                "vaultId": vault_id
            }
        }

    #phantom.debug(f"File artifact data: {create_file_artifact__data}")
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="create_file_artifact:data", value=json.dumps(create_file_artifact__data))

    artifact_create(container=container)

    return


@phantom.playbook_block()
def artifact_create(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("artifact_create() called")

    ################################################################################
    # Creates a new artifact to store information about the file collected from Crowdstrike.
    ################################################################################

    id_value = container.get("id", None)
    create_file_artifact__data = json.loads(_ if (_ := phantom.get_run_data(key="create_file_artifact:data")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "name": "Collected File Artifact",
        "tags": None,
        "label": "collected_file",
        "severity": None,
        "cef_field": None,
        "cef_value": None,
        "container": id_value,
        "input_json": create_file_artifact__data,
        "cef_data_type": None,
        "run_automation": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="artifact_create", callback=delete_session)

    return


@phantom.playbook_block()
def determine_get_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("determine_get_status() called")

    ################################################################################
    # Check the results of the RTR get command to ensure it was indeed successful. 
    #  RTR commands are notably unreliable in how they report status, instead proving 
    # stdout and stderr information.
    ################################################################################

    run_admin_command_get_result_data = phantom.collect2(container=container, datapath=["run_admin_command_get:action_result.status","run_admin_command_get:action_result.data.*.resources.*.stdout","run_admin_command_get:action_result.data.*.resources.*.stderr","run_admin_command_get:action_result.parameter.data","run_admin_command_get:action_result.message"], action_results=results)

    run_admin_command_get_result_item_0 = [item[0] for item in run_admin_command_get_result_data]
    run_admin_command_get_result_item_1 = [item[1] for item in run_admin_command_get_result_data]
    run_admin_command_get_result_item_2 = [item[2] for item in run_admin_command_get_result_data]
    run_admin_command_get_parameter_data = [item[3] for item in run_admin_command_get_result_data]
    run_admin_command_get_result_message = [item[4] for item in run_admin_command_get_result_data]

    determine_get_status__file_name = None
    determine_get_status__status = None
    determine_get_status__status_detail = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    determine_get_status__file_name = []
    determine_get_status__status = []
    determine_get_status__status_detail = []
    
    for file_name, status, stdout, stderr, message in zip(run_admin_command_get_parameter_data, run_admin_command_get_result_item_0, run_admin_command_get_result_item_1, run_admin_command_get_result_item_2,run_admin_command_get_result_message):
        #phantom.debug(f"file_name: {file_name}, status: {status}, stdout: {stdout}, stderr: {stderr}")
        determine_get_status__file_name.append(file_name)
        determine_get_status__status.append(status)
        if status == "success" and stdout.strip() and not stderr.strip():
            determine_get_status__status_detail.append(f"File collected: {stdout.strip()}")
        else:
            determine_get_status__status_detail.append(stderr.strip() if stderr else message)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="determine_get_status:file_name", value=json.dumps(determine_get_status__file_name))
    phantom.save_run_data(key="determine_get_status:status", value=json.dumps(determine_get_status__status))
    phantom.save_run_data(key="determine_get_status:status_detail", value=json.dumps(determine_get_status__status_detail))

    list_session_files(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_file_collection_report = phantom.get_format_data(name="format_file_collection_report")
    host_observables__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="host_observables:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "observable": host_observables__observable_array,
        "markdown_report": format_file_collection_report,
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