"""
Launches &quot;reputation analysis&quot; input playbooks, adds reputation reports, and then concludes the Response Tasks where this playbook appears.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'virustotal_v3_identifier_reputation_analysis' block
    virustotal_v3_identifier_reputation_analysis(container=container)
    # call 'phishtank_url_reputation_analysis' block
    phishtank_url_reputation_analysis(container=container)

    return

@phantom.playbook_block()
def markdown_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("markdown_filter() called")

    ################################################################################
    # Exclude Null playbook outputs
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["markdown_merge:custom_function_result.data.item", "!=", None]
        ],
        name="markdown_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_tasks(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def virustotal_v3_identifier_reputation_analysis(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("virustotal_v3_identifier_reputation_analysis() called")

    data_summary_dest_ip_value = container.get("data", {}).get("summary", {}).get("dest_ip", None)
    data_summary_src_ip_value = container.get("data", {}).get("summary", {}).get("src_ip", None)
    data_summary_url_value = container.get("data", {}).get("summary", {}).get("url", None)
    data_summary_dns_value = container.get("data", {}).get("summary", {}).get("dns", None)
    data_summary_src_dns_value = container.get("data", {}).get("summary", {}).get("src_dns", None)
    data_summary_file_hash_value = container.get("data", {}).get("summary", {}).get("file_hash", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.dest_ip","artifact:*.cef.src_ip","artifact:*.cef.url","artifact:*.cef.dns","artifact:*.cef.src_dns","artifact:*.cef.file_hash"])

    container_artifact_fields_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_fields_item_1 = [item[1] for item in container_artifact_data]
    container_artifact_fields_item_2 = [item[2] for item in container_artifact_data]
    container_artifact_fields_item_3 = [item[3] for item in container_artifact_data]
    container_artifact_fields_item_4 = [item[4] for item in container_artifact_data]
    container_artifact_fields_item_5 = [item[5] for item in container_artifact_data]

    ip_combined_value = phantom.concatenate(container_artifact_fields_item_0, container_artifact_fields_item_1, data_summary_dest_ip_value, data_summary_src_ip_value)
    url_combined_value = phantom.concatenate(container_artifact_fields_item_2, data_summary_url_value)
    domain_combined_value = phantom.concatenate(container_artifact_fields_item_3, container_artifact_fields_item_4, data_summary_dns_value, data_summary_src_dns_value)
    file_hash_combined_value = phantom.concatenate(container_artifact_fields_item_5, data_summary_file_hash_value)

    inputs = {
        "ip": ip_combined_value,
        "url": url_combined_value,
        "domain": domain_combined_value,
        "file_hash": file_hash_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/VirusTotal_v3_Identifier_Reputation_Analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/VirusTotal_v3_Identifier_Reputation_Analysis", container=container, name="virustotal_v3_identifier_reputation_analysis", callback=join_markdown_merge, inputs=inputs)

    return


@phantom.playbook_block()
def phishtank_url_reputation_analysis(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("phishtank_url_reputation_analysis() called")

    data_summary_url_value = container.get("data", {}).get("summary", {}).get("url", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.url"])

    container_artifact_fields_item_0 = [item[0] for item in container_artifact_data]

    url_combined_value = phantom.concatenate(container_artifact_fields_item_0, data_summary_url_value)

    inputs = {
        "url": url_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/PhishTank_URL_Reputation_Analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/PhishTank_URL_Reputation_Analysis", container=container, name="phishtank_url_reputation_analysis", callback=join_markdown_merge, inputs=inputs)

    return


@phantom.playbook_block()
def join_markdown_merge(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_markdown_merge() called")

    if phantom.completed(playbook_names=["virustotal_v3_identifier_reputation_analysis", "phishtank_url_reputation_analysis"]):
        # call connected block "markdown_merge"
        markdown_merge(container=container, handle=handle)

    return


@phantom.playbook_block()
def markdown_merge(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("markdown_merge() called")

    ################################################################################
    # Merges outputs from previous playbooks. Add or take away datapaths based on 
    # which input playbooks are present.
    ################################################################################

    virustotal_v3_identifier_reputation_analysis_output_markdown_report = phantom.collect2(container=container, datapath=["virustotal_v3_identifier_reputation_analysis:playbook_output:markdown_report"])
    phishtank_url_reputation_analysis_output_markdown_report = phantom.collect2(container=container, datapath=["phishtank_url_reputation_analysis:playbook_output:markdown_report"])

    virustotal_v3_identifier_reputation_analysis_output_markdown_report_values = [item[0] for item in virustotal_v3_identifier_reputation_analysis_output_markdown_report]
    phishtank_url_reputation_analysis_output_markdown_report_values = [item[0] for item in phishtank_url_reputation_analysis_output_markdown_report]

    parameters = []

    parameters.append({
        "input_1": virustotal_v3_identifier_reputation_analysis_output_markdown_report_values,
        "input_2": phishtank_url_reputation_analysis_output_markdown_report_values,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="markdown_merge", callback=markdown_filter)

    return


@phantom.playbook_block()
def filter_response_tasks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_response_tasks() called")

    ################################################################################
    # Locate the response task that contains this playbook in the suggestions
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["get_tasks:action_result.data.*.suggestions.playbooks.*.name", "==", "get_playbook_name:custom_function:output"]
        ],
        name="filter_response_tasks:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_task_note(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def get_tasks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_tasks() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Get all tasks from response template
    ################################################################################

    external_id_value = container.get("external_id", None)

    parameters = []

    if external_id_value is not None:
        parameters.append({
            "id": external_id_value,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get tasks", parameters=parameters, name="get_tasks", assets=["builtin_mc_connector"], callback=get_playbook_name)

    return


@phantom.playbook_block()
def get_playbook_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_playbook_name() called")

    ################################################################################
    # Get the current playbook name for the downstream block in case the playbook 
    # is used in a custom repo or the playbook name changes.
    ################################################################################

    get_playbook_name__output = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    get_playbook_name__output = phantom.get_playbook_info()[0]['name']
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="get_playbook_name:output", value=json.dumps(get_playbook_name__output))

    filter_response_tasks(container=container)

    return


@phantom.playbook_block()
def add_task_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_task_note() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Leave a closing note for the task associated with this playbook.
    ################################################################################

    external_id_value = container.get("external_id", None)
    filtered_cf_result_0 = phantom.collect2(container=container, datapath=["filtered-data:markdown_filter:condition_1:markdown_merge:custom_function_result.data.item"])
    filtered_result_0_data_filter_response_tasks = phantom.collect2(container=container, datapath=["filtered-data:filter_response_tasks:condition_1:get_tasks:action_result.data.*.id","filtered-data:filter_response_tasks:condition_1:get_tasks:action_result.data.*.phase_id","filtered-data:filter_response_tasks:condition_1:get_tasks:action_result.data.*.response_plan_id"])

    parameters = []

    # build parameters list for 'add_task_note' call
    for filtered_cf_result_0_item in filtered_cf_result_0:
        for filtered_result_0_item_filter_response_tasks in filtered_result_0_data_filter_response_tasks:
            if external_id_value is not None and filtered_cf_result_0_item[0] is not None and filtered_result_0_item_filter_response_tasks[0] is not None and filtered_result_0_item_filter_response_tasks[1] is not None and filtered_result_0_item_filter_response_tasks[2] is not None:
                parameters.append({
                    "id": external_id_value,
                    "title": "Reputation Report",
                    "content": filtered_cf_result_0_item[0],
                    "task_id": filtered_result_0_item_filter_response_tasks[0],
                    "phase_id": filtered_result_0_item_filter_response_tasks[1],
                    "response_plan_id": filtered_result_0_item_filter_response_tasks[2],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note", assets=["builtin_mc_connector"], callback=task_status_decision)

    return


@phantom.playbook_block()
def join_close_task_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_close_task_1() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_close_task_1_called"):
        return

    if phantom.completed(action_names=["add_task_note"]):
        # save the state that the joined function has now been called
        phantom.save_run_data(key="join_close_task_1_called", value="close_task_1")

        # call connected block "close_task_1"
        close_task_1(container=container, handle=handle)

    return


@phantom.playbook_block()
def close_task_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("close_task_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Close the task associated with this playbook. (Contains custom code)
    ################################################################################

    external_id_value = container.get("external_id", None)
    filtered_result_0_data_filter_response_tasks = phantom.collect2(container=container, datapath=["filtered-data:filter_response_tasks:condition_1:get_tasks:action_result.data.*.name","filtered-data:filter_response_tasks:condition_1:get_tasks:action_result.data.*.order","filtered-data:filter_response_tasks:condition_1:get_tasks:action_result.data.*.id"])

    parameters = []

    # build parameters list for 'close_task_1' call
    for filtered_result_0_item_filter_response_tasks in filtered_result_0_data_filter_response_tasks:
        if external_id_value is not None and filtered_result_0_item_filter_response_tasks[0] is not None and filtered_result_0_item_filter_response_tasks[1] is not None and filtered_result_0_item_filter_response_tasks[2] is not None:
            parameters.append({
                "id": external_id_value,
                "name": filtered_result_0_item_filter_response_tasks[0],
                "order": filtered_result_0_item_filter_response_tasks[1],
                "task_id": filtered_result_0_item_filter_response_tasks[2],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    new_param = []
    for item in parameters:
        item['status'] = "Ended"
        new_param.append(item)
    parameters = new_param
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update task", parameters=parameters, name="close_task_1", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def task_status_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("task_status_decision() called")

    ################################################################################
    # Determines if the task has been started before progressing to closed.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:filter_response_tasks:condition_1:get_tasks:action_result.data.*.status", "==", "Pending"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        start_task(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_close_task_1(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def start_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("start_task() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Start the task associated with this playbook. (Contains custom code)
    ################################################################################

    external_id_value = container.get("external_id", None)
    filtered_result_0_data_filter_response_tasks = phantom.collect2(container=container, datapath=["filtered-data:filter_response_tasks:condition_1:get_tasks:action_result.data.*.name","filtered-data:filter_response_tasks:condition_1:get_tasks:action_result.data.*.order","filtered-data:filter_response_tasks:condition_1:get_tasks:action_result.data.*.id"])

    parameters = []

    # build parameters list for 'start_task' call
    for filtered_result_0_item_filter_response_tasks in filtered_result_0_data_filter_response_tasks:
        if external_id_value is not None and filtered_result_0_item_filter_response_tasks[0] is not None and filtered_result_0_item_filter_response_tasks[1] is not None and filtered_result_0_item_filter_response_tasks[2] is not None:
            parameters.append({
                "id": external_id_value,
                "name": filtered_result_0_item_filter_response_tasks[0],
                "order": filtered_result_0_item_filter_response_tasks[1],
                "owner": "soar_automation_user",
                "task_id": filtered_result_0_item_filter_response_tasks[2],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    new_param = []
    for item in parameters:
        item['status'] = "Started"
        new_param.append(item)
    parameters = new_param

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update task", parameters=parameters, name="start_task", assets=["builtin_mc_connector"], callback=join_close_task_1)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return