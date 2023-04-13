"""
Launches &quot;attribute lookup&quot; input playbooks, creates events, and then concludes the Response Tasks where this playbook appears.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'azure_ad_graph_entity_attribute_lookup' block
    azure_ad_graph_entity_attribute_lookup(container=container)
    # call 'crowdstrike_device_attribute_lookup' block
    crowdstrike_device_attribute_lookup(container=container)

    return

@phantom.playbook_block()
def observable_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("observable_filter() called")

    ################################################################################
    # Exclude Null playbook outputs
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["observable_merge:custom_function_result.data.item", "!=", None]
        ],
        name="observable_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        create_events(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def azure_ad_graph_entity_attribute_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("azure_ad_graph_entity_attribute_lookup() called")

    data_summary_user_value = container.get("data", {}).get("summary", {}).get("user", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.user"])

    container_artifact_fields_item_0 = [item[0] for item in container_artifact_data]

    user_combined_value = phantom.concatenate(container_artifact_fields_item_0, data_summary_user_value)

    inputs = {
        "user": user_combined_value,
        "device": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Azure_AD_Graph_User_Attribute_Lookup", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Azure_AD_Graph_User_Attribute_Lookup", container=container, name="azure_ad_graph_entity_attribute_lookup", callback=join_observable_merge, inputs=inputs)

    return


@phantom.playbook_block()
def crowdstrike_device_attribute_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("crowdstrike_device_attribute_lookup() called")

    data_summary_dest_value = container.get("data", {}).get("summary", {}).get("dest", None)
    data_summary_src_value = container.get("data", {}).get("summary", {}).get("src", None)
    data_summary_dest_ip_value = container.get("data", {}).get("summary", {}).get("dest_ip", None)
    data_summary_src_ip_value = container.get("data", {}).get("summary", {}).get("src_ip", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.dest","artifact:*.cef.dest_ip","artifact:*.cef.src","artifact:*.cef.src_ip"])

    container_artifact_fields_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_fields_item_1 = [item[1] for item in container_artifact_data]
    container_artifact_fields_item_2 = [item[2] for item in container_artifact_data]
    container_artifact_fields_item_3 = [item[3] for item in container_artifact_data]

    device_combined_value = phantom.concatenate(container_artifact_fields_item_0, container_artifact_fields_item_1, container_artifact_fields_item_2, container_artifact_fields_item_3, data_summary_dest_value, data_summary_src_value, data_summary_dest_ip_value, data_summary_src_ip_value)

    inputs = {
        "device": device_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CrowdStrike_OAuth_API_Device_Attribute_Lookup", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CrowdStrike_OAuth_API_Device_Attribute_Lookup", container=container, name="crowdstrike_device_attribute_lookup", callback=join_observable_merge, inputs=inputs)

    return


@phantom.playbook_block()
def join_observable_merge(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_observable_merge() called")

    if phantom.completed(playbook_names=["azure_ad_graph_entity_attribute_lookup", "crowdstrike_device_attribute_lookup"]):
        # call connected block "observable_merge"
        observable_merge(container=container, handle=handle)

    return


@phantom.playbook_block()
def observable_merge(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("observable_merge() called")

    ################################################################################
    # Merges outputs from previous playbooks. Add or take away datapaths based on 
    # which input playbooks are present.
    ################################################################################

    azure_ad_graph_entity_attribute_lookup_output_observable = phantom.collect2(container=container, datapath=["azure_ad_graph_entity_attribute_lookup:playbook_output:observable"])
    crowdstrike_device_attribute_lookup_output_observable = phantom.collect2(container=container, datapath=["crowdstrike_device_attribute_lookup:playbook_output:observable"])

    azure_ad_graph_entity_attribute_lookup_output_observable_values = [item[0] for item in azure_ad_graph_entity_attribute_lookup_output_observable]
    crowdstrike_device_attribute_lookup_output_observable_values = [item[0] for item in crowdstrike_device_attribute_lookup_output_observable]

    parameters = []

    parameters.append({
        "input_1": azure_ad_graph_entity_attribute_lookup_output_observable_values,
        "input_2": crowdstrike_device_attribute_lookup_output_observable_values,
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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="observable_merge", callback=observable_filter)

    return


@phantom.playbook_block()
def create_events(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_events() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Create new events with the outputs of the dispatch lookup (Contains custom code)
    ################################################################################

    external_id_value = container.get("external_id", None)
    filtered_cf_result_0 = phantom.collect2(container=container, datapath=["filtered-data:observable_filter:condition_1:observable_merge:custom_function_result.data.item"])

    parameters = []

    # build parameters list for 'create_events' call
    for filtered_cf_result_0_item in filtered_cf_result_0:
        if external_id_value is not None:
            parameters.append({
                "pairs": [
                    { "name": "Placeholder", "value": filtered_cf_result_0_item[0] },
                ],
                "incident_id": external_id_value,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []
    
    for filtered_cf_result_0_item in filtered_cf_result_0:
        pairs = []
        for k,v in filtered_cf_result_0_item[0]['attributes'].items():
            pairs.append(
                {"name": k, "value": v}
            )
            
        parameters.append({
            "incident_id": external_id_value,
            "pairs": pairs
        })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create events", parameters=parameters, name="create_events", assets=["builtin_mc_connector"], callback=get_tasks)

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
    filtered_result_0_data_filter_response_tasks = phantom.collect2(container=container, datapath=["filtered-data:filter_response_tasks:condition_1:get_tasks:action_result.data.*.id","filtered-data:filter_response_tasks:condition_1:get_tasks:action_result.data.*.phase_id","filtered-data:filter_response_tasks:condition_1:get_tasks:action_result.data.*.response_plan_id"])

    parameters = []

    # build parameters list for 'add_task_note' call
    for filtered_result_0_item_filter_response_tasks in filtered_result_0_data_filter_response_tasks:
        if external_id_value is not None and filtered_result_0_item_filter_response_tasks[0] is not None and filtered_result_0_item_filter_response_tasks[1] is not None and filtered_result_0_item_filter_response_tasks[2] is not None:
            parameters.append({
                "id": external_id_value,
                "title": "Task Complete",
                "content": "MC Attribute Lookup created new events",
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