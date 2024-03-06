"""
Accepts message ID that needs to be evicted from provided email mailbox in Microsoft Office365. Generates an observable output based on the status of message eviction.\n\nRef: D3-ER\nhttps://d3fend.mitre.org/technique/d3f:EmailRemoval/
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'input_validation_filter' block
    input_validation_filter(container=container)

    return

@phantom.playbook_block()
def search_o365_for_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("search_o365_for_email() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Search for  provided message ID in provided mailbox from filtered playbook inputs.
    ################################################################################

    filtered_input_0_email = phantom.collect2(container=container, datapath=["filtered-data:input_validation_filter:condition_1:playbook_input:email"])
    filtered_input_1_message_id = phantom.collect2(container=container, datapath=["filtered-data:input_validation_filter:condition_1:playbook_input:message_id"])

    parameters = []

    # build parameters list for 'search_o365_for_email' call
    for filtered_input_0_email_item in filtered_input_0_email:
        for filtered_input_1_message_id_item in filtered_input_1_message_id:
            if filtered_input_0_email_item[0] is not None:
                parameters.append({
                    "folder": "Inbox",
                    "email_address": filtered_input_0_email_item[0],
                    "get_folder_id": True,
                    "internet_message_id": filtered_input_1_message_id_item[0],
                    "search_well_known_folders": True,
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="search_o365_for_email", assets=["ms_graph_for_office_365"], callback=filter_run_query)

    return


@phantom.playbook_block()
def purge_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("purge_email() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Remove  provided message ID in provided mailbox from filtered query outputs.
    ################################################################################

    filtered_result_0_data_filter_run_query = phantom.collect2(container=container, datapath=["filtered-data:filter_run_query:condition_1:search_o365_for_email:action_result.data.*.id","filtered-data:filter_run_query:condition_1:search_o365_for_email:action_result.parameter.email_address"])

    parameters = []

    # build parameters list for 'purge_email' call
    for filtered_result_0_item_filter_run_query in filtered_result_0_data_filter_run_query:
        if filtered_result_0_item_filter_run_query[0] is not None and filtered_result_0_item_filter_run_query[1] is not None:
            parameters.append({
                "id": filtered_result_0_item_filter_run_query[0],
                "email_address": filtered_result_0_item_filter_run_query[1],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("delete email", parameters=parameters, name="purge_email", assets=["ms_graph_for_office_365"], callback=purge_filter)

    return


@phantom.playbook_block()
def email_deletion_observable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("email_deletion_observable() called")

    ################################################################################
    # Format a normalized output for each message_id and mailbox.
    ################################################################################

    filtered_result_0_data_purge_filter = phantom.collect2(container=container, datapath=["filtered-data:purge_filter:condition_1:purge_email:action_result.parameter.email_address","filtered-data:purge_filter:condition_1:purge_email:action_result.parameter.id","filtered-data:purge_filter:condition_1:purge_email:action_result.status","filtered-data:purge_filter:condition_1:purge_email:action_result.message"])

    filtered_result_0_parameter_email_address = [item[0] for item in filtered_result_0_data_purge_filter]
    filtered_result_0_parameter_id = [item[1] for item in filtered_result_0_data_purge_filter]
    filtered_result_0_status = [item[2] for item in filtered_result_0_data_purge_filter]
    filtered_result_0_message = [item[3] for item in filtered_result_0_data_purge_filter]

    email_deletion_observable__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    email_address = filtered_result_0_parameter_email_address
    message_id = filtered_result_0_parameter_id
    result_status = filtered_result_0_status
    result_message = filtered_result_0_message
    
    email_deletion_observable__observable_array = []
    
    for message_id, email, result, message in zip(message_id, email_address, result_status, result_message):
        email_status = {
            "type": "Internet Message ID",
            "source": "MS Graph for Office365",
            "value": message_id,
            "mailbox": email,
            "message": message,
            "status": "deleted"
        }

        email_deletion_observable__observable_array.append(email_status)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="email_deletion_observable:observable_array", value=json.dumps(email_deletion_observable__observable_array))

    return


@phantom.playbook_block()
def input_validation_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("input_validation_filter() called")

    ################################################################################
    # Filter message_id and email inputs to route inputs to appropriate actions.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["playbook_input:email", "!=", ""],
            ["playbook_input:message_id", "!=", ""]
        ],
        name="input_validation_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        search_o365_for_email(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_run_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_run_query() called")

    ################################################################################
    # filter check if the message is found in the mailbox.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["search_o365_for_email:action_result.summary.emails_matched", ">=", 1]
        ],
        name="filter_run_query:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        purge_email(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def purge_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("purge_filter() called")

    ################################################################################
    # filter check if the message is deleted from mailbox
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["purge_email:action_result.status", "==", "success"]
        ],
        name="purge_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        email_deletion_observable(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    email_deletion_observable__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="email_deletion_observable:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "observable": email_deletion_observable__observable_array,
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