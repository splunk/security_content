"""
Accepts an Internet Message ID and an email mailbox, searches for the Message ID&#39;s presence in each mailbox&#39;s recoverable deleted items, and then restores the ones it finds. 
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'input_decision' block
    input_decision(container=container)

    return

@phantom.playbook_block()
def input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("input_filter() called")

    ################################################################################
    # ensures the artifact this is running against has the right fields
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.internet message id", "!=", ""]
        ],
        name="input_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        playbook_ms_graph_for_office_365_message_restore_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def playbook_ms_graph_for_office_365_message_restore_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_ms_graph_for_office_365_message_restore_1() called")

    filtered_artifact_0_data_input_filter = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_1:artifact:*.cef.internet message id","filtered-data:input_filter:condition_1:artifact:*.cef.email"])

    filtered_artifact_0__cef_internet_message_id = [item[0] for item in filtered_artifact_0_data_input_filter]
    filtered_artifact_0__cef_email = [item[1] for item in filtered_artifact_0_data_input_filter]

    inputs = {
        "message_id": filtered_artifact_0__cef_internet_message_id,
        "email": filtered_artifact_0__cef_email,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/MS_Graph_for_Office_365_Message_Restore", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/MS_Graph_for_Office_365_Message_Restore", container=container, name="playbook_ms_graph_for_office_365_message_restore_1", callback=filter_2, inputs=inputs)

    return


@phantom.playbook_block()
def artifact_does_not_exist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("artifact_does_not_exist() called")

    ################################################################################
    # In the event an artifact does not exist suitable for this usecase, inform the 
    # user.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="\"No Internet Message ID artifacts found\"")

    return


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_ms_graph_for_office_365_message_restore_1:playbook_output:observables", "!=", None]
        ],
        name="filter_2:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_note(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_ms_graph_for_office_365_message_restore_1:playbook_output:observables", "==", None]
        ],
        name="filter_2:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        no_observable_found(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def format_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_note() called")

    ################################################################################
    # Format the output of the Message Restore playbook to provide a table to the 
    # user showing the deleted messages.
    ################################################################################

    template = """SOAR restored messages in O365. The table below shows a summary of the messages.\n\n| Mailbox | Message ID | Status | Message |\n| --- | --- | --- | --- |\n%%\n| {0} | {1} | {2} | {3} |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_1:playbook_ms_graph_for_office_365_message_restore_1:playbook_output:observables.mailbox",
        "filtered-data:filter_2:condition_1:playbook_ms_graph_for_office_365_message_restore_1:playbook_output:observables.value",
        "filtered-data:filter_2:condition_1:playbook_ms_graph_for_office_365_message_restore_1:playbook_output:observables.status",
        "filtered-data:filter_2:condition_1:playbook_ms_graph_for_office_365_message_restore_1:playbook_output:observables.message"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note")

    update_workbook_task(container=container)

    return


@phantom.playbook_block()
def no_observable_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("no_observable_found() called")

    ################################################################################
    # In the event the Message Restore playbook does not return an observable, inform 
    # the user.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="No observable output found for dispatched playbook.")

    return


@phantom.playbook_block()
def update_workbook_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_workbook_task() called")

    ################################################################################
    # Upon completion, update the workbook task with the formatted output and mark 
    # task as complete.
    ################################################################################

    id_value = container.get("id", None)
    format_note = phantom.get_format_data(name="format_note")

    parameters = []

    parameters.append({
        "owner": None,
        "status": "complete",
        "container": id_value,
        "task_name": "playbook",
        "note_title": "Search and Restore Results",
        "note_content": format_note,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="update_workbook_task")

    return


@phantom.playbook_block()
def input_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("input_decision() called")

    ################################################################################
    # ensures the artifact this is running against has the right fields
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["artifact:*.cef.internet message id", "!=", ""],
            ["artifact:*.cef.email", "!=", ""]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        input_filter(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    artifact_does_not_exist(action=action, success=success, container=container, results=results, handle=handle)

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