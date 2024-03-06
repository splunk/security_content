"""
Accepts an Internet Message ID, searches for its presence in each mailbox, and then deletes the ones it finds. The Message Eviction playbook performs a &quot;soft delete&quot;, which allows for messages to be recovered.
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
def playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1() called")

    filtered_artifact_0_data_input_filter = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_1:artifact:*.cef.internet message id"])

    filtered_artifact_0__cef_internet_message_id = [item[0] for item in filtered_artifact_0_data_input_filter]

    inputs = {
        "message_id": filtered_artifact_0__cef_internet_message_id,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/MS_Graph_for_Office_365_Message_Identifier_Activity_Analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/MS_Graph_for_Office_365_Message_Identifier_Activity_Analysis", container=container, name="playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1", callback=identifier_filter, inputs=inputs)

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
def identifier_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("identifier_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1:playbook_output:observables", "!=", None]
        ],
        name="identifier_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_prompt(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1:playbook_output:observables", "==", None]
        ],
        name="identifier_filter:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        no_observable_found(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def playbook_ms_graph_for_office_365_message_eviction_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_ms_graph_for_office_365_message_eviction_1() called")

    filtered_output_0_playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1_output_observables = phantom.collect2(container=container, datapath=["filtered-data:identifier_filter:condition_1:playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1:playbook_output:observables.recipient","filtered-data:identifier_filter:condition_1:playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1:playbook_output:observables.value"])

    filtered_output_0_playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1_output_observables_recipient = [item[0] for item in filtered_output_0_playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1_output_observables]
    filtered_output_0_playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1_output_observables_value = [item[1] for item in filtered_output_0_playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1_output_observables]

    inputs = {
        "email": filtered_output_0_playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1_output_observables_recipient,
        "message_id": filtered_output_0_playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1_output_observables_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/MS_Graph_for_Office_365_Message_Eviction", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/MS_Graph_for_Office_365_Message_Eviction", container=container, name="playbook_ms_graph_for_office_365_message_eviction_1", callback=format_note, inputs=inputs)

    return


@phantom.playbook_block()
def no_observable_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("no_observable_found() called")

    ################################################################################
    # In the event the Message Identifier Activity Analysis playbook does not return 
    # an observable, inform the user.
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
def format_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_note() called")

    ################################################################################
    # Format the output of the Message Eviction playbook to provide a table to the 
    # user showing the deleted messages.
    ################################################################################

    template = """SOAR deleted messages in O365. The table below shows a summary of the messages.\n\n| Mailbox | Message ID | Status | Message |\n| --- | --- | --- | --- |\n%%\n| {0} | {1} | {2} | {3} |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_ms_graph_for_office_365_message_eviction_1:playbook_output:observable.mailbox",
        "playbook_ms_graph_for_office_365_message_eviction_1:playbook_output:observable.value",
        "playbook_ms_graph_for_office_365_message_eviction_1:playbook_output:observable.status",
        "playbook_ms_graph_for_office_365_message_eviction_1:playbook_output:observable.message"
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
        "note_title": "Search and Purge Results",
        "note_content": format_note,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="update_workbook_task", callback=format_artifact)

    return


@phantom.playbook_block()
def format_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_artifact() called")

    ################################################################################
    # These artifacts capture the message ID and the mailbox they were removed from 
    # so that they can be restored later.
    ################################################################################

    template = """%%\n{{\"cef_data\": \n{{\"email\": \"{0}\", \"internet message id\": \"{1}\"}}}}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_ms_graph_for_office_365_message_eviction_1:playbook_input:email",
        "playbook_ms_graph_for_office_365_message_eviction_1:playbook_input:message_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_artifact")

    create_artifacts_0(container=container)

    return


@phantom.playbook_block()
def create_artifacts_0(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_artifacts_0() called")

    ################################################################################
    # These artifacts capture the message ID and the mailbox they were removed from 
    # so that they can be restored later.
    ################################################################################

    id_value = container.get("id", None)
    format_artifact__as_list = phantom.get_format_data(name="format_artifact__as_list")

    parameters = []

    # build parameters list for 'create_artifacts_0' call
    for format_artifact__item in format_artifact__as_list:
        parameters.append({
            "name": "Purged Email Results",
            "tags": None,
            "label": "office_365_delete",
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "container": id_value,
            "input_json": format_artifact__item,
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

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="create_artifacts_0")

    return


@phantom.playbook_block()
def input_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("input_decision() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.internet message id", "!=", ""]
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
def input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("input_filter() called")

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
        playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_prompt() called")

    template = """| Mailbox | Subject | Email ID |\n| --- | --- | --- |\n%%\n| {0} | {1} | {2} |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:identifier_filter:condition_2:playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1:playbook_output:observables.recipient",
        "filtered-data:identifier_filter:condition_2:playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1:playbook_output:observables.subject",
        "filtered-data:identifier_filter:condition_2:playbook_ms_graph_for_office_365_message_identifier_activity_analysis_1:playbook_output:observables.value"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_prompt")

    delete_email_prompt_1(container=container)

    return


@phantom.playbook_block()
def delete_email_prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("delete_email_prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = container.get('owner_name', None)
    role = None
    message = """The following emails will be deleted. These emails will be recoverable but will not be visible in the mailbox.\n\n{0} """

    # parameter list for template variable replacement
    parameters = [
        "format_prompt:formatted_data"
    ]

    # responses
    response_types = [
        {
            "prompt": "Delete these messages?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="delete_email_prompt_1", parameters=parameters, response_types=response_types, callback=prompt_decision)

    return


@phantom.playbook_block()
def prompt_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_decision() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["delete_email_prompt_1:action_result.summary.responses.0", "==", "yes"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_ms_graph_for_office_365_message_eviction_1(action=action, success=success, container=container, results=results, handle=handle)
        return

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