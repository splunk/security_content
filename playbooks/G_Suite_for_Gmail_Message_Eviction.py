"""
Accepts a gmail email ID and a mailbox, and then attempts to delete the email from the mailbox. \n\nCaution: Emails deleted by running this playbook are deleted permanently and cannot be recovered\n\nRef: D3-ER: https://d3fend.mitre.org/technique/d3f:EmailRemoval/
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
    # Filter message_id and email inputs to route inputs to appropriate actions.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["playbook_input:message_id", "!=", ""],
            ["playbook_input:email", "!=", ""]
        ],
        name="input_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        purge_email(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def purge_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("purge_email() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Remove  provided gmail email ID in provided mailbox.
    ################################################################################

    filtered_input_0_message_id = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_1:playbook_input:message_id"])
    filtered_input_1_email = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_1:playbook_input:email"])

    parameters = []

    # build parameters list for 'purge_email' call
    for filtered_input_0_message_id_item in filtered_input_0_message_id:
        for filtered_input_1_email_item in filtered_input_1_email:
            if filtered_input_0_message_id_item[0] is not None and filtered_input_1_email_item[0] is not None:
                parameters.append({
                    "id": filtered_input_0_message_id_item[0],
                    "email": filtered_input_1_email_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("delete email", parameters=parameters, name="purge_email", assets=["g_suite_for_gmail"], callback=post_delete_filter)

    return


@phantom.playbook_block()
def post_delete_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("post_delete_filter() called")

    ################################################################################
    # Ensure that the email deletion occurred successfully.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["purge_email:action_result.status", "==", "success"]
        ],
        name="post_delete_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        observable_output(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def observable_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("observable_output() called")

    ################################################################################
    # Format a normalized output for each deleted message.
    ################################################################################

    filtered_result_0_data_post_delete_filter = phantom.collect2(container=container, datapath=["filtered-data:post_delete_filter:condition_1:purge_email:action_result.parameter.email","filtered-data:post_delete_filter:condition_1:purge_email:action_result.parameter.id","filtered-data:post_delete_filter:condition_1:purge_email:action_result.status","filtered-data:post_delete_filter:condition_1:purge_email:action_result.message"])

    filtered_result_0_parameter_email = [item[0] for item in filtered_result_0_data_post_delete_filter]
    filtered_result_0_parameter_id = [item[1] for item in filtered_result_0_data_post_delete_filter]
    filtered_result_0_status = [item[2] for item in filtered_result_0_data_post_delete_filter]
    filtered_result_0_message = [item[3] for item in filtered_result_0_data_post_delete_filter]

    observable_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    
    observable_output__observable_array = []
    
    emails = filtered_result_0_parameter_email
    messageID = filtered_result_0_parameter_id
    Statuses = filtered_result_0_status
    Messages = filtered_result_0_message
    
    for email, message_id, status, message in zip(emails, messageID, Statuses, Messages):
        observable = {
            "mailbox": email,
            "message_id": message_id,
            "status": "deleted",
            "message": message,
            "source": "GSuite for GMail"
        }
        observable_output__observable_array.append(observable)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="observable_output:observable_array", value=json.dumps(observable_output__observable_array))

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    observable_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="observable_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "observable": observable_output__observable_array,
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