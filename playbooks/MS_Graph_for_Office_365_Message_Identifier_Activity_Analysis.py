"""
Caution: This may run into performance or rate limiting issues at large scale because each mailbox is checked individually.\n\nAccepts an internet message id, and asks Office365 for a list of mailboxes to search, and then searches each one to look for records that have a matching internet message id.  It then produces a normalized output and summary table.\n\nRef: D3-IAA: https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis/
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'artifact_filter' block
    artifact_filter(container=container)

    return

@phantom.playbook_block()
def artifact_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("artifact_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:message_id", "!=", ""]
        ],
        name="artifact_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_mailboxes(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def get_mailboxes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_mailboxes() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Currently a required step in order to search "All" of the mailboxes in an O365 
    # tenant. This receives a list of mailboxes that are passed to the next action.
    ################################################################################

    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("list users", parameters=parameters, name="get_mailboxes", assets=["ms_graph_for_office_365"], callback=search_mailboxes)

    return


@phantom.playbook_block()
def search_mailboxes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("search_mailboxes() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_mailboxes_result_data = phantom.collect2(container=container, datapath=["get_mailboxes:action_result.data.*.mail","get_mailboxes:action_result.parameter.context.artifact_id"], action_results=results)
    filtered_input_0_message_id = phantom.collect2(container=container, datapath=["filtered-data:artifact_filter:condition_1:playbook_input:message_id"])

    parameters = []

    # build parameters list for 'search_mailboxes' call
    for get_mailboxes_result_item in get_mailboxes_result_data:
        for filtered_input_0_message_id_item in filtered_input_0_message_id:
            if get_mailboxes_result_item[0] is not None:
                parameters.append({
                    "folder": "Inbox",
                    "email_address": get_mailboxes_result_item[0],
                    "get_folder_id": True,
                    "internet_message_id": filtered_input_0_message_id_item[0],
                    "search_well_known_folders": True,
                    "context": {'artifact_id': get_mailboxes_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="search_mailboxes", assets=["ms_graph_for_office_365"], callback=results_filter)

    return


@phantom.playbook_block()
def results_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("results_filter() called")

    ################################################################################
    # Filter results from mailbox search
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["search_mailboxes:action_result.status", "==", "success"],
            ["search_mailboxes:action_result.summary.emails_matched", ">", 0]
        ],
        name="results_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_message_report(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_message_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_message_report() called")

    template = """SOAR searched for occurrences of `{0}` within your environment using MS Graph for O365. The table below shows a summary of the information gathered.\n\n| Recipient | Sender | Subject |\n| --- | --- | --- | --- |\n%%\n| {1} | {2} | {3} |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:results_filter:condition_1:search_mailboxes:action_result.parameter.internet_message_id",
        "filtered-data:results_filter:condition_1:search_mailboxes:action_result.data.*.toRecipients.*.emailAddress.address",
        "filtered-data:results_filter:condition_1:search_mailboxes:action_result.data.*.sender.emailAddress.address",
        "filtered-data:results_filter:condition_1:search_mailboxes:action_result.data.*.subject"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_message_report")

    build_message_output(container=container)

    return


@phantom.playbook_block()
def build_message_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_message_output() called")

    ################################################################################
    # Logic regarding observable construction goes here
    ################################################################################

    filtered_result_0_data_results_filter = phantom.collect2(container=container, datapath=["filtered-data:results_filter:condition_1:search_mailboxes:action_result.parameter.internet_message_id","filtered-data:results_filter:condition_1:search_mailboxes:action_result.parameter.email_address","filtered-data:results_filter:condition_1:search_mailboxes:action_result.data.*.subject","filtered-data:results_filter:condition_1:search_mailboxes:action_result.data.*.sender.emailAddress.address","filtered-data:results_filter:condition_1:search_mailboxes:action_result.data.*.id"])

    filtered_result_0_parameter_internet_message_id = [item[0] for item in filtered_result_0_data_results_filter]
    filtered_result_0_parameter_email_address = [item[1] for item in filtered_result_0_data_results_filter]
    filtered_result_0_data___subject = [item[2] for item in filtered_result_0_data_results_filter]
    filtered_result_0_data___sender_emailaddress_address = [item[3] for item in filtered_result_0_data_results_filter]
    filtered_result_0_data___id = [item[4] for item in filtered_result_0_data_results_filter]

    build_message_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    internet_message_ids = filtered_result_0_parameter_internet_message_id
    mailboxes = filtered_result_0_parameter_email_address
    subjects = filtered_result_0_data___subject
    senders = filtered_result_0_data___sender_emailaddress_address
    office365_ids = filtered_result_0_data___id
    
    build_message_output__observable_array = []
    
    for internet_message_id, recipient_address, subject, sender, office365_id in zip(internet_message_ids, mailboxes, subjects, senders, office365_ids):
        record = {
            "subject": subject,
            "sender": sender,
            "recipient": recipient_address,
            "o365_id": office365_id,
            "value": internet_message_id,
            "type": "internet message id",
            "source": "MS Graph for Office365"
        }
        
        
        
        build_message_output__observable_array.append(record)
    
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_message_output:observable_array", value=json.dumps(build_message_output__observable_array))

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_message_report = phantom.get_format_data(name="format_message_report")
    build_message_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_message_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "observables": build_message_output__observable_array,
        "markdown_report": format_message_report,
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