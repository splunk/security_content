"""
Accepts an internet message id, and asks Gmail for a list of mailboxes to search, and then searches each one to look for records that have a matching internet message id.  It then produces a normalized output and summary table.\n\nThis may not work in the intended fashion if your organization has more than 500 mailboxes.\n\nRef: D3-IAA: https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis/
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
            ["playbook_input:message_id", "!=", None]
        ],
        name="artifact_filter:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_mailboxes(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def get_mailboxes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_mailboxes() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Required step in order to search "All" of a Gsuite organization. This receives 
    # a list of mailboxes that are passed to the next action.
    ################################################################################

    parameters = []

    parameters.append({
        "max_items": 500,
        "page_token": "",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("list users", parameters=parameters, name="get_mailboxes", assets=["g_suite_for_gmail"], callback=search_mailboxes)

    return


@phantom.playbook_block()
def search_mailboxes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("search_mailboxes() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_mailboxes_result_data = phantom.collect2(container=container, datapath=["get_mailboxes:action_result.data.*.emails.*.address","get_mailboxes:action_result.parameter.context.artifact_id"], action_results=results)
    filtered_input_0_message_id = phantom.collect2(container=container, datapath=["filtered-data:artifact_filter:condition_1:playbook_input:message_id"])

    parameters = []

    # build parameters list for 'search_mailboxes' call
    for get_mailboxes_result_item in get_mailboxes_result_data:
        for filtered_input_0_message_id_item in filtered_input_0_message_id:
            if get_mailboxes_result_item[0] is not None:
                parameters.append({
                    "email": get_mailboxes_result_item[0],
                    "label": "Inbox",
                    "query": "",
                    "max_results": 100,
                    "internet_message_id": filtered_input_0_message_id_item[0],
                    "context": {'artifact_id': get_mailboxes_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="search_mailboxes", assets=["g_suite_for_gmail"], callback=results_filter)

    return


@phantom.playbook_block()
def format_message_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_message_report() called")

    template = """SOAR searched for occurrences of `{0}` within your environment using GSuite for GMail. The table below shows a summary of the information gathered.\n\n| Recipient | Addressed To | Subject | Sender |\n| --- | --- | --- | --- |\n%%\n| {1} | {2} | {3} | {4} |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:results_filter:condition_1:search_mailboxes:action_result.parameter.internet_message_id",
        "filtered-data:results_filter:condition_1:search_mailboxes:action_result.data.*.delivered_to",
        "filtered-data:results_filter:condition_1:search_mailboxes:action_result.data.*.to",
        "filtered-data:results_filter:condition_1:search_mailboxes:action_result.data.*.subject",
        "filtered-data:results_filter:condition_1:search_mailboxes:action_result.data.*.from"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    
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

    filtered_result_0_data_results_filter = phantom.collect2(container=container, datapath=["filtered-data:results_filter:condition_1:search_mailboxes:action_result.parameter.internet_message_id","filtered-data:results_filter:condition_1:search_mailboxes:action_result.data.*.delivered_to","filtered-data:results_filter:condition_1:search_mailboxes:action_result.data.*.to","filtered-data:results_filter:condition_1:search_mailboxes:action_result.data.*.subject","filtered-data:results_filter:condition_1:search_mailboxes:action_result.data.*.from","filtered-data:results_filter:condition_1:search_mailboxes:action_result.data.*.id"])

    filtered_result_0_parameter_internet_message_id = [item[0] for item in filtered_result_0_data_results_filter]
    filtered_result_0_data___delivered_to = [item[1] for item in filtered_result_0_data_results_filter]
    filtered_result_0_data___to = [item[2] for item in filtered_result_0_data_results_filter]
    filtered_result_0_data___subject = [item[3] for item in filtered_result_0_data_results_filter]
    filtered_result_0_data___from = [item[4] for item in filtered_result_0_data_results_filter]
    filtered_result_0_data___id = [item[5] for item in filtered_result_0_data_results_filter]

    build_message_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Variable renaming for convenince
    messageID = filtered_result_0_parameter_internet_message_id
    recipients = filtered_result_0_data___delivered_to
    addressees = filtered_result_0_data___to
    subjects = filtered_result_0_data___subject
    senders = filtered_result_0_data___from
    gmailIDs = filtered_result_0_data___id
    
    build_message_output__observable_array = []
    
    
    
        # construct iterables for records
    for message_id, recipient, addressee, subject, sender, gmailID in zip(messageID, recipients, addressees, subjects, senders, gmailIDs):
        record = {
            "recipient": recipient,
            "addressee": addressee,
            "subject": subject,
            "sender": sender,
            "gmail_id": gmailID,
            "value": message_id,
            "type": "internet message ID",
            "source": "GSuite for GMail"
        }
            
        
        # Create observable body
    
        build_message_output__observable_array.append(record)
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_message_output:observable_array", value=json.dumps(build_message_output__observable_array))

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
            ["search_mailboxes:action_result.summary.total_messages_returned", ">", 0]
        ],
        name="results_filter:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_message_report(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_message_report = phantom.get_format_data(name="format_message_report")
    build_message_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_message_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "observable": build_message_output__observable_array,
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