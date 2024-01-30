"""
Accepts an internet message id, and asks Splunk \n to look for records that have a matching internet message id.  It then produces a normalized output and summary table.\n\nRef: D3-IAA https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis/
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
def input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("input_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            ["playbook_input:message_id", "!=", None],
            ["playbook_input:sender", "!=", None],
            ["playbook_input:subject", "!=", None]
        ],
        name="input_filter:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_message_query(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_message_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_message_query() called")

    template = """summariesonly=false fillnull_value=\"Unknown\" count from datamodel=Email.All_Email where (All_Email.message_id IN (\n%%\n\"{0}\" \n%%\n) OR All_Email.subject IN (\n%%\n\"{1}\" \n%%\n) OR All_Email.src_user IN (\n%%\n\"{2}\" \n%%\n)) by All_Email.orig_recipient, All_Email.recipient, All_Email.src_user, All_Email.subject All_Email.message_id | `drop_dm_object_name(\"All_Email\")` | rename orig_recipient as Addressee, recipient as Recipient, src_user as Sender, subject as Subject message_id as Message_Id | fields Addressee, Recipient, Sender, Subject, Message_Id | fillnull value=\"Unknown\""""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:input_filter:condition_1:playbook_input:message_id",
        "filtered-data:input_filter:condition_1:playbook_input:subject",
        "filtered-data:input_filter:condition_1:playbook_input:sender"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_message_query", drop_none=False)

    run_message_query(container=container)

    return


@phantom.playbook_block()
def run_message_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_message_query() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_message_query = phantom.get_format_data(name="format_message_query")

    parameters = []

    if format_message_query is not None:
        parameters.append({
            "query": format_message_query,
            "command": "tstats",
            "display": "Addressee,Recipient,Sender,Subject",
            "search_mode": "smart",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_message_query", assets=["splunk"], callback=results_filter)

    return


@phantom.playbook_block()
def format_message_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_message_report() called")

    template = """SOAR searched for occurrences of one of the following:\n- Message ID(s): `{0}` \n- Subject(s): `{5}`\n- Sender(s): `{6}`\nwithin your environment using Splunk's Email data model. The table below shows a summary of the information gathered.\n\n| Recipient | Addressed To | Subject | Sender |\n| --- | --- | --- | --- |\n%%\n| {1} | {2} | {3} | {4} |\n%%\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:input_filter:condition_1:playbook_input:message_id",
        "filtered-data:results_filter:condition_1:run_message_query:action_result.data.*.Recipient",
        "filtered-data:results_filter:condition_1:run_message_query:action_result.data.*.Addressee",
        "filtered-data:results_filter:condition_1:run_message_query:action_result.data.*.Subject",
        "filtered-data:results_filter:condition_1:run_message_query:action_result.data.*.Sender",
        "filtered-data:input_filter:condition_1:playbook_input:subject",
        "filtered-data:input_filter:condition_1:playbook_input:sender"
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
def build_message_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_message_output() called")

    ################################################################################
    # Logic regarding observable construction goes here
    ################################################################################

    filtered_result_0_data_results_filter = phantom.collect2(container=container, datapath=["filtered-data:results_filter:condition_1:run_message_query:action_result.data.*.Recipient","filtered-data:results_filter:condition_1:run_message_query:action_result.data.*.Addressee","filtered-data:results_filter:condition_1:run_message_query:action_result.data.*.Subject","filtered-data:results_filter:condition_1:run_message_query:action_result.data.*.Sender","filtered-data:results_filter:condition_1:run_message_query:action_result.data.*.Message_Id"])

    filtered_result_0_data___recipient = [item[0] for item in filtered_result_0_data_results_filter]
    filtered_result_0_data___addressee = [item[1] for item in filtered_result_0_data_results_filter]
    filtered_result_0_data___subject = [item[2] for item in filtered_result_0_data_results_filter]
    filtered_result_0_data___sender = [item[3] for item in filtered_result_0_data_results_filter]
    filtered_result_0_data___message_id = [item[4] for item in filtered_result_0_data_results_filter]

    build_message_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Variable renames for convenience
    recipients = filtered_result_0_data___recipient
    addressees = filtered_result_0_data___addressee
    subjects = filtered_result_0_data___subject
    senders = filtered_result_0_data___sender
    message_id = filtered_result_0_data___message_id
    
    build_message_output__observable_array = []
    recordList = []
    
    # unwind records
    for recipient, addressee, subject, sender, message_id in zip(recipients, addressees, subjects, senders, filtered_result_0_data___message_id):
        record = {
            "recipient": recipient,
            "addressee": addressee,
            "subject": subject,
            "sender": sender
        }

        observable = {
            "value": message_id,
            "type": "internet message ID",
            "count": len(recordList),
            "source": "Splunk",
            "message_identifier_activity": record
        }

        build_message_output__observable_array.append(observable)
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_message_output:observable_array", value=json.dumps(build_message_output__observable_array))

    return


@phantom.playbook_block()
def results_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("results_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["run_message_query:action_result.summary.total_events", ">", 0]
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