"""
Detects available indicators and routes them to dynamic related ticket search playbooks. The output of the analysis will update any artifacts, tasks, and indicator tags.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'artifact_decision' block
    artifact_decision(container=container)

    return

@phantom.playbook_block()
def filter_new_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_new_artifacts() called")

    ################################################################################
    # Only dispatch rplaybooks against new artifacts.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.id", "!=", None]
        ],
        name="filter_new_artifacts:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        dispatch_ticketing_playbooks(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="No new artifact data found in event.")

    return


@phantom.playbook_block()
def dispatch_ticketing_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_ticketing_playbooks() called")

    filtered_artifact_0_data_filter_new_artifacts = phantom.collect2(container=container, datapath=["filtered-data:filter_new_artifacts:condition_1:artifact:*.id"])

    filtered_artifact_0__id = [item[0] for item in filtered_artifact_0_data_filter_new_artifacts]

    inputs = {
        "playbook_repo": [],
        "playbook_tags": ["ticket"],
        "artifact_ids_include": filtered_artifact_0__id,
        "indicator_tags_exclude": [],
        "indicator_tags_include": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/dispatch_input_playbooks", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/dispatch_input_playbooks", container=container, name="dispatch_ticketing_playbooks", callback=outputs_decision, inputs=inputs)

    return


@phantom.playbook_block()
def artifact_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_decision() called")

    ################################################################################
    # Determine if artifacts exist to run through the playbook.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.id", "!=", None]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_new_artifacts(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_2(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def outputs_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("outputs_decision() called")

    ################################################################################
    # Determine if outputs exist.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["dispatch_ticketing_playbooks:playbook_output:observable", "!=", None]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        dispatch_filter_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_3(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_comment_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_3() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="No observable data found from dispatched playbooks.")

    return


@phantom.playbook_block()
def merge_reports(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_reports() called")

    ################################################################################
    # Format a note that merges together normalized data. The data will come from 
    # the playbooks launched by the Dispatch Ticketing Playbooks block.
    ################################################################################

    template = """SOAR retrieved tickets from Splunk. The table below shows a summary of the information gathered.\n\n| Name | Number | Message | Start Time | End Time | Assignee | Creator Name | State | Matched Fields | Source | Source Link |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n%%\n| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} | {10} |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:dispatch_filter_1:condition_1:dispatch_ticketing_playbooks:playbook_output:observable.ticket.name",
        "filtered-data:dispatch_filter_1:condition_1:dispatch_ticketing_playbooks:playbook_output:observable.ticket.number",
        "filtered-data:dispatch_filter_1:condition_1:dispatch_ticketing_playbooks:playbook_output:observable.ticket.message",
        "filtered-data:dispatch_filter_1:condition_1:dispatch_ticketing_playbooks:playbook_output:observable.ticket.start_time",
        "filtered-data:dispatch_filter_1:condition_1:dispatch_ticketing_playbooks:playbook_output:observable.ticket.end_time",
        "filtered-data:dispatch_filter_1:condition_1:dispatch_ticketing_playbooks:playbook_output:observable.ticket.assignee",
        "filtered-data:dispatch_filter_1:condition_1:dispatch_ticketing_playbooks:playbook_output:observable.ticket.creator_name",
        "filtered-data:dispatch_filter_1:condition_1:dispatch_ticketing_playbooks:playbook_output:observable.ticket.state",
        "filtered-data:dispatch_filter_1:condition_1:dispatch_ticketing_playbooks:playbook_output:observable.matched_fields",
        "filtered-data:dispatch_filter_1:condition_1:dispatch_ticketing_playbooks:playbook_output:observable.source",
        "filtered-data:dispatch_filter_1:condition_1:dispatch_ticketing_playbooks:playbook_output:observable.source_link"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="merge_reports")

    ticketing_update(container=container)

    return


@phantom.playbook_block()
def ticketing_update(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ticketing_update() called")

    id_value = container.get("id", None)
    merge_reports = phantom.get_format_data(name="merge_reports")

    parameters = []

    parameters.append({
        "owner": None,
        "status": "complete",
        "container": id_value,
        "task_name": "playbook",
        "note_title": "Dynamic Related Ticket Search Report",
        "note_content": merge_reports,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="ticketing_update")

    return


@phantom.playbook_block()
def dispatch_filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_filter_1() called")

    ################################################################################
    # Create a dataset with the output of the dispatch playbooks that is not None
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["dispatch_ticketing_playbooks:playbook_output:observable", "!=", None]
        ],
        name="dispatch_filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_reports(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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