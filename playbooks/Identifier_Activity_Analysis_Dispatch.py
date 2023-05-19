"""
Detects available indicators and routes them to related identifier activity analysis playbooks. The output of the analysis will update any artifacts, tasks, and indicator tags.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'route_artifacts' block
    route_artifacts(container=container)

    return

@phantom.playbook_block()
def route_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("route_artifacts() called")

    ################################################################################
    # Only dispatch playbooks against new artifacts.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.id", "!=", None]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_inputs(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    no_artifacts(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def filter_inputs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_inputs() called")

    ################################################################################
    # Ensure there are artifacts
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.id", "!=", None]
        ],
        name="filter_inputs:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        dispatch_activity_analysis_playbooks(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def no_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("no_artifacts() called")

    ################################################################################
    # Comment and exit if there are no new artifacts
    ################################################################################

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
def dispatch_activity_analysis_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_activity_analysis_playbooks() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.id"])

    container_artifact_header_item_0 = [item[0] for item in container_artifact_data]

    inputs = {
        "playbook_repo": [""],
        "playbook_tags": ["identifier_activity"],
        "artifact_ids_include": container_artifact_header_item_0,
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
    playbook_run_id = phantom.playbook("community/dispatch_input_playbooks", container=container, name="dispatch_activity_analysis_playbooks", callback=route_outputs, inputs=inputs)

    return


@phantom.playbook_block()
def route_outputs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("route_outputs() called")

    ################################################################################
    # Determine if outputs exist
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["dispatch_activity_analysis_playbooks:playbook_output:observable", "!=", None]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        markdown_filter(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    no_outputs(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def markdown_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("markdown_filter() called")

    ################################################################################
    # Ensure there are outputs
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["dispatch_activity_analysis_playbooks:playbook_output:markdown_report", "!=", None]
        ],
        name="markdown_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_reports(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def no_outputs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("no_outputs() called")

    ################################################################################
    # Comment and exit if there are no observables returned
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="No observable data found from playbook(s).")

    return


@phantom.playbook_block()
def merge_reports(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_reports() called")

    ################################################################################
    # Merge markdown outputs from dispatched playbooks
    ################################################################################

    template = """%%\n{0}\n\n\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:markdown_filter:condition_1:dispatch_activity_analysis_playbooks:playbook_output:markdown_report"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="merge_reports")

    update_identifier_activity_analysis_task(container=container)

    return


@phantom.playbook_block()
def update_identifier_activity_analysis_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_identifier_activity_analysis_task() called")

    id_value = container.get("id", None)
    merge_reports = phantom.get_format_data(name="merge_reports")

    parameters = []

    parameters.append({
        "owner": None,
        "status": "complete",
        "container": id_value,
        "task_name": "playbook",
        "note_title": "Identifier Activity Analysis Dispatch",
        "note_content": merge_reports,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="update_identifier_activity_analysis_task")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    output = {
        "observable": [],
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