"""
Accepts a URL or vault_id and does reputation analysis on the objects. Generates a global report and a per observable sub-report and normalized score. The score can be customized based on a variety of factors.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'new_artifacts_filter' block
    new_artifacts_filter(container=container)

    return

@phantom.playbook_block()
def dispatch_detonation_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_detonation_playbooks() called")

    filtered_artifact_0_data_new_artifacts_filter = phantom.collect2(container=container, datapath=["filtered-data:new_artifacts_filter:condition_1:artifact:*.id"])

    filtered_artifact_0__id = [item[0] for item in filtered_artifact_0_data_new_artifacts_filter]

    inputs = {
        "playbook_tags": ["sandbox"],
        "playbook_repo": [],
        "indicator_tags_include": [],
        "indicator_tags_exclude": [],
        "artifact_ids_include": filtered_artifact_0__id,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/dispatch_input_playbooks", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/dispatch_input_playbooks", container=container, name="dispatch_detonation_playbooks", callback=filter_successful_observable_output, inputs=inputs)

    return


@phantom.playbook_block()
def artifacts_check_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifacts_check_comment() called")

    ################################################################################
    # no url or vault_id artifacts inputs
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="no url or vault_id artifacts inputs")

    return


@phantom.playbook_block()
def filter_successful_observable_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_successful_observable_output() called")

    ################################################################################
    # Filter to check if observable output is successfully generated or not.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["dispatch_detonation_playbooks:playbook_output:observable", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_dispatch_output(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    no_observables_comment(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def merge_report_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_report_1() called")

    ################################################################################
    # summary report for all sandbox detonation input playbooks.
    ################################################################################

    template = """SOAR detonated indicators in connected sandboxes. The table below shows a summary of the information gathered.\n\n| Value | Score | Confidence | Source |\n| --- | --- | --- | --- |\n%%\n| {0} | {1} | {2} | {3} |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_dispatch_output:condition_1:dispatch_detonation_playbooks:playbook_output:observable.value",
        "filtered-data:filter_dispatch_output:condition_1:dispatch_detonation_playbooks:playbook_output:observable.reputation.score",
        "filtered-data:filter_dispatch_output:condition_1:dispatch_detonation_playbooks:playbook_output:observable.reputation.confidence",
        "filtered-data:filter_dispatch_output:condition_1:dispatch_detonation_playbooks:playbook_output:observable.source"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(phantom.format(container=container, template=template, parameters=parameters, name="merge_report_1"))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="merge_report_1")

    indicator_tag(container=container)

    return


@phantom.playbook_block()
def indicator_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_tag() called")

    filtered_output_0_dispatch_detonation_playbooks_output_observable = phantom.collect2(container=container, datapath=["filtered-data:filter_dispatch_output:condition_1:dispatch_detonation_playbooks:playbook_output:observable.classifications","filtered-data:filter_dispatch_output:condition_1:dispatch_detonation_playbooks:playbook_output:observable.value"])

    parameters = []

    # build parameters list for 'indicator_tag' call
    for filtered_output_0_dispatch_detonation_playbooks_output_observable_item in filtered_output_0_dispatch_detonation_playbooks_output_observable:
        parameters.append({
            "tags": filtered_output_0_dispatch_detonation_playbooks_output_observable_item[0],
            "indicator": filtered_output_0_dispatch_detonation_playbooks_output_observable_item[1],
            "overwrite": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="indicator_tag", callback=workbook_update_task)

    return


@phantom.playbook_block()
def workbook_update_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_update_task() called")

    id_value = container.get("id", None)
    merge_report_1 = phantom.get_format_data(name="merge_report_1")

    parameters = []

    parameters.append({
        "owner": None,
        "status": "complete",
        "container": id_value,
        "task_name": "playbook",
        "note_title": "Automatic Dynamic Analysis Report",
        "note_content": merge_report_1,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="workbook_update_task")

    return


@phantom.playbook_block()
def no_observables_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("no_observables_comment() called")

    ################################################################################
    # observable output of detonation playbooks does not exist
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="No observable output found for dispatched playbooks.")

    return


@phantom.playbook_block()
def filter_dispatch_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_dispatch_output() called")

    ################################################################################
    # Filter out any results that are Null.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["dispatch_detonation_playbooks:playbook_output:observable", "!=", ""]
        ],
        name="filter_dispatch_output:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_report_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def new_artifacts_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("new_artifacts_filter() called")

    ################################################################################
    # This block is used to ensure only "new" artifacts are utilized.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.id", "!=", ""]
        ],
        name="new_artifacts_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        dispatch_detonation_playbooks(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.id", "==", ""]
        ],
        name="new_artifacts_filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        artifacts_check_comment(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

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