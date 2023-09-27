"""
Detects available indicators and routes them to indicator reputation analysis playbooks. The output of the analysis will update any artifacts, tasks, and indicator tags.\n\nRef: https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/
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
def update_reputation_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_reputation_task() called")

    id_value = container.get("id", None)
    merge_reports = phantom.get_format_data(name="merge_reports")

    parameters = []

    parameters.append({
        "owner": None,
        "status": "complete",
        "container": id_value,
        "task_name": "playbook",
        "note_title": "Identifier Reputation Analysis Report",
        "note_content": merge_reports,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="update_reputation_task")

    return


@phantom.playbook_block()
def tag_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("tag_indicators() called")

    filtered_output_0_dispatch_reputation_playbooks_1_output_observable = phantom.collect2(container=container, datapath=["filtered-data:outputs_filter:condition_1:dispatch_reputation_playbooks_1:playbook_output:observable.reputation.score","filtered-data:outputs_filter:condition_1:dispatch_reputation_playbooks_1:playbook_output:observable.value"])

    parameters = []

    # build parameters list for 'tag_indicators' call
    for filtered_output_0_dispatch_reputation_playbooks_1_output_observable_item in filtered_output_0_dispatch_reputation_playbooks_1_output_observable:
        parameters.append({
            "tags": filtered_output_0_dispatch_reputation_playbooks_1_output_observable_item[0],
            "indicator": filtered_output_0_dispatch_reputation_playbooks_1_output_observable_item[1],
            "overwrite": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="tag_indicators")

    return


@phantom.playbook_block()
def outputs_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("outputs_filter() called")

    ################################################################################
    # Routes outputs based on reputation score and report availability.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["dispatch_reputation_playbooks_1:playbook_output:observable.reputation.score_id", ">=", 0]
        ],
        name="outputs_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_reports(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        tag_indicators(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_new_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_new_artifacts() called")

    ################################################################################
    # Only dispatch reputation playbooks against new artifacts.
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
        dispatch_reputation_playbooks_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def dispatch_reputation_playbooks_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_reputation_playbooks_1() called")

    filtered_artifact_0_data_filter_new_artifacts = phantom.collect2(container=container, datapath=["filtered-data:filter_new_artifacts:condition_1:artifact:*.id"])

    filtered_artifact_0__id = [item[0] for item in filtered_artifact_0_data_filter_new_artifacts]

    inputs = {
        "playbook_repo": [],
        "playbook_tags": ["reputation"],
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
    playbook_run_id = phantom.playbook("community/dispatch_input_playbooks", container=container, name="dispatch_reputation_playbooks_1", callback=outputs_decision, inputs=inputs)

    return


@phantom.playbook_block()
def merge_reports(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_reports() called")

    ################################################################################
    # Format a note that merges together normalized data. The data will come from 
    # the playbooks launched by the Dispatch Reputation Playbooks block.
    ################################################################################

    template = """SOAR performed Reputation Analysis based on available indicators and playbooks. The following table shows a summary of the information gathered.\n\n| Type | Value | Normalized Score | Categories | Source | Source Link |\n| --- | --- | --- | --- | --- | --- |\n%%\n| {0} | `{1}` | {2} | {3} | {4} | {5} |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:outputs_filter:condition_1:dispatch_reputation_playbooks_1:playbook_output:observable.type",
        "filtered-data:outputs_filter:condition_1:dispatch_reputation_playbooks_1:playbook_output:observable.value",
        "filtered-data:outputs_filter:condition_1:dispatch_reputation_playbooks_1:playbook_output:observable.reputation.score",
        "filtered-data:outputs_filter:condition_1:dispatch_reputation_playbooks_1:playbook_output:observable.categories",
        "filtered-data:outputs_filter:condition_1:dispatch_reputation_playbooks_1:playbook_output:observable.source",
        "filtered-data:outputs_filter:condition_1:dispatch_reputation_playbooks_1:playbook_output:observable.source_link"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="merge_reports")

    update_reputation_task(container=container)

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
            ["dispatch_reputation_playbooks_1:playbook_output:observable", "!=", None]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        outputs_filter(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_1(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="No observable data found from playbook.")

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
def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="No new artifacts found to perform Dynamic Identifier Reputation Analysis.")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return