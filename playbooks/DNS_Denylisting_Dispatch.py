"""
Detects available indicators and routes them to dispatch DNS denylisting playbooks.  These playbooks will block the given domains. The output of the analysis will update any artifacts, tasks, and indicator tags.\n\nhttps://d3fend.mitre.org/technique/d3f:DNSDenylisting/
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'artifact_exists' block
    artifact_exists(container=container)

    return

@phantom.playbook_block()
def artifact_exists(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_exists() called")

    ################################################################################
    # Checks if a artifact exists
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.id", "!=", None]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_new_artifacts(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    comment_no_new_artifacts(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def filter_new_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_new_artifacts() called")

    ################################################################################
    # Only dispatch playbooks against new artifacts.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.id", "!=", None]
        ],
        name="filter_new_artifacts:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        dispatch_dns_denylisting_playbooks(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def comment_no_new_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_no_new_artifacts() called")

    ################################################################################
    # Add comment when no new artifacts exists.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="No new artifacts found.")

    return


@phantom.playbook_block()
def dispatch_dns_denylisting_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_dns_denylisting_playbooks() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.id"])

    container_artifact_header_item_0 = [item[0] for item in container_artifact_data]

    inputs = {
        "playbook_tags": ["denylist"],
        "playbook_repo": [],
        "indicator_tags_include": [],
        "indicator_tags_exclude": [],
        "artifact_ids_include": container_artifact_header_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/dispatch_input_playbooks", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/dispatch_input_playbooks", container=container, name="dispatch_dns_denylisting_playbooks", callback=outputs_decision, inputs=inputs)

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
            ["dispatch_dns_denylisting_playbooks:playbook_output:observable", "!=", None]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        output_filter(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    comment_no_observables(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def tag_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("tag_indicators() called")

    filtered_output_0_dispatch_dns_denylisting_playbooks_output_observable = phantom.collect2(container=container, datapath=["filtered-data:output_filter:condition_1:dispatch_dns_denylisting_playbooks:playbook_output:observable.value"])

    parameters = []

    # build parameters list for 'tag_indicators' call
    for filtered_output_0_dispatch_dns_denylisting_playbooks_output_observable_item in filtered_output_0_dispatch_dns_denylisting_playbooks_output_observable:
        parameters.append({
            "tags": "blocked",
            "indicator": filtered_output_0_dispatch_dns_denylisting_playbooks_output_observable_item[0],
            "overwrite": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="tag_indicators", callback=format_note)

    return


@phantom.playbook_block()
def format_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note() called")

    ################################################################################
    # Format a note that merges together normalized data. 
    ################################################################################

    template = """Splunk SOAR blocked the following domains:\n\n| domain | status | source |\n| --- | --- | --- |\n%%\n| {0} | {1} | {2} |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:output_filter:condition_1:dispatch_dns_denylisting_playbooks:playbook_output:observable.value",
        "filtered-data:output_filter:condition_1:dispatch_dns_denylisting_playbooks:playbook_output:observable.status",
        "filtered-data:output_filter:condition_1:dispatch_dns_denylisting_playbooks:playbook_output:observable.source"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note")

    update_isolation_task(container=container)

    return


@phantom.playbook_block()
def update_isolation_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_isolation_task() called")

    id_value = container.get("id", None)
    format_note = phantom.get_format_data(name="format_note")

    parameters = []

    parameters.append({
        "owner": None,
        "status": "complete",
        "container": id_value,
        "task_name": "playbook",
        "note_title": "DNS Denylisting Dispatch Report",
        "note_content": format_note,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="update_isolation_task")

    return


@phantom.playbook_block()
def comment_no_observables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comment_no_observables() called")

    ################################################################################
    # Add comment when no observables were generated.
    ################################################################################

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
def output_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("output_filter() called")

    ################################################################################
    # Determine if the observable is not None.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["dispatch_dns_denylisting_playbooks:playbook_output:observable", "!=", None]
        ],
        name="output_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        tag_indicators(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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