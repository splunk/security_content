"""
Detects available entities and routes them to attribute lookup playbooks. The output of the playbooks will create new artifacts for any technologies that returned information.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'decision_1' block
    decision_1(container=container)

    return

@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.id", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        new_artifact_filter(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_1(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def new_artifact_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("new_artifact_filter() called")

    ################################################################################
    # Only include new artifacts
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.id", "!=", ""]
        ],
        name="new_artifact_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        dispatch_attribute_lookup(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_1() called")

    ################################################################################
    # Leave a comment indicating no new artifacts were found
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
def dispatch_attribute_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_attribute_lookup() called")

    filtered_artifact_0_data_new_artifact_filter = phantom.collect2(container=container, datapath=["filtered-data:new_artifact_filter:condition_1:artifact:*.id"])

    filtered_artifact_0__id = [item[0] for item in filtered_artifact_0_data_new_artifact_filter]

    inputs = {
        "playbook_repo": [""],
        "playbook_tags": ["attributes"],
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
    playbook_run_id = phantom.playbook("community/dispatch_input_playbooks", container=container, name="dispatch_attribute_lookup", callback=observable_decision, inputs=inputs)

    return


@phantom.playbook_block()
def create_entity_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_entity_artifact() called")

    ################################################################################
    # Create new artifacts with the outputs of the dispatch lookup (Contains custom 
    # code)
    ################################################################################

    id_value = container.get("id", None)
    filtered_output_0_dispatch_attribute_lookup_output_observable = phantom.collect2(container=container, datapath=["filtered-data:observable_filter:condition_1:dispatch_attribute_lookup:playbook_output:observable"])

    parameters = []

    # build parameters list for 'create_entity_artifact' call
    for filtered_output_0_dispatch_attribute_lookup_output_observable_item in filtered_output_0_dispatch_attribute_lookup_output_observable:
        parameters.append({
            "name": filtered_output_0_dispatch_attribute_lookup_output_observable_item[0],
            "tags": None,
            "label": "attribute_lookup",
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "container": id_value,
            "input_json": None,
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []
    
    for filtered_output_0_dispatch_attribute_lookup_output_observable_item in filtered_output_0_dispatch_attribute_lookup_output_observable:
        name = (
            f"{filtered_output_0_dispatch_attribute_lookup_output_observable_item[0]['type'].capitalize()} "
            f"\'{filtered_output_0_dispatch_attribute_lookup_output_observable_item[0]['value']}\' "
            f"details from "
            f"{filtered_output_0_dispatch_attribute_lookup_output_observable_item[0]['source']}"
        )
        cef_dict = {
            "cef": filtered_output_0_dispatch_attribute_lookup_output_observable_item[0]['attributes']
        }
        parameters.append({
            "name": name,
            "tags": None,
            "label": "attribute_lookup",
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "container": id_value,
            "input_json": json.dumps(cef_dict),
            "cef_data_type": None,
            "run_automation": None,
        })
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="create_entity_artifact", callback=workbook_task_update_4)

    return


@phantom.playbook_block()
def observable_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("observable_decision() called")

    ################################################################################
    # Determine if there are any results from the dispatch playbook
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["dispatch_attribute_lookup:playbook_output:observable", "!=", None]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        observable_filter(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_3(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_comment_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_3() called")

    ################################################################################
    # Leave a comment indicating the playbooks did not have results.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="No observable data found.")

    return


@phantom.playbook_block()
def workbook_task_update_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_task_update_4() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "owner": None,
        "status": "complete",
        "container": id_value,
        "task_name": "playbook",
        "note_title": None,
        "note_content": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="workbook_task_update_4")

    return


@phantom.playbook_block()
def observable_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("observable_filter() called")

    ################################################################################
    # Exclude Null playbook outputs
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["dispatch_attribute_lookup:playbook_output:observable", "!=", None]
        ],
        name="observable_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        create_entity_artifact(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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