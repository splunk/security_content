"""
This playbook checks for the presence of the Risk Response workbook and updates tasks or leaves generic notes. &quot;Risk_notable_verdict&quot; recommends this playbook as a second phase of the investigation. Additionally, this playbook can be used in ad-hoc investigations or incorporated into custom workbooks.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'workbook_list' block
    workbook_list(container=container)

    return

def workbook_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_list() called")

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_list", parameters=parameters, name="workbook_list", callback=workbook_decision)

    return


def workbook_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_decision() called")

    ################################################################################
    # Determines if the workbook Risk Response is present and available for use.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["workbook_list:custom_function_result.data.*.name", "==", "Risk Response"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        workbook_add(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_risk_notable_review_indicators(action=action, success=success, container=container, results=results, handle=handle)

    return


def workbook_add(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_add() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "workbook": "Risk Response",
        "container": id_value,
        "start_workbook": "true",
        "check_for_existing_workbook": "true",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_add", parameters=parameters, name="workbook_add", callback=workbook_start_task)

    return


def workbook_start_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_start_task() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "owner": None,
        "status": "in_progress",
        "container": id_value,
        "task_name": "Block Indicators",
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

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="workbook_start_task", callback=join_risk_notable_review_indicators)

    return


def join_risk_notable_review_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_risk_notable_review_indicators() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_risk_notable_review_indicators_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_risk_notable_review_indicators_called", value="risk_notable_review_indicators")

    # call connected block "risk_notable_review_indicators"
    risk_notable_review_indicators(container=container, handle=handle)

    return


def risk_notable_review_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("risk_notable_review_indicators() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/risk_notable_review_indicators", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/risk_notable_review_indicators", container=container, name="risk_notable_review_indicators", callback=indicator_get_by_tag)

    return


def risk_notable_block_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("risk_notable_block_indicators() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/risk_notable_block_indicators", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/risk_notable_block_indicators", container=container, name="risk_notable_block_indicators", callback=note_decision_1)

    return


def join_risk_notable_protect_assets_and_users(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_risk_notable_protect_assets_and_users() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_risk_notable_protect_assets_and_users_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_risk_notable_protect_assets_and_users_called", value="risk_notable_protect_assets_and_users")

    # call connected block "risk_notable_protect_assets_and_users"
    risk_notable_protect_assets_and_users(container=container, handle=handle)

    return


def risk_notable_protect_assets_and_users(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("risk_notable_protect_assets_and_users() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/risk_notable_protect_assets_and_users", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/risk_notable_protect_assets_and_users", container=container, name="risk_notable_protect_assets_and_users", callback=note_decision_2)

    return


def note_decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("note_decision_1() called")

    ################################################################################
    # Determine if a note was left by the previous playbook and if the Risk Mitigate 
    # workbook should be used.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["risk_notable_block_indicators:playbook_output:note_title", "!=", ""],
            ["risk_notable_block_indicators:playbook_output:note_content", "!=", ""],
            ["workbook_list:custom_function_result.data.*.name", "==", "Risk Mitigate"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        update_block_task(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["risk_notable_block_indicators:playbook_output:note_title", "!=", ""],
            ["risk_notable_block_indicators:playbook_output:note_content", "!=", ""]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        add_block_note(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def update_block_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_block_task() called")

    id_value = container.get("id", None)
    risk_notable_block_indicators_output_note_title = phantom.collect2(container=container, datapath=["risk_notable_block_indicators:playbook_output:note_title"])
    risk_notable_block_indicators_output_note_content = phantom.collect2(container=container, datapath=["risk_notable_block_indicators:playbook_output:note_content"])

    parameters = []

    # build parameters list for 'update_block_task' call
    for risk_notable_block_indicators_output_note_title_item in risk_notable_block_indicators_output_note_title:
        for risk_notable_block_indicators_output_note_content_item in risk_notable_block_indicators_output_note_content:
            parameters.append({
                "owner": None,
                "status": "closed",
                "container": id_value,
                "task_name": "Review and Block Indicators",
                "note_title": risk_notable_block_indicators_output_note_title_item[0],
                "note_content": risk_notable_block_indicators_output_note_content_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="update_block_task", callback=start_protect_task)

    return


def start_protect_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("start_protect_task() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "owner": None,
        "status": "in_progress",
        "container": id_value,
        "task_name": "Protect Assets and Users",
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

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="start_protect_task", callback=join_risk_notable_protect_assets_and_users)

    return


def add_block_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_block_note() called")

    ################################################################################
    # Custom code to handle leaving a note with a dynamic title and content when the 
    # Risk Mitigate workbook is not present.
    ################################################################################

    risk_notable_block_indicators_output_note_title = phantom.collect2(container=container, datapath=["risk_notable_block_indicators:playbook_output:note_title"])
    risk_notable_block_indicators_output_note_content = phantom.collect2(container=container, datapath=["risk_notable_block_indicators:playbook_output:note_content"])

    risk_notable_block_indicators_output_note_title_values = [item[0] for item in risk_notable_block_indicators_output_note_title]
    risk_notable_block_indicators_output_note_content_values = [item[0] for item in risk_notable_block_indicators_output_note_content]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    note_title = risk_notable_block_indicators_output_note_title_values
    note_content = risk_notable_block_indicators_output_note_content_values
    for title, content in zip(note_title, note_content):
        phantom.add_note(container=container, title=title, content=content, note_type="general", note_format="markdown")

    ################################################################################
    ## Custom Code End
    ################################################################################

    join_risk_notable_protect_assets_and_users(container=container)

    return


def note_decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("note_decision_2() called")

    ################################################################################
    # Determine if a note was left by the previous playbook and if the Risk Mitigate 
    # workbook should be used.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["risk_notable_protect_assets_and_users:playbook_output:note_title", "!=", ""],
            ["risk_notable_protect_assets_and_users:playbook_output:note_content", "!=", ""],
            ["workbook_list:custom_function_result.data.*.name", "==", "Risk Mitigate"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        update_protect_task(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["risk_notable_protect_assets_and_users:playbook_output:note_title", "!=", ""],
            ["risk_notable_protect_assets_and_users:playbook_output:note_content", "!=", ""]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        add_protect_note(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def update_protect_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_protect_task() called")

    id_value = container.get("id", None)
    risk_notable_protect_assets_and_users_output_note_title = phantom.collect2(container=container, datapath=["risk_notable_protect_assets_and_users:playbook_output:note_title"])
    risk_notable_protect_assets_and_users_output_note_content = phantom.collect2(container=container, datapath=["risk_notable_protect_assets_and_users:playbook_output:note_content"])

    parameters = []

    # build parameters list for 'update_protect_task' call
    for risk_notable_protect_assets_and_users_output_note_title_item in risk_notable_protect_assets_and_users_output_note_title:
        for risk_notable_protect_assets_and_users_output_note_content_item in risk_notable_protect_assets_and_users_output_note_content:
            parameters.append({
                "owner": None,
                "status": "complete",
                "container": id_value,
                "task_name": "Protect Assets and Users",
                "note_title": risk_notable_protect_assets_and_users_output_note_title_item[0],
                "note_content": risk_notable_protect_assets_and_users_output_note_content_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="update_protect_task")

    return


def add_protect_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_protect_note() called")

    ################################################################################
    # Custom code to handle leaving a note with a dynamic title and content when the 
    # Risk Mitigate workbook is not present.
    ################################################################################

    risk_notable_protect_assets_and_users_output_note_title = phantom.collect2(container=container, datapath=["risk_notable_protect_assets_and_users:playbook_output:note_title"])
    risk_notable_protect_assets_and_users_output_note_content = phantom.collect2(container=container, datapath=["risk_notable_protect_assets_and_users:playbook_output:note_content"])

    risk_notable_protect_assets_and_users_output_note_title_values = [item[0] for item in risk_notable_protect_assets_and_users_output_note_title]
    risk_notable_protect_assets_and_users_output_note_content_values = [item[0] for item in risk_notable_protect_assets_and_users_output_note_content]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    note_title = risk_notable_protect_assets_and_users_output_note_title_values
    note_content = risk_notable_protect_assets_and_users_output_note_content_values
    for title, content in zip(note_title, note_content):
        phantom.add_note(container=container, title=title, content=content, note_type="general", note_format="markdown")

    ################################################################################
    ## Custom Code End
    ################################################################################

    return


def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_4() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["indicator_get_by_tag:custom_function_result.data.*.indicator_value", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        risk_notable_block_indicators(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_risk_notable_protect_assets_and_users(action=action, success=success, container=container, results=results, handle=handle)

    return


def indicator_get_by_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_get_by_tag() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "tags_or": "marked_for_block",
        "tags_and": None,
        "container": id_value,
        "tags_exclude": "blocked, safe",
        "indicator_timerange": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_get_by_tag", parameters=parameters, name="indicator_get_by_tag", callback=decision_4)

    return


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