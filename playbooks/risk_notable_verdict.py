"""
Find available response tagged playbooks and present them to the analyst. Based on analyst selection, launch next their chosen playbook.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_effective_user' block
    get_effective_user(container=container)

    return

def get_effective_user(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_effective_user() called")

    ################################################################################
    # Get the user that launched this playbook.
    ################################################################################

    get_effective_user__username = None
    get_effective_user__user_type = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    effective_user_id = phantom.get_effective_user()
    url = phantom.build_phantom_rest_url('ph_user', effective_user_id)
    response_json = phantom.requests.get(url, verify=False).json()
    get_effective_user__username = response_json['username']
    get_effective_user__user_type = response_json['type']

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="get_effective_user:username", value=json.dumps(get_effective_user__username))
    phantom.save_run_data(key="get_effective_user:user_type", value=json.dumps(get_effective_user__user_type))

    user_decision(container=container)

    return


def user_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("user_decision() called")

    ################################################################################
    # Based on the user that launched this playbook, decide to go to the next block 
    # or end playbook.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_effective_user:custom_function:user_type", "!=", "automation"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        workbook_list(action=action, success=success, container=container, results=results, handle=handle)
        return

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

    phantom.custom_function(custom_function="community/workbook_list", parameters=parameters, name="workbook_list", callback=decision_2)

    return


def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["workbook_list:custom_function_result.data.*.name", "==", "Risk Investigation"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        workbook_add(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_list_response_playbooks(action=action, success=success, container=container, results=results, handle=handle)

    return


def workbook_add(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_add() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "workbook": "Risk Investigation",
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

    phantom.custom_function(custom_function="community/workbook_add", parameters=parameters, name="workbook_add", callback=workbook_start)

    return


def workbook_start(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_start() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "owner": None,
        "status": "in_progress",
        "container": id_value,
        "task_name": "Render Verdict",
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

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="workbook_start", callback=join_list_response_playbooks)

    return


def join_list_response_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_list_response_playbooks() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_list_response_playbooks_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_list_response_playbooks_called", value="list_response_playbooks")

    # call connected block "list_response_playbooks"
    list_response_playbooks(container=container, handle=handle)

    return


def list_response_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_response_playbooks() called")

    parameters = []

    parameters.append({
        "name": None,
        "repo": None,
        "tags": "response_option",
        "category": None,
        "playbook_type": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/playbooks_list", parameters=parameters, name="list_response_playbooks", callback=playbook_decision)

    return


def playbook_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_decision() called")

    ################################################################################
    # Determine if any response playbooks were found.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["list_response_playbooks:custom_function_result.data.*.full_name", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        select_response_plan(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["workbook_list:custom_function_result.data.*.name", "==", "Risk Investigation"]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        workbook_task_update(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 3
    add_error_note(action=action, success=success, container=container, results=results, handle=handle)

    return


def select_response_plan(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("select_response_plan() called")

    # set user and message variables for phantom.prompt call
    user = json.loads(phantom.get_run_data(key='get_effective_user:username'))
    message = """Splunk SOAR has loaded all available response plans\n - Only Playbooks with tags "response_option" are shown."""
    
    # Playbooks list
    playbook_list = phantom.collect2(container=container, datapath=["list_response_playbooks:custom_function_result.data.*.full_name"], action_results=results)
    playbook_list = [item[0] for item in playbook_list]
    playbook_list.append("Do Nothing")
    
    #responses:
    response_types = [
        {
            "prompt": "Response Plan",
            "options": {
                "type": "list",
                "choices": playbook_list
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="select_response_plan", response_types=response_types, callback=user_response_decision)

    return

def workbook_task_update(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_task_update() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "owner": None,
        "status": None,
        "container": id_value,
        "task_name": "Render Verdict",
        "note_title": "[Auto-Generated] Verdict Error",
        "note_content": "No response playbooks found for criteria in playbook_list utility block.",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="workbook_task_update")

    return


def add_error_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_error_note() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content="No response playbooks found for criteria in playbook_list utility block.", note_format="markdown", note_type="general", title="[Auto-Generated] Verdict Error")

    return


def decide_and_launch_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decide_and_launch_playbook() called")

    ################################################################################
    # Process user responses and determine which playbook should be launched.
    ################################################################################

    select_response_plan_result_data = phantom.collect2(container=container, datapath=["select_response_plan:action_result.summary.responses.0"], action_results=results)

    select_response_plan_summary_responses_0 = [item[0] for item in select_response_plan_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Lunch the playbook that the analyst chose.
    playbook_run_id = phantom.playbook(playbook=select_response_plan_summary_responses_0[0], container=container)

    ################################################################################
    ## Custom Code End
    ################################################################################

    decision_5(container=container)

    return


def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_5() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["workbook_list:custom_function_result.data.*.name", "==", "Risk Investigation"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_task_close(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def task_close(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("task_close() called")

    id_value = container.get("id", None)
    format_task_close = phantom.get_format_data(name="format_task_close")

    parameters = []

    parameters.append({
        "owner": None,
        "status": "complete",
        "container": id_value,
        "task_name": "Render Verdict",
        "note_title": "[Auto-Generated] Response Verdict Summary",
        "note_content": format_task_close,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="task_close")

    return


def user_response_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("user_response_decision() called")

    ################################################################################
    # Determine if the user opted to launch a playbook.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["select_response_plan:action_result.summary.responses.0", "!=", "Do Nothing"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        decide_and_launch_playbook(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def format_task_close(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_task_close() called")

    ################################################################################
    # Format a note with the response plan that the user chose.
    ################################################################################

    template = """Launched '{0}' based on user selection.\n"""

    # parameter list for template variable replacement
    parameters = [
        "select_response_plan:action_result.summary.responses.0"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_task_close")

    task_close(container=container)

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