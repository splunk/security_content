"""
This is a playbook that is designed to be recommended within a workbook. If used in this manner, the playbook will assign the user that launched the playbook as the owner of the event, move the event status to &quot;Open&quot;, and complete the workbook task where this playbook appears. If there is a task after the one where the playbook appears (within the same phase), it will set the next task to &quot;In Progress.&quot;
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
    # Find the user and user type that launched this playbook.
    ################################################################################

    get_effective_user__user_id = None
    get_effective_user__user_type = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    effective_user_id = phantom.get_effective_user()
    url = phantom.build_phantom_rest_url('ph_user', effective_user_id)
    response_json = phantom.requests.get(url, verify=False).json()
    
    get_effective_user__user_type = response_json['type']
    get_effective_user__user_id = effective_user_id
        

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="get_effective_user:user_id", value=json.dumps(get_effective_user__user_id))
    phantom.save_run_data(key="get_effective_user:user_type", value=json.dumps(get_effective_user__user_type))

    user_decision(container=container)

    return


def user_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("user_decision() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_effective_user:custom_function:user_type", "!=", "automation"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_owner(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def set_owner(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_owner() called")

    ################################################################################
    # Sets the owner of the container as the user that launched this playbook
    ################################################################################

    get_effective_user__user_id = json.loads(phantom.get_run_data(key="get_effective_user:user_id"))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    phantom.set_owner(container=container, user=get_effective_user__user_id)

    ################################################################################
    ## Custom Code End
    ################################################################################

    status_decision(container=container)

    return


def status_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("status_decision() called")

    ################################################################################
    # Determine if the status of the container should be changed.
    ################################################################################

    status_value = container.get("status", None)

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            [status_value, "==", "new"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_status_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_update_workbook_tasks(action=action, success=success, container=container, results=results, handle=handle)

    return


def set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_status_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="open")

    container = phantom.get_container(container.get('id', None))

    join_update_workbook_tasks(container=container)

    return


def join_update_workbook_tasks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_update_workbook_tasks() called")

    # call connected block "update_workbook_tasks"
    update_workbook_tasks(container=container, handle=handle)

    return


def update_workbook_tasks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_workbook_tasks() called")

    ################################################################################
    # Custom code to determine which task this playbook occurs in, complete that task, 
    # and set the status of the next task in the workbook (within the same phase) 
    # to "In Progress".
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Get current repo and playbook name
    current_scm = phantom.get_playbook_info()[0]['repo_name']
    current_playbook = phantom.get_playbook_info()[0]['name']
    task_order = None
    
    # Iterate through tasks on the current container
    for task in phantom.get_tasks(container=container):
        playbooks = task.get('data').get('suggestions').get('playbooks')
        if playbooks:
            for playbook in playbooks:
                # Check if the current container tasks contain a reference to this playbook.
                # If so, this is the task phase you want to mark as current
                if playbook['playbook'] == current_playbook and playbook['scm'] == current_scm:
                    task_order = task['data']['order']
                    status = task['data']['status']
                    url = phantom.build_phantom_rest_url('workbook_task') + '/{}'.format(task['data']['id'])
                    # If status is not started (statud id 0), move to in progress (status id 2) before moving to complete (status id 1)
                    if status == 0:
                        data = {'status': 2}
                        phantom.requests.post(url, data=json.dumps(data), verify=False)
                    data = {'status': 1}      
                    phantom.set_phase(container=container, phase=task['data']['phase']) 
                    phantom.requests.post(url, data=json.dumps(data), verify=False)
                    
    # Iterate through the other tasks on the current container if a task was updated as indicated by the presence of "task_order"                
    if task_order:
        for task in phantom.get_tasks(container=container):
            # If another task matches the updated task's order + 1, then update it as well
            if task['data']['order'] == task_order + 1:
                data = {'status': 2}
                url = phantom.build_phantom_rest_url('workbook_task') + '/{}'.format(task['data']['id'])
                phantom.requests.post(url, data=json.dumps(data), verify=False)


    ################################################################################
    ## Custom Code End
    ################################################################################

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