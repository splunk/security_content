"""
Accepts user name that needs to be disabled in Azure Active Directory. Generates an observable output based on the status of account locking or disabling.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'user_name_filter' block
    user_name_filter(container=container)

    return

@phantom.playbook_block()
def user_name_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("user_name_filter() called")

    ################################################################################
    # Filter user name inputs to route inputs to appropriate actions.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:user", "!=", ""]
        ],
        name="user_name_filter:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        disable_user_account(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def disable_user_account(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("disable_user_account() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Disable the user attributes for filtered playbook inputs.
    ################################################################################

    filtered_input_0_user = phantom.collect2(container=container, datapath=["filtered-data:user_name_filter:condition_1:playbook_input:user"])

    parameters = []

    # build parameters list for 'disable_user_account' call
    for filtered_input_0_user_item in filtered_input_0_user:
        if filtered_input_0_user_item[0] is not None:
            parameters.append({
                "user_id": filtered_input_0_user_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("disable user", parameters=parameters, name="disable_user_account", assets=["azure_ad_graph"], callback=filter_disable_result)

    return


@phantom.playbook_block()
def username_observables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("username_observables() called")

    ################################################################################
    # Format a normalized output for each user.
    ################################################################################

    filtered_result_0_data_filter_disable_result = phantom.collect2(container=container, datapath=["filtered-data:filter_disable_result:condition_1:disable_user_account:action_result.parameter.user_id","filtered-data:filter_disable_result:condition_1:disable_user_account:action_result.status","filtered-data:filter_disable_result:condition_1:disable_user_account:action_result.message"])

    filtered_result_0_parameter_user_id = [item[0] for item in filtered_result_0_data_filter_disable_result]
    filtered_result_0_status = [item[1] for item in filtered_result_0_data_filter_disable_result]
    filtered_result_0_message = [item[2] for item in filtered_result_0_data_filter_disable_result]

    username_observables__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    username_observables__observable_array = []
    
    for user_id, status, msg in zip(filtered_result_0_parameter_user_id, filtered_result_0_status, filtered_result_0_message):
        user_acc_status = {
            "type": "Azure AD Account",
            "value": user_id,
            "message": msg,
            "status": status
        }
        username_observables__observable_array.append(user_acc_status)
        #phantom.debug(username_observables__observable_array)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="username_observables:observable_array", value=json.dumps(username_observables__observable_array))

    return


@phantom.playbook_block()
def filter_disable_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_disable_result() called")

    ################################################################################
    # filter check if the user is disabled successfully.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["disable_user_account:action_result.status", "==", "success"]
        ],
        name="filter_disable_result:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        username_observables(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    username_observables__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="username_observables:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "observable": username_observables__observable_array,
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