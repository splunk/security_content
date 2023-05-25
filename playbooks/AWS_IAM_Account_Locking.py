"""
Accepts user name that needs to be disabled in AWS IAM Active Directory. Generates an observable output based on the status of account locking or disabling.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'username_filter' block
    username_filter(container=container)

    return

@phantom.playbook_block()
def username_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("username_filter() called")

    ################################################################################
    # Filter user name inputs to route inputs to appropriate actions.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:user", "!=", ""]
        ],
        name="username_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        disable_user_account(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def disable_user_account(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("disable_user_account() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Disable user account from filtered playbook inputs.
    ################################################################################

    filtered_input_0_user = phantom.collect2(container=container, datapath=["filtered-data:username_filter:condition_1:playbook_input:user"])

    parameters = []

    # build parameters list for 'disable_user_account' call
    for filtered_input_0_user_item in filtered_input_0_user:
        if filtered_input_0_user_item[0] is not None:
            parameters.append({
                "disable_access_keys": True,
                "username": filtered_input_0_user_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("disable user", parameters=parameters, name="disable_user_account", assets=["aws_iam"], callback=filter_disable_result)

    return


@phantom.playbook_block()
def username_observables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("username_observables() called")

    ################################################################################
    # Format a normalized output for each user.
    ################################################################################

    filtered_result_0_data_filter_disable_result = phantom.collect2(container=container, datapath=["filtered-data:filter_disable_result:condition_1:disable_user_account:action_result.parameter.disable_access_keys","filtered-data:filter_disable_result:condition_1:disable_user_account:action_result.parameter.username","filtered-data:filter_disable_result:condition_1:disable_user_account:action_result.parameter.credentials","filtered-data:filter_disable_result:condition_1:disable_user_account:action_result.data.*.RequestId","filtered-data:filter_disable_result:condition_1:disable_user_account:action_result.message","filtered-data:filter_disable_result:condition_1:disable_user_account:action_result.status"])

    filtered_result_0_parameter_disable_access_keys = [item[0] for item in filtered_result_0_data_filter_disable_result]
    filtered_result_0_parameter_username = [item[1] for item in filtered_result_0_data_filter_disable_result]
    filtered_result_0_parameter_credentials = [item[2] for item in filtered_result_0_data_filter_disable_result]
    filtered_result_0_data___requestid = [item[3] for item in filtered_result_0_data_filter_disable_result]
    filtered_result_0_message = [item[4] for item in filtered_result_0_data_filter_disable_result]
    filtered_result_0_status = [item[5] for item in filtered_result_0_data_filter_disable_result]

    username_observables__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    username_observables__observable_array = []
    
    for access_key, usrname, creds, req_id, msg, status in zip(filtered_result_0_parameter_disable_access_keys, filtered_result_0_parameter_username, filtered_result_0_parameter_credentials, filtered_result_0_data___requestid, filtered_result_0_message, filtered_result_0_status):
        user_acc_status = {
            "type": "aws iam user name",
            "value": usrname,
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
        name="filter_disable_result:condition_1")

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