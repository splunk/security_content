"""
Find AWS accounts that have not been used for a long time (90 days by default). For each unused account, gather additional group and policy information and create an artifact to enable further automation or manual action.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_all_accounts' block
    list_all_accounts(container=container)
    # call 'calculate_start_time' block
    calculate_start_time(container=container)

    return

def list_all_accounts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_all_accounts() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # List all AWS IAM accounts, which will include the PasswordLastUsed field for 
    # us to filter on.
    ################################################################################

    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("list users", parameters=parameters, name="list_all_accounts", assets=["aws_iam"], callback=join_filter_inactive_accounts)

    return


def calculate_start_time(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("calculate_start_time() called")

    parameters = []

    parameters.append({
        "input_datetime": None,
        "input_format_string": None,
        "modification_unit": "days",
        "amount_to_modify": -90,
        "output_format_string": "%Y-%m-%dT%H:%M:%SZ",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/datetime_modify", parameters=parameters, name="calculate_start_time", callback=join_filter_inactive_accounts)

    return


def join_filter_inactive_accounts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_filter_inactive_accounts() called")

    if phantom.completed(action_names=["list_all_accounts"], custom_function_names=["calculate_start_time"]):
        # call connected block "filter_inactive_accounts"
        filter_inactive_accounts(container=container, handle=handle)

    return


def filter_inactive_accounts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_inactive_accounts() called")

    ################################################################################
    # Compare the PasswordLastUsed field to the calculated start time to find unused 
    # accounts. Ignore accounts with no value for PasswordLastUsed. This will ignore 
    # all accounts with no passwords, such as accounts that only use API access keys.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["list_all_accounts:action_result.data.*.PasswordLastUsed", "<", "calculate_start_time:custom_function_result.data.datetime_string"],
            ["list_all_accounts:action_result.data.*.PasswordLastUsed", "!=", ""]
        ],
        name="filter_inactive_accounts:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_unused_account_information(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def get_unused_account_information(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_unused_account_information() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Use the "get user" action to gather more information about the unused accounts, 
    # including group membership and policy assignments.
    ################################################################################

    filtered_result_0_data_filter_inactive_accounts = phantom.collect2(container=container, datapath=["filtered-data:filter_inactive_accounts:condition_1:list_all_accounts:action_result.data.*.UserName"])

    parameters = []

    # build parameters list for 'get_unused_account_information' call
    for filtered_result_0_item_filter_inactive_accounts in filtered_result_0_data_filter_inactive_accounts:
        if filtered_result_0_item_filter_inactive_accounts[0] is not None:
            parameters.append({
                "username": filtered_result_0_item_filter_inactive_accounts[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get user", parameters=parameters, name="get_unused_account_information", assets=["aws_iam"], callback=save_to_artifacts)

    return


def save_to_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("save_to_artifacts() called")

    id_value = container.get("id", None)
    get_unused_account_information_result_data = phantom.collect2(container=container, datapath=["get_unused_account_information:action_result.parameter.username","get_unused_account_information:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'save_to_artifacts' call
    for get_unused_account_information_result_item in get_unused_account_information_result_data:
        parameters.append({
            "container": id_value,
            "name": "Unused AWS Account",
            "label": "user",
            "severity": None,
            "cef_field": "awsUserName",
            "cef_value": get_unused_account_information_result_item[0],
            "cef_data_type": "aws iam user name",
            "tags": None,
            "run_automation": "false",
            "input_json": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="save_to_artifacts", callback=playbook_aws_disable_user_accounts_1)

    return


def playbook_aws_disable_user_accounts_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_aws_disable_user_accounts_1() called")

    get_unused_account_information_result_data = phantom.collect2(container=container, datapath=["get_unused_account_information:action_result.parameter.username"], action_results=results)

    get_unused_account_information_parameter_username = [item[0] for item in get_unused_account_information_result_data]

    inputs = {
        "aws_username": get_unused_account_information_parameter_username,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/aws_disable_user_accounts", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/aws_disable_user_accounts", container=container, inputs=inputs)

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