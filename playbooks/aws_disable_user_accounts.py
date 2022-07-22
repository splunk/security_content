"""
Disable a list of AWS IAM user accounts. After checking the list of accounts against an allowlist and confirming with an analyst, each account is disabled. The change can be reversed with the &quot;enable user&quot; action.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_1' block
    filter_1(container=container)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:aws_username", "in", "custom_list:aws_inactive_user_allowlist"]
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        indicator_tag_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:aws_username", "not in", "custom_list:aws_inactive_user_allowlist"]
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        aws_disable_user_check(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


def aws_disable_user_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("aws_disable_user_check() called")

    # set user and message variables for phantom.prompt call

    user = "proyer"
    message = """The following AWS user(s) were found to be inactive:\n\n```\n{0}\n```"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_2:playbook_input:aws_username"
    ]

    # responses
    response_types = [
        {
            "prompt": "Should those user account(s) be disabled?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="aws_disable_user_check", parameters=parameters, response_types=response_types, callback=decision_1)

    return


def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["aws_disable_user_check:action_result.summary.responses.0", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        disable_user_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def disable_user_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("disable_user_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_input_0_aws_username = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_2:playbook_input:aws_username"])

    parameters = []

    # build parameters list for 'disable_user_1' call
    for filtered_input_0_aws_username_item in filtered_input_0_aws_username:
        if filtered_input_0_aws_username_item[0] is not None:
            parameters.append({
                "username": filtered_input_0_aws_username_item[0],
                "disable_access_keys": True,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("disable user", parameters=parameters, name="disable_user_1", assets=["aws_iam"])

    return


def indicator_tag_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_tag_4() called")

    filtered_input_0_aws_username = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:aws_username"])

    parameters = []

    # build parameters list for 'indicator_tag_4' call
    for filtered_input_0_aws_username_item in filtered_input_0_aws_username:
        parameters.append({
            "indicator": filtered_input_0_aws_username_item[0],
            "tags": "aws_inactive_user_allowlist",
            "overwrite": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="indicator_tag_4")

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