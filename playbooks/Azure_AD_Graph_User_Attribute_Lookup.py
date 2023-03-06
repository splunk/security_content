"""
Accepts a user or device and looks up the most recent attributes and groups for that user or device. This playbook produces a normalized output for each user and device.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'playbook_inputs_filter' block
    playbook_inputs_filter(container=container)

    return

@phantom.playbook_block()
def get_user_attributes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_user_attributes() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Query for the user attributes for filtered playbook inputs.
    ################################################################################

    filtered_input_0_user = phantom.collect2(container=container, datapath=["filtered-data:playbook_inputs_filter:condition_1:playbook_input:user"])

    parameters = []

    # build parameters list for 'get_user_attributes' call
    for filtered_input_0_user_item in filtered_input_0_user:
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

    phantom.act("list user attributes", parameters=parameters, name="get_user_attributes", assets=["azure_ad_graph"], callback=user_results_filter)

    return


@phantom.playbook_block()
def format_user_outputs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_user_outputs() called")

    ################################################################################
    # Format a normalized output for each user.
    ################################################################################

    filtered_result_0_data_user_results_filter = phantom.collect2(container=container, datapath=["filtered-data:user_results_filter:condition_1:get_user_attributes:action_result.data.0","filtered-data:user_results_filter:condition_1:get_user_attributes:action_result.parameter.user_id"])

    filtered_result_0_data_0 = [item[0] for item in filtered_result_0_data_user_results_filter]
    filtered_result_0_parameter_user_id = [item[1] for item in filtered_result_0_data_user_results_filter]

    format_user_outputs__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    format_user_outputs__observable_array = []
    
    # create normalized output dictionary
    for pb_input, user in zip(filtered_result_0_parameter_user_id, filtered_result_0_data_0):
        user_dict = {
            "account_type": "Azure AD Account",
            "account_type_id": 6,
            "account_uid": user['userPrincipalName'],
            "domain": user['userPrincipalName'].split('@')[1],
            "email_addr": user['mail'],
            "full_name": user['displayName'],
            "name": user['userPrincipalName'].split('@')[0],
            "start_date": user['createdDateTime'],
            "type": "User",
            "type_id": 1,
            "uid": user['objectId']
        }
        phones = [
            user['telephoneNumber'],
            user['facsimileTelephoneNumber']
        ]
        labels = [
            user['jobTitle'],
            user['department']
        ]
        
                
        # clean up phone numbers
        phones = [phone for phone in phones if phone]
        user_dict['phones'] = phones
            
        # clean up labels
        labels = [label for label in labels if label]
        user_dict['labels'] = labels
                
        final_output = {
            "type": "user",
            "value": pb_input,
            "attributes": user_dict,
            "source": "Azure AD Graph"
        }
        format_user_outputs__observable_array.append(final_output)
        
    # phantom.debug(format_user_outputs__observable_array)
        

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="format_user_outputs:observable_array", value=json.dumps(format_user_outputs__observable_array))

    return


@phantom.playbook_block()
def playbook_inputs_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_inputs_filter() called")

    ################################################################################
    # Filter inputs to route inputs to appropriate actions.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:user", "!=", None]
        ],
        name="playbook_inputs_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_user_attributes(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def user_results_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("user_results_filter() called")

    ################################################################################
    # Determine if a user was found from the preceding action
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["get_user_attributes:action_result.status", "==", "success"]
        ],
        name="user_results_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_user_outputs(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_user_outputs__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="format_user_outputs:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    format_device_outputs__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="format_device_outputs:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    observable_combined_value = phantom.concatenate(format_user_outputs__observable_array, format_device_outputs__observable_array)

    output = {
        "observable": observable_combined_value,
    }

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

    phantom.save_playbook_output_data(output=output)

    return