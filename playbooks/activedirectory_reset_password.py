"""
This playbook resets the password of a potentially compromised user account. First, an analyst is prompted to evaluate the situation and choose whether to reset the account. If they approve, a strong password is generated and the password is reset.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

from random import randint
from random import shuffle

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')

    reset_password(container=container)

    return

"""
Custom code block that generates a strong random password
"""
def generate_password(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('generate_password() called')
    
    input_parameter_0 = ""

    generate_password__strong_password = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    alpha = 'abcdefghijklmnopqrstuvwxyz'
    num = '0123456789'
    special = '!@#$%^&*('
    
    pwd = ''
    for i in range(5):
        pwd += alpha[randint(0, len(alpha)-1)]
        pwd += (alpha[randint(0, len(alpha)-1)]).upper()
        pwd += num[randint(0, len(num)-1)]
        pwd += special[randint(0, len(special)-1)]
    r = list(pwd)
    shuffle(r)
    generate_password__strong_password = ''.join(r)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='generate_password:strong_password', value=json.dumps(generate_password__strong_password))
    reset_ad_password(container=container)
    format_pwd_message(container=container)

    return

def reset_password(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reset_password() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Found the account \"{0}\" has a compromised credential! Would you like to automatically reset the password?"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.compromisedUserName",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="reset_password", parameters=parameters, response_types=response_types, callback=reset_option)

    return

def reset_option(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reset_option() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["reset_password:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        generate_password(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    format_decline_msg(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Reset the Active Directory password of the user to the generated password
"""
def reset_ad_password(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reset_ad_password() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    generate_password__strong_password = json.loads(phantom.get_run_data(key='generate_password:strong_password'))
    # collect data for 'reset_ad_password' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.compromisedUserName', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'reset_ad_password' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'username': container_item[0],
                'new_password': generate_password__strong_password,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="set password", parameters=parameters, assets=['active directory'], name="reset_ad_password")

    return

def add_comment_pwd_reset(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_pwd_reset() called')

    formatted_data_1 = phantom.get_format_data(name='format_pwd_message')

    phantom.comment(container=container, comment=formatted_data_1)

    return

"""
Formats a message about the password reset to provide in the comments
"""
def format_pwd_message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_pwd_message() called')
    
    template = """Reset user {0} password to {1}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.compromisedUserName",
        "generate_password:custom_function:strong_password",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_pwd_message")

    add_comment_pwd_reset(container=container)

    return

"""
Formats a message stating the user declined to reset the password
"""
def format_decline_msg(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_decline_msg() called')
    
    template = """Analyst declined to reset password for user: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.compromisedUserName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_decline_msg")

    add_comment_no_reset(container=container)

    return

"""
Add the comment notifying the reader that the password reset was declined
"""
def add_comment_no_reset(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_no_reset() called')

    formatted_data_1 = phantom.get_format_data(name='format_decline_msg')

    phantom.comment(container=container, comment=formatted_data_1)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return