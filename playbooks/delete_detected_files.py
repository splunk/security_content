"""
This playbook acts upon events where a file has been determined to be malicious (ie webshells being dropped on an end host).

Before deleting the file, we run a "more' command on the file in question to extract its contents.

We then run a delete on the file in question.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Format_More_Command' block
    Format_More_Command(container=container)

    return

def Format_Del_Command(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Del_Command() called')
    
    template = """del \"{0}\""""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.filePath",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Del_Command")

    Delete_File(container=container)

    return

def Format_More_Command(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_More_Command() called')
    
    template = """more \"{0}\""""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.filePath",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_More_Command")

    Gather_File_Contents(container=container)

    return

def Gather_File_Contents(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Gather_File_Contents() called')

    # collect data for 'Gather_File_Contents' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='Format_More_Command')

    parameters = []
    
    # build parameters list for 'Gather_File_Contents' call
    for container_item in container_data:
        parameters.append({
            'ip_hostname': container_item[0],
            'command': formatted_data_1,
            'arguments': "",
            'parser': "",
            'async': "",
            'command_id': "",
            'shell_id': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act(action="run command", parameters=parameters, assets=['winrm'], callback=Format_Del_Command, name="Gather_File_Contents")

    return

def Delete_File(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Delete_File() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Delete_File' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='Format_Del_Command')

    parameters = []
    
    # build parameters list for 'Delete_File' call
    for container_item in container_data:
        parameters.append({
            'ip_hostname': container_item[0],
            'command': formatted_data_1,
            'arguments': "",
            'parser': "",
            'async': "",
            'command_id': "",
            'shell_id': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act(action="run command", parameters=parameters, assets=['winrm'], name="Delete_File")

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