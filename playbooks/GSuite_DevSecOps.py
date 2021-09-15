"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Get_File_from_GDrive' block
    Get_File_from_GDrive(container=container)

    # call 'ip_reputation_1' block
    ip_reputation_1(container=container)

    return

def Get_File_from_GDrive(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_File_from_GDrive() called')

    # collect data for 'Get_File_from_GDrive' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.doc_id', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Get_File_from_GDrive' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'id': container_item[0],
                'ph': "",
                'email': "",
                'file_name': "",
                'mime_type': "",
                'download_file': True,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get file", parameters=parameters, assets=['google-gdrive'], callback=VT_Lookup, name="Get_File_from_GDrive")

    return

def VT_Lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('VT_Lookup() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'VT_Lookup' call
    results_data_1 = phantom.collect2(container=container, datapath=['Get_File_from_GDrive:action_result.summary.vault_id', 'Get_File_from_GDrive:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'VT_Lookup' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'hash': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="get file", parameters=parameters, assets=['virustotal'], callback=VT_Lookup_Error_Handling, name="VT_Lookup", parent_action=action)

    return

def VT_Lookup_Error_Handling(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('VT_Lookup_Error_Handling() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["VT_Lookup:action_result.status", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Prompt_for_Upload(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

def Prompt_for_Upload(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prompt_for_Upload() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Should this file be uploaded to VirusTotal?"""

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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Prompt_for_Upload", separator=", ", response_types=response_types, callback=Prompt_Handling)

    return

def Prompt_Handling(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prompt_Handling() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Prompt_for_Upload:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        VT_Upload(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

def VT_Upload(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('VT_Upload() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'VT_Upload' call
    results_data_1 = phantom.collect2(container=container, datapath=['Get_File_from_GDrive:action_result.summary.vault_id', 'Get_File_from_GDrive:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'VT_Upload' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'vault_id': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="detonate file", parameters=parameters, assets=['virustotal'], name="VT_Upload")

    return

def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_1() called')

    # collect data for 'ip_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.src_ip', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal'], callback=geolocate_ip_1, name="ip_reputation_1")

    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_ip_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'geolocate_ip_1' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['ip_reputation_1:artifact:*.cef.src_ip', 'ip_reputation_1:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'geolocate_ip_1' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'ip': inputs_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], name="geolocate_ip_1", parent_action=action)

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