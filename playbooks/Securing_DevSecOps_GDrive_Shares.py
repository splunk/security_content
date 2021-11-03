"""
This playbook was built to be used in coordination with the &quot;ESCU - Gsuite Drive Share In External Email - Rule&quot; detection, distributed as part of the Splunk Enterprise Security Content Update app.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'greynoise_lookup' block
    greynoise_lookup(container=container)
    # call 'get_file_from_gdrive' block
    get_file_from_gdrive(container=container)

    return

def greynoise_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("greynoise_lookup() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.src_ip","artifact:*.id"])

    parameters = []

    # build parameters list for 'greynoise_lookup' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("lookup ip", parameters=parameters, name="greynoise_lookup", assets=["greynoise"])

    return


def get_file_from_gdrive(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_file_from_gdrive() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.doc_id","artifact:*.id"])

    parameters = []

    # build parameters list for 'get_file_from_gdrive' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "id": container_artifact_item[0],
                "download_file": True,
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get file", parameters=parameters, name="get_file_from_gdrive", assets=["google-gdrive"], callback=get_file_from_gdrive_callback)

    return


def get_file_from_gdrive_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_file_from_gdrive_callback() called")

    
    vt_lookup(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    format_search(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def vt_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("vt_lookup() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_file_from_gdrive_result_data = phantom.collect2(container=container, datapath=["get_file_from_gdrive:action_result.summary.vault_id","get_file_from_gdrive:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'vt_lookup' call
    for get_file_from_gdrive_result_item in get_file_from_gdrive_result_data:
        if get_file_from_gdrive_result_item[0] is not None:
            parameters.append({
                "hash": get_file_from_gdrive_result_item[0],
                "context": {'artifact_id': get_file_from_gdrive_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("file reputation", parameters=parameters, name="vt_lookup", assets=["virustotal"], callback=decision_1)

    return


def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["vt_lookup:action_result.status", "==", "failed"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        prompt_for_upload(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def prompt_for_upload(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_for_upload() called")

    # set user and message variables for phantom.prompt call

    user = "Administrator"
    message = """File was not found on VirusTotal"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Should this file be uploaded to VirusTotal?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_for_upload", parameters=parameters, response_types=response_types, callback=decision_2)

    return


def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_for_upload:action_result.summary.responses.0", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        detonate_file_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def detonate_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("detonate_file_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_file_from_gdrive_result_data = phantom.collect2(container=container, datapath=["get_file_from_gdrive:action_result.summary.vault_id","get_file_from_gdrive:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'detonate_file_1' call
    for get_file_from_gdrive_result_item in get_file_from_gdrive_result_data:
        if get_file_from_gdrive_result_item[0] is not None:
            parameters.append({
                "vault_id": get_file_from_gdrive_result_item[0],
                "context": {'artifact_id': get_file_from_gdrive_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate file", parameters=parameters, name="detonate_file_1", assets=["virustotal"])

    return


def format_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_search() called")

    template = """| search `gsuite_drive` parameters.doc_id=\"{0}\" | rename parameters.owner as user | stats count by user"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.doc_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_search")

    run_query_1(container=container)

    return


def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_query_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_search = phantom.get_format_data(name="format_search")

    parameters = []

    if format_search is not None:
        parameters.append({
            "query": format_search,
            "command": "search",
            "display": "user",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["splunk"], callback=format_output)

    return


def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_1() called")

    format_output__as_list = phantom.get_format_data(name="format_output__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_output__as_list, note_format="markdown", note_type="general", title="List of users with same email")

    return


def format_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_output() called")

    template = """The following Users received this email:\n%%\n{0}\n%%\n\nThese emails and users should also be investigated."""

    # parameter list for template variable replacement
    parameters = [
        "run_query_1:action_result.data.*.user"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_output")

    add_note_1(container=container)

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