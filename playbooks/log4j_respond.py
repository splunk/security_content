"""
Published in response to CVE-2021-44228, this playbook is meant to be launched by log4j_investigate. In this playbook, the risk from an exploited host can be mitigated by optionally deleting malicious files from the hosts, blocking outbound network connections from the hosts, and/or shutting down the hosts.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'enumerate_files_to_delete' block
    enumerate_files_to_delete(container=container)

    return

def enumerate_files_to_delete(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("enumerate_files_to_delete() called")

    parameters = []

    parameters.append({
        "input_1": "log4j_hosts_and_files",
        "input_2": None,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # use custom code to read a custom list of potential log4j files to delete
    # and make a json to create an artifact for each one.
    # the expected format of the custom list is:
    #     hostname1 | unix | /full/path/to/delete/on/hostname_1
    #     1.1.1.1   | windows | C:\\Full\Path\To\Delete\On\1_1_1_1
    #
    # the list can either have all rows with files or no rows with files. some rows with files and some without will not work

    custom_list_name = parameters[0]['input_1']
    
    success, message, rows = phantom.get_list(list_name=custom_list_name)
    
    # return early if the list is not found
    if not success:
        phantom.debug("Failed to find the custom list, so only existing artifacts will be used")
        phantom.custom_function(custom_function="community/passthrough", parameters=[], name="enumerate_files_to_delete", callback=create_file_artifacts)
        return
    
    # loop through the rows and create a list of artifact jsons to add
    # the three columns are expected to be the ip_or_hostname, the operating system family, and the full path to the file to delete
    parameters = []
    unix_hosts = []
    windows_hosts = []
    unknown_hosts = []
    has_files = False
    if rows[0][2] and ('/' in rows[0][2] or '\\' in rows[0][2]):
        has_files = True
    for row in rows:
        # hostname and operating system are required, but file path is optional. files will not be deleted if file path is missing
        if row[0] and row[1]:
            # only windows and unix are supported, and operating system family is required
            if row[1] == 'unix' or row[1] == 'windows':
                artifact_dict = {
                    'cef_data': {
                        'deviceHostname': row[0],
                        'operatingSystemFamily': row[1],
                        'filePath': row[2]},
                    'field_mapping': {
                        'deviceHostname': ['host name', 'ip'],
                        'filePath': ['file path']}}
                # full paths should have at least one slash somewhere in them
                if row[2] and ('/' in row[2] or '\\' in row[2]):
                    if has_files:
                        artifact_dict['cef_data']['filePath'] = row[2]
                        artifact_dict['field_mapping']['filePath'] = ['file path']
                    else:
                        phantom.debug("skipping host {} with file {} because other rows did not have files".format(row[0], row[2]))
                else:
                    if has_files:
                        phantom.error("host {} is missing a file; playbook will be discontinued".format(row[0]))
                        phantom.discontinue()
                parameters.append({'input_1': artifact_dict})

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/passthrough", parameters=parameters, name="enumerate_files_to_delete", callback=create_file_artifacts)

    return


def create_file_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_file_artifacts() called")

    id_value = container.get("id", None)
    enumerate_files_to_delete_data = phantom.collect2(container=container, datapath=["enumerate_files_to_delete:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'create_file_artifacts' call
    for enumerate_files_to_delete_data_item in enumerate_files_to_delete_data:
        parameters.append({
            "name": "potential log4j file",
            "tags": None,
            "label": None,
            "severity": "high",
            "cef_field": None,
            "cef_value": None,
            "container": id_value,
            "input_json": enumerate_files_to_delete_data_item[0],
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="create_file_artifacts", callback=if_hosts_exist)

    return


def if_hosts_exist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("if_hosts_exist() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["artifact:*.cef.deviceHostname", "!=", ""],
            ["artifact:*.cef.operatingSystemFamily", "==", "unix"],
            ["artifact:*.name", "==", "potential log4j file"]
        ],
        name="if_hosts_exist:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        playbook_internal_host_ssh_log4j_respond_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["artifact:*.cef.deviceHostname", "!=", ""],
            ["artifact:*.cef.operatingSystemFamily", "==", "windows"],
            ["artifact:*.name", "==", "potential log4j file"]
        ],
        name="if_hosts_exist:condition_2",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        playbook_internal_host_winrm_log4j_respond_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


def playbook_internal_host_ssh_log4j_respond_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_internal_host_ssh_log4j_respond_2() called")

    filtered_artifact_0_data_if_hosts_exist = phantom.collect2(container=container, datapath=["filtered-data:if_hosts_exist:condition_1:artifact:*.cef.deviceHostname","filtered-data:if_hosts_exist:condition_1:artifact:*.cef.filePath"], scope="all")

    filtered_artifact_0__cef_devicehostname = [item[0] for item in filtered_artifact_0_data_if_hosts_exist]
    filtered_artifact_0__cef_filepath = [item[1] for item in filtered_artifact_0_data_if_hosts_exist]

    inputs = {
        "ip_or_hostname": filtered_artifact_0__cef_devicehostname,
        "filepath": filtered_artifact_0__cef_filepath,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/internal_host_ssh_log4j_respond", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/internal_host_ssh_log4j_respond", container=container, inputs=inputs)

    return


def playbook_internal_host_winrm_log4j_respond_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_internal_host_winrm_log4j_respond_2() called")

    filtered_artifact_0_data_if_hosts_exist = phantom.collect2(container=container, datapath=["filtered-data:if_hosts_exist:condition_2:artifact:*.cef.deviceHostname","filtered-data:if_hosts_exist:condition_2:artifact:*.cef.filePath"])

    filtered_artifact_0__cef_devicehostname = [item[0] for item in filtered_artifact_0_data_if_hosts_exist]
    filtered_artifact_0__cef_filepath = [item[1] for item in filtered_artifact_0_data_if_hosts_exist]

    inputs = {
        "ip_or_hostname": filtered_artifact_0__cef_devicehostname,
        "filepath": filtered_artifact_0__cef_filepath,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/internal_host_winrm_log4j_respond", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/internal_host_winrm_log4j_respond", container=container, inputs=inputs)

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