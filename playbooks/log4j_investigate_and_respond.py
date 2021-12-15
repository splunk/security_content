"""
Published in response to CVE-2021-44228, this playbook and its sub-playbooks can be used to investigate and  respond to attacks against hosts running vulnerable Java applications which use log4j.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'enumerate_hosts' block
    enumerate_hosts(container=container)

    return

def enumerate_hosts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("enumerate_hosts() called")

    parameters = []

    parameters.append({
        "input_1": "log4j_hosts",
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

    # use custom code to read a custom list of potential log4j hosts and/or ip addresses
    # and make a json to create an artifact for each one.
    # the expected format of the custom list is:
    #     hostname1 | unix
    #     1.1.1.1   | windows
    
    # TODO remove this testing piece which deletes existing artifacts
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.id","artifact:*.id"])
    container_artifact_header_item_0 = [item[0] for item in container_artifact_data]
    for artifact_id in container_artifact_header_item_0:
        phantom.delete_artifact(artifact_id=artifact_id)
    
    
    # TODO: bring in a test splunk notable and clean up the fields in that as well

    custom_list_name = parameters[0]['input_1']
    
    success, message, rows = phantom.get_list(list_name=custom_list_name)
    
    # loop through the rows and create a list of artifact jsons to add
    # the two columns are expected to be the ip_or_hostname and the operating system family
    parameters = []
    unix_hosts = []
    windows_hosts = []
    unknown_hosts = []
    for row in rows:
        if row[0]:
            if row[1] != 'unix' and row[1] != 'windows':
                os_family = 'unknown'
            else:
                os_family = row[1]
            
            parameters.append({'input_1': {'cef_data': {'deviceHostname': row[0], 'operatingSystemFamily': os_family}}})
            

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/passthrough", parameters=parameters, name="enumerate_hosts", callback=create_artifacts)

    return


def create_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_artifacts() called")

    id_value = container.get("id", None)
    enumerate_hosts_data = phantom.collect2(container=container, datapath=["enumerate_hosts:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'create_artifacts' call
    for enumerate_hosts_data_item in enumerate_hosts_data:
        parameters.append({
            "name": "Potential log4j Host",
            "tags": None,
            "label": None,
            "severity": "high",
            "cef_field": None,
            "cef_value": None,
            "container": id_value,
            "input_json": enumerate_hosts_data_item[0],
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="create_artifacts", callback=playbook_internal_host_splunk_investigate_log4j_1)

    return


def os_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("os_filter() called")

    ################################################################################
    # The operatingSystemFamily should be either unix, windows, or unknown. If it 
    # is unknown, both sets of playbooks should be called.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            ["artifact:*.cef.operatingSystemFamily", "==", "unix"],
            ["artifact:*.cef.operatingSystemFamily", "==", "unknown"]
        ],
        name="os_filter:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        playbook_internal_host_ssh_investigate_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        playbook_internal_host_ssh_log4j_investigate_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            ["artifact:*.cef.operatingSystemFamily", "==", "windows"],
            ["artifact:*.cef.operatingSystemFamily", "==", "unknown"]
        ],
        name="os_filter:condition_2",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        playbook_internal_host_winrm_investigate_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)
        playbook_internal_host_winrm_log4j_investigate_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


def playbook_internal_host_ssh_investigate_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_internal_host_ssh_investigate_2() called")

    filtered_artifact_0_data_os_filter = phantom.collect2(container=container, datapath=["filtered-data:os_filter:condition_1:artifact:*.cef.deviceHostname"], scope="all")

    filtered_artifact_0__cef_devicehostname = [item[0] for item in filtered_artifact_0_data_os_filter]

    ip_or_hostname_combined_value = phantom.concatenate(filtered_artifact_0__cef_devicehostname, dedup=True)

    inputs = {
        "ip_or_hostname": ip_or_hostname_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/internal_host_ssh_investigate", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/internal_host_ssh_investigate", container=container, name="playbook_internal_host_ssh_investigate_2", inputs=inputs)

    return


def playbook_internal_host_ssh_log4j_investigate_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_internal_host_ssh_log4j_investigate_2() called")

    filtered_artifact_0_data_os_filter = phantom.collect2(container=container, datapath=["filtered-data:os_filter:condition_1:artifact:*.cef.deviceHostname"], scope="all")

    filtered_artifact_0__cef_devicehostname = [item[0] for item in filtered_artifact_0_data_os_filter]

    ip_or_hostname_combined_value = phantom.concatenate(filtered_artifact_0__cef_devicehostname, dedup=True)

    inputs = {
        "ip_or_hostname": ip_or_hostname_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/internal_host_ssh_log4j_investigate", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/internal_host_ssh_log4j_investigate", container=container, name="playbook_internal_host_ssh_log4j_investigate_2", inputs=inputs)

    return


def playbook_internal_host_winrm_investigate_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_internal_host_winrm_investigate_2() called")

    filtered_artifact_0_data_os_filter = phantom.collect2(container=container, datapath=["filtered-data:os_filter:condition_2:artifact:*.cef.deviceHostname"], scope="all")

    filtered_artifact_0__cef_devicehostname = [item[0] for item in filtered_artifact_0_data_os_filter]

    ip_or_hostname_combined_value = phantom.concatenate(filtered_artifact_0__cef_devicehostname, dedup=True)

    inputs = {
        "ip_or_hostname": ip_or_hostname_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/internal_host_winrm_investigate", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/internal_host_winrm_investigate", container=container, name="playbook_internal_host_winrm_investigate_2", inputs=inputs)

    return


def playbook_internal_host_winrm_log4j_investigate_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_internal_host_winrm_log4j_investigate_2() called")

    filtered_artifact_0_data_os_filter = phantom.collect2(container=container, datapath=["filtered-data:os_filter:condition_2:artifact:*.cef.deviceHostname"], scope="all")

    filtered_artifact_0__cef_devicehostname = [item[0] for item in filtered_artifact_0_data_os_filter]

    ip_or_hostname_combined_value = phantom.concatenate(filtered_artifact_0__cef_devicehostname, dedup=True)

    inputs = {
        "ip_or_hostname": ip_or_hostname_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/internal_host_winrm_log4j_investigate", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/internal_host_winrm_log4j_investigate", container=container, name="playbook_internal_host_winrm_log4j_investigate_2", inputs=inputs)

    return


def playbook_internal_host_splunk_investigate_log4j_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_internal_host_splunk_investigate_log4j_1() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.deviceHostname"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    ip_or_hostname_combined_value = phantom.concatenate(container_artifact_cef_item_0, dedup=True)

    inputs = {
        "ip_or_hostname": ip_or_hostname_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/internal_host_splunk_investigate_log4j", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/internal_host_splunk_investigate_log4j", container=container, name="playbook_internal_host_splunk_investigate_log4j_1", callback=os_filter, inputs=inputs)

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