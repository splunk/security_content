"""
Published in response to CVE-2021-44228, this playbook accepts a list of hosts and filenames to remediate on the endpoint. If filenames are provided, the endpoints will be searched and then the user can approve deletion. Then the user is prompted to quarantine the endpoint.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'filepath_decision' block
    filepath_decision(container=container)

    return

def locate_files(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("locate_files() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Run a search to locate files. Contains custom code.
    ################################################################################

    playbook_input_filepath = phantom.collect2(container=container, datapath=["playbook_input:filepath"])
    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])

    parameters = []

    # build parameters list for 'locate_files' call
    for playbook_input_filepath_item in playbook_input_filepath:
        for playbook_input_ip_or_hostname_item in playbook_input_ip_or_hostname:
            if playbook_input_ip_or_hostname_item[0] is not None:
                parameters.append({
                    "command": playbook_input_filepath_item[0],
                    "ip_hostname": playbook_input_ip_or_hostname_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []
    host_search = {}
    
    # Treat ip_or_hostname and filePath as a paired unit and iterate through them,
    # then create a dictionary for each host with a list of its filepaths
    for playbook_input_filepath_item, playbook_input_ip_or_hostname_item in zip(playbook_input_filepath, playbook_input_ip_or_hostname):
        if playbook_input_ip_or_hostname_item[0] in host_search.keys():
            host_search[playbook_input_ip_or_hostname_item[0]].append(playbook_input_filepath_item[0])
        else:
            host_search[playbook_input_ip_or_hostname_item[0]] = [playbook_input_filepath_item[0]]
    
    # Iterate through the host dictionary and generation one search string that checks all filepaths per host.
    # This ensures that we are only connecting to each host once.
    for k,v in host_search.items():
        script_str = f'''RESULT=""; for i in "{'" "'.join(v)}"; do if [ -f "$i" ]; then RESULT="${{RESULT}} true"; else RESULT="${{RESULT}} false"; fi; done; echo $RESULT'''
        parameters.append({
            "ip_hostname": k,
            "command": script_str
        })
    
    # Save the host_search dictionary into temporary data to access downstream.
    # This makes it easier to compare the results of locate files with the filepaths and hosts
    phantom.save_run_data(value=json.dumps(host_search), key="host_dictionary")
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="locate_files", assets=["ssh"], callback=file_search_decision)

    return


def file_search_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("file_search_decision() called")

    ################################################################################
    # Determine if at least one file was found
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["true", "in", "locate_files:action_result.data.*.output"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        generate_deletion_commands(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_dedup_hostnames(action=action, success=success, container=container, results=results, handle=handle)

    return


def generate_deletion_commands(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("generate_deletion_commands() called")

    ################################################################################
    # Generate a prompt along with one deletion command per host.
    ################################################################################

    locate_files_result_data = phantom.collect2(container=container, datapath=["locate_files:action_result.parameter.ip_hostname","locate_files:action_result.data.*.output"], action_results=results)

    locate_files_parameter_ip_hostname = [item[0] for item in locate_files_result_data]
    locate_files_result_item_1 = [item[1] for item in locate_files_result_data]

    generate_deletion_commands__prompt_content = None
    generate_deletion_commands__deletion_command = None
    generate_deletion_commands__host = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    generate_deletion_commands__prompt_content = ""
    generate_deletion_commands__host = []
    generate_deletion_commands__deletion_command = []
    
    # Retrieve previously saved key
    host_dictionary = json.loads(phantom.get_run_data(key="host_dictionary"))
    # Iterate through the paired host and locate files action result
    for hostname, action_result in zip(locate_files_parameter_ip_hostname, locate_files_result_item_1):

        # Ensure at least one file was found for that host
        if "true" in action_result.split(' '):
            
            # Attach this host to list of deletion hosts
            generate_deletion_commands__host.append(hostname)
            
            # Begin building deletion powershell script and prompt message
            deletion_string = f'''for i in '''
            generate_deletion_commands__prompt_content += f"### {hostname}\n\n"
            for filepath, result in zip(host_dictionary[hostname], action_result.split(' ')):
                if result == "true":
                    generate_deletion_commands__prompt_content += f"- {filepath}\n"
                    deletion_string += f'"{filepath}" '
                    
            # Remove trailing comma and attach one deletion command
            deletion_string = deletion_string.rstrip(',')
            deletion_string += '; do rm -v $i; done;'
            generate_deletion_commands__deletion_command.append(deletion_string)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="generate_deletion_commands:prompt_content", value=json.dumps(generate_deletion_commands__prompt_content))
    phantom.save_run_data(key="generate_deletion_commands:deletion_command", value=json.dumps(generate_deletion_commands__deletion_command))
    phantom.save_run_data(key="generate_deletion_commands:host", value=json.dumps(generate_deletion_commands__host))

    deletion_confirmation(container=container)

    return


def deletion_confirmation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("deletion_confirmation() called")

    ################################################################################
    # Prompt the user to confirm deletion
    ################################################################################

    # set user and message variables for phantom.prompt call

    user = "Incident Commander"
    message = """SOAR found results for the following files. Please review the returned list and confirm if they should be deleted.\n\n&nbsp;\n{0}"""

    # parameter list for template variable replacement
    parameters = [
        "generate_deletion_commands:custom_function:prompt_content"
    ]

    # responses
    response_types = [
        {
            "prompt": "Type 'confirm' to delete",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="deletion_confirmation", parameters=parameters, response_types=response_types, callback=deletion_decision)

    return


def deletion_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("deletion_decision() called")

    ################################################################################
    # Determine if user wants to delete files
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["deletion_confirmation:action_result.summary.responses.0", "==", "confirm"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        delete_files(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_dedup_hostnames(action=action, success=success, container=container, results=results, handle=handle)

    return


def delete_files(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("delete_files() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Iterate through host and deletion command. Contains custom code.
    ################################################################################

    generate_deletion_commands__deletion_command = json.loads(phantom.get_run_data(key="generate_deletion_commands:deletion_command"))
    generate_deletion_commands__host = json.loads(phantom.get_run_data(key="generate_deletion_commands:host"))

    parameters = []

    if generate_deletion_commands__host is not None:
        parameters.append({
            "command": generate_deletion_commands__deletion_command,
            "ip_hostname": generate_deletion_commands__host,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []
    for del_cmd, host in zip(generate_deletion_commands__deletion_command, generate_deletion_commands__host):
        parameters.append({
            "command": del_cmd,
            "ip_hostname": host,
        })
        
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="delete_files", assets=["ssh"], callback=join_dedup_hostnames)

    return


def filepath_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filepath_decision() called")

    ################################################################################
    # Determine if filepath is present in playbook inputs
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_input:filepath", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        locate_files(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_dedup_hostnames(action=action, success=success, container=container, results=results, handle=handle)

    return


def format_host_list_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_host_list_prompt() called")

    ################################################################################
    # Format a list of the hosts. This will feed both env var prompt and shut down 
    # prompts.
    ################################################################################

    template = """%%\n- {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "dedup_hostnames:custom_function_result.data.*.item"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_host_list_prompt")

    quarantine_prompt(container=container)

    return


def quarantine_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("quarantine_prompt() called")

    ################################################################################
    # Offer the user options to quarantine the affected endpoints
    ################################################################################

    # set user and message variables for phantom.prompt call

    user = "Incident Commander"
    message = """Choose an action you would like to take on the following hosts and then type confirm. The same selected action will be performed on every host.\n\n&nbsp;\n### Available Actions:\n- Restrict Outbound Traffic\n(Sets a firewall policy to prevent all outbound traffic. This may disrupt domain authentication for all but cached credentials.)\n- Shutdown Host (This is a forced shutdown)\n\n&nbsp;\n### Target Hosts\n{0}"""

    # parameter list for template variable replacement
    parameters = [
        "format_host_list_prompt:formatted_data"
    ]

    # responses
    response_types = [
        {
            "prompt": "Available Actions",
            "options": {
                "type": "list",
                "choices": [
                    "Restrict Outbound Traffic",
                    "Shutdown",
                    "Restrict Outbound Traffic and Shutdown",
                    "Do Nothing"
                ],
            },
        },
        {
            "prompt": "Type \"confirm\"",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="quarantine_prompt", parameters=parameters, response_types=response_types, callback=quarantine_decision)

    return


def quarantine_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("quarantine_decision() called")

    ################################################################################
    # Determine which action the user selected
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["quarantine_prompt:action_result.summary.responses.0", "==", "Restrict Outbound Traffic"],
            ["quarantine_prompt:action_result.summary.responses.1", "==", "confirm"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        block_outbound_traffic(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["quarantine_prompt:action_result.summary.responses.0", "==", "Shutdown"],
            ["quarantine_prompt:action_result.summary.responses.1", "==", "confirm"]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        shutdown(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3
    found_match_3 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["quarantine_prompt:action_result.summary.responses.0", "==", "Restrict Outbound Traffic and Shutdown"],
            ["quarantine_prompt:action_result.summary.responses.1", "==", "confirm"]
        ])

    # call connected blocks if condition 3 matched
    if found_match_3:
        block_and_shutdown(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 4
    join_format_custom_note(action=action, success=success, container=container, results=results, handle=handle)

    return


def block_outbound_traffic(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("block_outbound_traffic() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Add firewall rule blocking outbound traffic
    ################################################################################

    dedup_hostnames_data = phantom.collect2(container=container, datapath=["dedup_hostnames:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'block_outbound_traffic' call
    for dedup_hostnames_data_item in dedup_hostnames_data:
        if dedup_hostnames_data_item[0] is not None:
            parameters.append({
                "command": "sudo -S iptables -I OUTPUT -p all 0.0.0.0/0 -j DROP SPLUNK_SOAR_BLOCK",
                "ip_hostname": dedup_hostnames_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="block_outbound_traffic", assets=["ssh"], callback=join_format_custom_note)

    return


def shutdown(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("shutdown() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Shutdown machine
    ################################################################################

    dedup_hostnames_data = phantom.collect2(container=container, datapath=["dedup_hostnames:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'shutdown' call
    for dedup_hostnames_data_item in dedup_hostnames_data:
        if dedup_hostnames_data_item[0] is not None:
            parameters.append({
                "command": "shutdown now",
                "ip_hostname": dedup_hostnames_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="shutdown", assets=["ssh"], callback=join_format_custom_note)

    return


def block_and_shutdown(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("block_and_shutdown() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Add firewall rule and then shutdown machine
    ################################################################################

    dedup_hostnames_data = phantom.collect2(container=container, datapath=["dedup_hostnames:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'block_and_shutdown' call
    for dedup_hostnames_data_item in dedup_hostnames_data:
        if dedup_hostnames_data_item[0] is not None:
            parameters.append({
                "command": "sudo -S iptables -I OUTPUT -p all 0.0.0.0/0 -j DROP SPLUNK_SOAR_BLOCK && shutdown now",
                "ip_hostname": dedup_hostnames_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="block_and_shutdown", assets=["ssh"], callback=join_format_custom_note)

    return


def summary_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("summary_note() called")

    ################################################################################
    # Leave a summary note
    ################################################################################

    format_custom_note__output = json.loads(phantom.get_run_data(key="format_custom_note:output"))

    ################################################################################
    ## Custom Code Start
    ################################################################################


    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_custom_note__output, note_format="markdown", note_type="general", title="SSH Log4j Response")

    return


def join_dedup_hostnames(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_dedup_hostnames() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_dedup_hostnames_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_dedup_hostnames_called", value="dedup_hostnames")

    # call connected block "dedup_hostnames"
    dedup_hostnames(container=container, handle=handle)

    return


def dedup_hostnames(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dedup_hostnames() called")

    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])

    playbook_input_ip_or_hostname_values = [item[0] for item in playbook_input_ip_or_hostname]

    parameters = []

    parameters.append({
        "input_list": playbook_input_ip_or_hostname_values,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_deduplicate", parameters=parameters, name="dedup_hostnames", callback=format_host_list_prompt)

    return


def join_format_custom_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_format_custom_note() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_format_custom_note_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_format_custom_note_called", value="format_custom_note")

    # call connected block "format_custom_note"
    format_custom_note(container=container, handle=handle)

    return


def format_custom_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_custom_note() called")

    ################################################################################
    # Format a dynamic summary note from playbook.get_summary()
    ################################################################################

    format_custom_note__output = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    format_custom_note__output = ""
    playbook_summary = phantom.get_summary()
    if 'result' in playbook_summary.keys() and playbook_summary['result']:
        for result_item in playbook_summary['result']:
            format_custom_note__output += f"#### Action - {result_item['name']}: {result_item['message']}\n"
            # Generate app run summary for each action
            if 'app_runs' in result_item.keys() and result_item['app_runs']:
                for app_run_item in result_item['app_runs']:
                    format_custom_note__output += f"- app_run_id: {app_run_item['app_run_id']}\n"
                    for k,v in app_run_item['parameter'].items():
                        if k != 'context':
                            format_custom_note__output += f"  - {k}: {v}\n"
                    format_custom_note__output += f"- summary: {app_run_item['summary']}\n"
            format_custom_note__output += "\n"

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="format_custom_note:output", value=json.dumps(format_custom_note__output))

    summary_note(container=container)

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