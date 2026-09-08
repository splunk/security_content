"""
This playbook attempts to find assets and users from the notable event and match those with assets and identities from Splunk Enterprise Security. If a match was found and the user has playbooks available to contain entities, the analyst decides which entities to disable or quarantine.\t
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_asset_playbooks' block
    list_asset_playbooks(container=container)

    return

def collect_type_user(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("collect_type_user() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "tags": None,
        "scope": "all",
        "container": id_value,
        "data_types": "user,username,user name,user_name,username",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/collect_by_cef_type", parameters=parameters, name="collect_type_user", callback=user_decision)

    return


def join_collect_type_host(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_collect_type_host() called")

    if phantom.completed(custom_function_names=["collect_type_user"], action_names=["run_identity_query"]):
        # call connected block "collect_type_host"
        collect_type_host(container=container, handle=handle)

    return


def collect_type_host(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("collect_type_host() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "tags": None,
        "scope": "all",
        "container": id_value,
        "data_types": "host name,host,hostname,host_name",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/collect_by_cef_type", parameters=parameters, name="collect_type_host", callback=host_decision_1)

    return


def list_asset_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_asset_playbooks() called")

    parameters = []

    parameters.append({
        "name": None,
        "repo": "local",
        "tags": "asset, containment, risk_notable",
        "category": None,
        "playbook_type": "input",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/playbooks_list", parameters=parameters, name="list_asset_playbooks", callback=list_identity_playbooks)

    return


def decide_and_launch_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decide_and_launch_playbooks() called")

    ################################################################################
    # Route information to input playbooks based on playbook input spec.
    ################################################################################

    protect_prompt_result_data = phantom.collect2(container=container, datapath=["protect_prompt:action_result.summary.responses"], action_results=results)
    list_asset_playbooks_data = phantom.collect2(container=container, datapath=["list_asset_playbooks:custom_function_result.data.*.full_name","list_asset_playbooks:custom_function_result.data.*.tags","list_asset_playbooks:custom_function_result.data.*.input_spec"])
    list_identity_playbooks_data = phantom.collect2(container=container, datapath=["list_identity_playbooks:custom_function_result.data.*.full_name","list_identity_playbooks:custom_function_result.data.*.tags","list_identity_playbooks:custom_function_result.data.*.input_spec"])

    protect_prompt_summary_responses = [item[0] for item in protect_prompt_result_data]
    list_asset_playbooks_data___full_name = [item[0] for item in list_asset_playbooks_data]
    list_asset_playbooks_data___tags = [item[1] for item in list_asset_playbooks_data]
    list_asset_playbooks_data___input_spec = [item[2] for item in list_asset_playbooks_data]
    list_identity_playbooks_data___full_name = [item[0] for item in list_identity_playbooks_data]
    list_identity_playbooks_data___tags = [item[1] for item in list_identity_playbooks_data]
    list_identity_playbooks_data___input_spec = [item[2] for item in list_identity_playbooks_data]

    decide_and_launch_playbooks__playbook_names = None
    decide_and_launch_playbooks__playbook_inputs = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    responses = protect_prompt_summary_responses[0]
    all_entity_list = json.loads(phantom.get_run_data(key="all_entities"))
    decide_and_launch_playbooks__output = {'user_playbooks': [], 'user_values': [], 'host_playbooks': [], 'host_values': []}
    user_list = []
    device_list = []

    decide_and_launch_playbooks__playbook_names = []
    decide_and_launch_playbooks__playbook_inputs = []
    
    playbook_launch_list = {}
    for entity,response in zip(all_entity_list,responses):
        if response.lower() == 'yes':
            if entity['type'] == 'device':
                device_list.append(entity['name'])
            if entity['type'] == 'user':
                user_list.append(entity['name'])
    
    # Iterate through identity playbooks
    if list_identity_playbooks_data___full_name:
        for pb_name, pb_spec in zip(list_identity_playbooks_data___full_name, list_identity_playbooks_data___input_spec):
            pb_inputs = {}
            for user in user_list:
                for spec in pb_spec:
                    if any('user' in list_item for list_item in spec['contains']):
                        phantom.debug(f"Match found for user '{user}' in playbook '{pb_name}' at input '{spec['name']}'")
                        if not pb_inputs:
                            pb_inputs[spec['name']] = [user]
                        else:
                            if user not in pb_inputs[spec['name']]:
                                pb_inputs[spec['name']].append(user)

            if pb_inputs:
                playbook_launch_list[pb_name] = pb_inputs
	
    # Iterate through asset playbooks
    if list_asset_playbooks_data___full_name:
        for pb_name, pb_spec in zip(list_asset_playbooks_data___full_name, list_asset_playbooks_data___input_spec):
            pb_inputs = {}
            for host in device_list:
                for spec in pb_spec:
                    if any('host' in list_item for list_item in spec['contains']):
                        phantom.debug(f"Match found for host '{host}' in playbook '{pb_name}' at input '{spec['name']}'")
                        if not pb_inputs:
                            pb_inputs[spec['name']] = [host]
                        else:
                            if host not in pb_inputs[spec['name']]:
                                pb_inputs[spec['name']].append(host)

            if pb_inputs:
                if pb_name in playbook_launch_list.keys():
                    playbook_launch_list[pb_name].update(pb_inputs)
                else:
                    playbook_launch_list[pb_name] = pb_inputs
    
    if playbook_launch_list:
        for k,v in playbook_launch_list.items():
            decide_and_launch_playbooks__playbook_names.append(k)
            decide_and_launch_playbooks__playbook_inputs.append(v)
            phantom.playbook(playbook=k, container=container, inputs=v)
    # Raise error if there were no matches found in the two playbook categories
    else:
        raise RuntimeError("Unable to find match between indicator types and playbook input types")
        
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="decide_and_launch_playbooks:playbook_names", value=json.dumps(decide_and_launch_playbooks__playbook_names))
    phantom.save_run_data(key="decide_and_launch_playbooks:playbook_inputs", value=json.dumps(decide_and_launch_playbooks__playbook_inputs))

    format_final_note(container=container)

    return


def format_asset_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_asset_query() called")

    ################################################################################
    # Format a Splunk query with host data from the container.
    ################################################################################

    template = """asset_lookup_by_str | search asset IN (\n%%\n\"{0}\"\n%%\n)\n| eval category=mvjoin(category, \"; \")"""

    # parameter list for template variable replacement
    parameters = [
        "collect_type_host:custom_function_result.data.*.artifact_value"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_asset_query", drop_none=True)

    run_asset_query(container=container)

    return


def format_identity_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_identity_query() called")

    ################################################################################
    # Format a Splunk query with user data from the container.
    ################################################################################

    template = """identity_lookup_expanded | search identity IN (\n%%\n\"{0}\"\n%%\n)\n| eval category=mvjoin(category, \"; \")"""

    # parameter list for template variable replacement
    parameters = [
        "collect_type_user:custom_function_result.data.*.artifact_value"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_identity_query", drop_none=True)

    run_identity_query(container=container)

    return


def user_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("user_decision() called")

    ################################################################################
    # Determine if a user data type is present in the container.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["collect_type_user:custom_function_result.data.*.artifact_value", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_identity_query(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_collect_type_host(action=action, success=success, container=container, results=results, handle=handle)

    return


def run_identity_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_identity_query() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Search for any matches to users in the identity table in Splunk.
    ################################################################################

    format_identity_query = phantom.get_format_data(name="format_identity_query")

    parameters = []

    if format_identity_query is not None:
        parameters.append({
            "query": format_identity_query,
            "command": "| inputlookup",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_identity_query", assets=["splunk"], callback=join_collect_type_host)

    return


def host_decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("host_decision_1() called")

    ################################################################################
    # Determine if a host/hostname datatype was found in the event.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["collect_type_host:custom_function_result.data.*.artifact_value", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_asset_query(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_results_decision(action=action, success=success, container=container, results=results, handle=handle)

    return


def run_asset_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_asset_query() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Search for any matches to hosts in the asset table in Splunk.
    ################################################################################

    format_asset_query = phantom.get_format_data(name="format_asset_query")

    parameters = []

    if format_asset_query is not None:
        parameters.append({
            "query": format_asset_query,
            "command": "| inputlookup",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_asset_query", assets=["splunk"], callback=join_results_decision)

    return


def join_results_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_results_decision() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_results_decision_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_results_decision_called", value="results_decision")

    # call connected block "results_decision"
    results_decision(container=container, handle=handle)

    return


def results_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("results_decision() called")

    ################################################################################
    # Determine if any results were found by the preceding queries.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["run_asset_query:action_result.summary.total_events", ">", 0],
            ["run_identity_query:action_result.summary.total_events", ">", 0]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_prompt(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_error_note(action=action, success=success, container=container, results=results, handle=handle)

    return


def protect_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("protect_prompt() called")

    # set user and message variables for phantom.prompt call

    user_id = phantom.get_effective_user()
    url = phantom.build_phantom_rest_url('ph_user', user_id)
    response = phantom.requests.get(url, verify=False).json()
    user = response['username']
    message = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "format_prompt:formatted_data"
    ]
    
    device_data = phantom.collect2(container=container, datapath=['run_asset_query:action_result.data.*.nt_host'], action_results=results )
    device_list = [item[0] for item in device_data]
    user_data = phantom.collect2(container=container, datapath=['run_identity_query:action_result.data.*.email'], action_results=results )
    user_list = [item[0] for item in user_data]
    
    list_asset_playbooks_data = phantom.collect2(container=container, datapath=["list_asset_playbooks:custom_function_result.data.*.full_name"])
    list_asset_playbooks_list = [item[0] for item in list_asset_playbooks_data if item[0]]
    list_identity_playbooks_data = phantom.collect2(container=container, datapath=["list_identity_playbooks:custom_function_result.data.*.full_name"])
    list_identity_playbooks_list = [item[0] for item in list_identity_playbooks_data if item[0]]
    
	#responses:
    all_entity_list = []
    response_types = []
    # only add a response if a device exists and a playbook exists
    if device_list and list_asset_playbooks_list: 
        for item in device_list:
            if item:
                response_types.append({
                        "prompt": "Launch protect asset playbooks on '{}'?".format(item),
                        "options": {
                            "type": "list",
                            "choices": [
                                "Yes",
                                "No"
                            ]
                        },
                    })
                all_entity_list.append({'type': 'device', 'name': item})
    
    # only add a response if a user exists and a playbook exists
    if user_list and list_identity_playbooks_list: 
        for item in user_list:
            if item:
                response_types.append({
                        "prompt": "Launch protect identity playbooks on '{}'?".format(item),
                        "options": {
                            "type": "list",
                            "choices": [
                                "Yes",
                                "No"
                            ]
                        },
                    })
                all_entity_list.append({'type': 'user', 'name': item})
                
    phantom.save_run_data(key='all_entities', value=json.dumps(all_entity_list))    
    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="protect_prompt", parameters=parameters, response_types=response_types, callback=decide_and_launch_playbooks)

    return

def format_error_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_error_note() called")

    ################################################################################
    # Format a note letting the user know that no assets or identities were found.
    ################################################################################

    template = """Splunk SOAR was unable to locate any matches in the Enterprise Security Asset & Identity Table for the below entities in this incident.\n\nUsers:\n%%\n- {0}\n%%\n\nAssets:\n%%\n- {1}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "collect_type_user:custom_function_result.data.*.artifact_value",
        "collect_type_host:custom_function_result.data.*.artifact_value"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_error_note")

    join_merge_notes(container=container)

    return


def format_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_prompt() called")

    ################################################################################
    # Format a table of the asset and identity information.
    ################################################################################

    template = """Below is a list of users and devices that were detected related to this event. \n\n\n**Only users and devices that are present in the ES Asset Inventory are shown.**\n\n#### Asset\n| nt_host | category | bunit | owner | city | country | pci_domain | priority |\n| --- | --- | --- | --- | --- | --- | --- | --- | \n%%\n| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} |  \n%%\n\n#### Identity\n| email | first | last | category | bunit | priority |\n| --- | --- | --- | --- | --- | --- |\n%%\n| {8} | {9} | {10} | {11} | {12} | {13} |\n%%\n---\n\n\n### Please select an action for the entities below. **Only entities with an applicable playbook are shown.** """

    # parameter list for template variable replacement
    parameters = [
        "run_asset_query:action_result.data.*.nt_host",
        "run_asset_query:action_result.data.*.category",
        "run_asset_query:action_result.data.*.bunit",
        "run_asset_query:action_result.data.*.owner",
        "run_asset_query:action_result.data.*.city",
        "run_asset_query:action_result.data.*.country",
        "run_asset_query:action_result.data.*.pci_domain",
        "run_asset_query:action_result.data.*.priority",
        "run_identity_query:action_result.data.*.email",
        "run_identity_query:action_result.data.*.first",
        "run_identity_query:action_result.data.*.last",
        "run_identity_query:action_result.data.*.category",
        "run_identity_query:action_result.data.*.bunit",
        "run_identity_query:action_result.data.*.priority"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_prompt")

    protect_prompt(container=container)

    return


def format_final_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_final_note() called")

    ################################################################################
    # Format a final note with everything done up to this point.
    ################################################################################

    template = """Summary of playbook launch activity below. Ensure the users or devices were contained by checking action results.\n\n| Playbooks | Inputs |\n| --- | --- |\n%%\n| `{0}` | `{1}` |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "decide_and_launch_playbooks:custom_function:playbook_names",
        "decide_and_launch_playbooks:custom_function:playbook_inputs"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_final_note", drop_none=True)

    join_merge_notes(container=container)

    return


def join_merge_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_merge_notes() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_merge_notes_called"):
        return

    if phantom.completed(action_names=["protect_prompt"]):
        # save the state that the joined function has now been called
        phantom.save_run_data(key="join_merge_notes_called", value="merge_notes")

        # call connected block "merge_notes"
        merge_notes(container=container, handle=handle)

    return


def merge_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_notes() called")

    ################################################################################
    # Merge available notes based on which format block was triggered.
    ################################################################################

    template = """{0}{1}"""

    # parameter list for template variable replacement
    parameters = [
        "format_error_note:formatted_data",
        "format_final_note:formatted_data"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="merge_notes", drop_none=True)

    return


def playbook_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_decision() called")

    ################################################################################
    # Determine if any protect playbooks exist.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["list_asset_playbooks:custom_function_result.data.*.full_name", "!=", ""],
            ["list_identity_playbooks:custom_function_result.data.*.full_name", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        collect_type_user(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def list_identity_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_identity_playbooks() called")

    parameters = []

    parameters.append({
        "name": None,
        "repo": "local",
        "tags": "identity, containment, risk_notable",
        "category": None,
        "playbook_type": "input",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/playbooks_list", parameters=parameters, name="list_identity_playbooks", callback=playbook_decision)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    merge_notes = phantom.get_format_data(name="merge_notes")

    output = {
        "note_title": "[Auto-Generated] Protect Assets and Users Summary",
        "note_content": merge_notes,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################
    list_asset_playbooks_data = phantom.collect2(container=container, datapath=["list_asset_playbooks:custom_function_result.data.*.full_name"])
    list_identity_playbooks_data = phantom.collect2(container=container, datapath=["list_identity_playbooks:custom_function_result.data.*.full_name"])
    list_asset_playbooks_list = [item[0] for item in list_asset_playbooks_data if item[0]]
    list_identity_playbooks_list = [item[0] for item in list_identity_playbooks_data if item[0]]
    
    if not list_asset_playbooks_list and not list_identity_playbooks_list:
        raise RuntimeError("No playbooks found for provided 'playbooks_list' criteria")
    
    
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