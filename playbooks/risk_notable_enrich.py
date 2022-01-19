"""
This playbook collects the available Indicator data types within the event as well as available investigative playbooks. It will launch any playbooks that meet the filtered criteria.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_investigate_playbooks' block
    list_investigate_playbooks(container=container)

    return

def list_investigate_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_investigate_playbooks() called")

    parameters = []

    parameters.append({
        "name": None,
        "repo": "local",
        "tags": "investigate, risk_notable",
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

    phantom.custom_function(custom_function="community/playbooks_list", parameters=parameters, name="list_investigate_playbooks", callback=playbooks_decision)

    return


def decide_and_launch_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decide_and_launch_playbooks() called")

    ################################################################################
    # Matches indicators with the available playbooks designed to act upon them. It 
    # then passes the indicators to the matching inputs for the child playbooks. It 
    # launches all playbooks in synchronous mode.
    ################################################################################

    list_investigate_playbooks_data = phantom.collect2(container=container, datapath=["list_investigate_playbooks:custom_function_result.data.*.full_name","list_investigate_playbooks:custom_function_result.data.*.input_spec"])
    indicator_collect_data_all_indicators = phantom.collect2(container=container, datapath=["indicator_collect:custom_function_result.data.all_indicators.*.cef_value","indicator_collect:custom_function_result.data.all_indicators.*.data_types"])

    list_investigate_playbooks_data___full_name = [item[0] for item in list_investigate_playbooks_data]
    list_investigate_playbooks_data___input_spec = [item[1] for item in list_investigate_playbooks_data]
    indicator_collect_data_all_indicators___cef_value = [item[0] for item in indicator_collect_data_all_indicators]
    indicator_collect_data_all_indicators___data_types = [item[1] for item in indicator_collect_data_all_indicators]

    decide_and_launch_playbooks__names = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    playbook_name = list_investigate_playbooks_data___full_name
    playbook_spec = list_investigate_playbooks_data___input_spec
    indicator_cef_value_list = indicator_collect_data_all_indicators___cef_value
    indicator_cef_type_list = indicator_collect_data_all_indicators___data_types
	
    # Check if indicator cef_value_list and indicator_cef_type_list are empty
    if all(v is None for v in indicator_cef_value_list) and all(v is None for v in indicator_cef_type_list):
        raise RuntimeError("No indicator records found from indicator_collect utility")
    playbook_launch_list = {}
    decide_and_launch_playbooks__names = []
    
    for pb_name, spec_item in zip(playbook_name, playbook_spec):
        pb_inputs = {}
        for cef_value, cef_type in zip(indicator_cef_value_list, indicator_cef_type_list):
            for type_item in cef_type:
                # check if any of the investigate type playbooks have inputs that accept this data type
                for spec in spec_item:
                    for contains_type in spec['contains']:
                        if type_item == contains_type:
                            # build playbook inputs
                            if not pb_inputs:
                                pb_inputs[spec['name']] = [cef_value]
                            else:
                                if cef_value not in pb_inputs[spec['name']]:
                                    pb_inputs[spec['name']].append(cef_value)
        # only launch playbooks that have inputs
        if pb_inputs:
            playbook_launch_list[pb_name] = pb_inputs
    
    if playbook_launch_list:
        for k,v in playbook_launch_list.items():
            name = 'playbook_{}'.format(k.split('/')[1].replace(' ','_').lower())
            decide_and_launch_playbooks__names.append(name)
            phantom.debug(f"Launching playbook '{k}' with inputs '{v}'")
            phantom.playbook(playbook=k, container=container, inputs=v, name=name, callback=playbook_wait)
            
    else:
        raise RuntimeError(f"""Unable to find any match between indicator types and playbook input types.
Ensure you have an investigate type playbook to handle at least one of the following data types from the event:
'{[item[0] for item in indicator_cef_type_list if item]}'""")
        
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="decide_and_launch_playbooks:names", value=json.dumps(decide_and_launch_playbooks__names))

    playbook_wait(container=container)

    return


def playbooks_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbooks_decision() called")

    ################################################################################
    # Determines if any playbooks were found by the "list investigate playbooks" utility.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["list_investigate_playbooks:custom_function_result.data.*.full_name", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        indicator_collect(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def indicator_collect(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_collect() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "container": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_collect", parameters=parameters, name="indicator_collect", callback=decide_and_launch_playbooks)

    return


def process_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("process_notes() called")

    ################################################################################
    # Access note_title and note_content from dynamically launched playbooks.
    ################################################################################

    decide_and_launch_playbooks__names = json.loads(phantom.get_run_data(key="decide_and_launch_playbooks:names"))

    process_notes__note_title = None
    process_notes__note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    process_notes__note_title = []
    process_notes__note_content = []
    
    for name in decide_and_launch_playbooks__names:
        note_title = phantom.collect2(container=container, datapath=[f"{name}:playbook_output:note_title"])
        note_content = phantom.collect2(container=container, datapath=[f"{name}:playbook_output:note_content"])
        phantom.debug(note_title)
        phantom.debug(note_content)
        note_title = [item[0] for item in note_title]
        note_content = [item[0] for item in note_content]
        for title, content in zip(note_title, note_content):
            process_notes__note_title.append(title)
            process_notes__note_content.append(content)
	

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="process_notes:note_title", value=json.dumps(process_notes__note_title))
    phantom.save_run_data(key="process_notes:note_content", value=json.dumps(process_notes__note_content))

    return


def playbook_wait(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_wait() called")

    ################################################################################
    # Custom code block operating as a join function for dynamic playbook calls.
    ################################################################################

    decide_and_launch_playbooks__names = json.loads(phantom.get_run_data(key="decide_and_launch_playbooks:names"))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    
    if phantom.completed(playbook_names=decide_and_launch_playbooks__names):
        process_notes(container=container)
    # return early to avoid moving to next block
    return    

    ################################################################################
    ## Custom Code End
    ################################################################################

    process_notes(container=container)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")
	
    # Added custom code to overcome bug with on_finish trying to call outputs that may not exist
    process_notes__note_title = phantom.get_run_data(key="process_notes:note_title")
    process_notes__note_content = phantom.get_run_data(key="process_notes:note_content")
    if process_notes__note_title:
        process_notes__note_title = json.loads(process_notes__note_title)
    if process_notes__note_content:
        process_notes__note_content = json.loads(process_notes__note_content)
    output = {
        "note_title": process_notes__note_title,
        "note_content": process_notes__note_content,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    # Error handling in case of playbook not being able to find investigative playbooks
    list_investigate_playbooks_data = phantom.collect2(container=container, datapath=["list_investigate_playbooks:custom_function_result.data.*.full_name"])
    list_investigate_playbooks_data___full_name = [item[0] for item in list_investigate_playbooks_data if item[0]]
    if not list_investigate_playbooks_data___full_name:
        raise RuntimeError("Unable to find investigate type playbooks.")
        
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