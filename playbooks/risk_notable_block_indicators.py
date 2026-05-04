"""
This playbook handles locating indicators marked for blocking and determining if any blocking playbooks exist. If there is a match to the appropriate tags in the playbook, a filter block routes the name of the playbook to launch to a code block.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################

################################################################################
## Global Custom Code End
################################################################################

def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_marked_indicators' block
    get_marked_indicators(container=container)

    return

def get_marked_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_marked_indicators() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "tags_or": "marked_for_block",
        "tags_and": None,
        "container": id_value,
        "tags_exclude": "blocked, safe",
        "indicator_timerange": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_get_by_tag", parameters=parameters, name="get_marked_indicators", callback=list_block_playbooks)

    return


def list_block_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_block_playbooks() called")

    parameters = []

    parameters.append({
        "name": None,
        "repo": "local",
        "tags": "block, risk_notable",
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

    phantom.custom_function(custom_function="community/playbooks_list", parameters=parameters, name="list_block_playbooks", callback=indicator_and_playbook_decision)

    return


def decide_and_launch_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decide_and_launch_playbooks() called")

    ################################################################################
    # This block matches indicators with the available playbooks designed to act upon 
    # them. It then dedupes the playbook list, so each child playbook is only launched 
    # once. After that, it is up to the child playbook to fetch the indicators it 
    # knows how to block.
    ################################################################################

    get_marked_indicators_data = phantom.collect2(container=container, datapath=["get_marked_indicators:custom_function_result.data.*.indicator_value","get_marked_indicators:custom_function_result.data.*.indicator_cef_type"])
    list_block_playbooks_data = phantom.collect2(container=container, datapath=["list_block_playbooks:custom_function_result.data.*.full_name","list_block_playbooks:custom_function_result.data.*.input_spec"])

    get_marked_indicators_data___indicator_value = [item[0] for item in get_marked_indicators_data]
    get_marked_indicators_data___indicator_cef_type = [item[1] for item in get_marked_indicators_data]
    list_block_playbooks_data___full_name = [item[0] for item in list_block_playbooks_data]
    list_block_playbooks_data___input_spec = [item[1] for item in list_block_playbooks_data]

    decide_and_launch_playbooks__names = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    indicator_value_list = get_marked_indicators_data___indicator_value
    indicator_cef_type_list = get_marked_indicators_data___indicator_cef_type

    playbook_name = list_block_playbooks_data___full_name
    playbook_spec = list_block_playbooks_data___input_spec
	
    decide_and_launch_playbooks__names = []
    playbook_launch_list = {}
    
    for pb_name, spec_item in zip(playbook_name, playbook_spec):
        pb_inputs = {}
        for cef_value, cef_type in zip(indicator_value_list, indicator_cef_type_list):
            for type_item in cef_type:
                # check if any of the investigate type playbooks have inputs that accept this data type
                for spec in spec_item:
                    for contains_type in spec['contains']:
                        if type_item and type_item in contains_type:
                            phantom.debug(f"Match found for '{cef_value}' of type '{type_item}' for playbook '{pb_name}' at input '{spec['name']}'")
                            if not pb_inputs:
                                pb_inputs[spec['name']] = [cef_value]
                            else:
                                if cef_value not in pb_inputs[spec['name']]:
                                    pb_inputs[spec['name']].append(cef_value)

        if pb_inputs:
            playbook_launch_list[pb_name] = pb_inputs
    
    if playbook_launch_list:
        for k,v in playbook_launch_list.items():
            name = 'playbook_{}'.format(pb_name.split('/')[1].replace(' ','_').lower())
            decide_and_launch_playbooks__names.append(name)
            phantom.playbook(playbook=k, container=container, inputs=v, name=name, callback=playbook_wait)
        
    else:
        raise RuntimeError("Unable to find match between indicator types and playbook input types")
        
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="decide_and_launch_playbooks:names", value=json.dumps(decide_and_launch_playbooks__names))

    playbook_wait(container=container)

    return


def indicator_and_playbook_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_and_playbook_decision() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["list_block_playbooks:custom_function_result.data.*.full_name", "!=", ""],
            ["get_marked_indicators:custom_function_result.data.*.indicator_value", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        decide_and_launch_playbooks(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def get_indicators_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_indicators_status() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "tags_or": "marked_for_block, blocked",
        "tags_and": None,
        "container": id_value,
        "tags_exclude": None,
        "indicator_timerange": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_get_by_tag", parameters=parameters, name="get_indicators_status", callback=decision_3)

    return


def format_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note() called")

    template = """The following indicators were marked for block. Their current status is shown in the table below. Any indicators that are still listed as \"marked_for_block,\" may require manual remediation.\n\n| Value | Type | Current Tags |\n| --- | --- | --- |\n%%\n| `{0}` | `{1}` | `{2}` |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "get_indicators_status:custom_function_result.data.*.indicator_value",
        "get_indicators_status:custom_function_result.data.*.indicator_cef_type",
        "get_indicators_status:custom_function_result.data.*.indicator_tags"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note", drop_none=True)

    return


def playbook_wait(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_wait() called")

    decide_and_launch_playbooks__names = json.loads(phantom.get_run_data(key="decide_and_launch_playbooks:names"))

    ################################################################################
    ## Custom Code Start
    ################################################################################
	
    if phantom.completed(playbook_names=decide_and_launch_playbooks__names):
        # call connected block "indicators_not_blocked"
        get_indicators_status(container=container)
        
	# return early to avoid calling connected block too soon
    return

	   	
    ################################################################################
    ## Custom Code End
    ################################################################################

    get_indicators_status(container=container)

    return


def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_indicators_status:custom_function_result.data.*.indicator_value", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_note(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_note = phantom.get_format_data(name="format_note")

    output = {
        "note_title": "[Auto-Generated] Block Indicator Summary",
        "note_content": format_note,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    decide_and_launch_playbooks__names = phantom.get_run_data(key="decide_and_launch_playbooks:names")
    if not decide_and_launch_playbooks__names:
        raise RuntimeError("Unable to launch block playbooks due to missing indicators or missing playbooks")
    elif not json.loads(decide_and_launch_playbooks__names):
        raise RuntimeError("Unable to launch block playbooks due to no matching indicators for playbook inputs")
    
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