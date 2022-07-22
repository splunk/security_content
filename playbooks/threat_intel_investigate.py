"""
This parent playbook collects data and launches appropriate child playbooks to gather threat intelligence information about indicators. After the child playbooks have run, this playbook posts the notes to the container and prompts the analyst to add tags to each enriched indicator based on the intelligence provided.
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
        "tags": "investigate, threat_intel",
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

    phantom.custom_function(custom_function="community/playbooks_list", parameters=parameters, name="list_investigate_playbooks", callback=decision_1)

    return


def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["list_investigate_playbooks:custom_function_result.data.*.name", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        collect_all_indicators(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def collect_all_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("collect_all_indicators() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "container": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_collect", parameters=parameters, name="collect_all_indicators", callback=launch_investigate_playbooks)

    return


def launch_investigate_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("launch_investigate_playbooks() called")

    ################################################################################
    # Determine if any investigate playbooks are available with input types matching 
    # the indicators in the container, and synchronously launch any playbooks that 
    # are found. By default, this will look for local playbooks only, but it can be 
    # changed to use community playbooks.
    ################################################################################

    list_investigate_playbooks_data = phantom.collect2(container=container, datapath=["list_investigate_playbooks:custom_function_result.data.*.full_name","list_investigate_playbooks:custom_function_result.data.*.input_spec"])
    collect_all_indicators_data_all_indicators = phantom.collect2(container=container, datapath=["collect_all_indicators:custom_function_result.data.all_indicators.*.cef_value","collect_all_indicators:custom_function_result.data.all_indicators.*.data_types"])

    list_investigate_playbooks_data___full_name = [item[0] for item in list_investigate_playbooks_data]
    list_investigate_playbooks_data___input_spec = [item[1] for item in list_investigate_playbooks_data]
    collect_all_indicators_data_all_indicators___cef_value = [item[0] for item in collect_all_indicators_data_all_indicators]
    collect_all_indicators_data_all_indicators___data_types = [item[1] for item in collect_all_indicators_data_all_indicators]

    launch_investigate_playbooks__playbooks_launched = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    playbooks_launched = []
    
    # loop through each playbook with the matching tags
    for playbook in list_investigate_playbooks_data:
        playbook_name = playbook[0]
        input_spec = playbook[1]
        phantom.debug(playbook_name)
        inputs_to_provide = []
        # loop through each input parameter, matching only the "indicators" input
        for param in input_spec:
            if param['name'] == 'indicators':
                # loop through each accepted data type
                for accepted_data_type in param['contains']:
                    # loop through each indicator in the container and add any indicators with matching data types to the "inputs_to_provide" list
                    for indicator in collect_all_indicators_data_all_indicators:
                        for indicator_type in indicator[1]:
                            # if the types match and the indicator value is not already in the inputs_to_provide then add it now 
                            if indicator_type == accepted_data_type and indicator[0] not in inputs_to_provide:
                                inputs_to_provide.append(indicator[0])
        # back in the playbook loop, call the playbook if there are any inputs
        if inputs_to_provide != []:
            playbook_run_name = playbook_name.split('/')[1].replace(' ','_').lower()
            playbook_input = {'indicators': inputs_to_provide}
            phantom.debug('launching playbook {} with input {}'.format(playbook_name, playbook_input))
            phantom.playbook(playbook=playbook_name, container=container, name=playbook_run_name, inputs=playbook_input, callback=add_notes)
            playbooks_launched.append(playbook_run_name)
            
    launch_investigate_playbooks__playbooks_launched = playbooks_launched

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="launch_investigate_playbooks:playbooks_launched", value=json.dumps(launch_investigate_playbooks__playbooks_launched))

    add_notes(container=container)

    return


def add_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_notes() called")

    ################################################################################
    # Add notes to the container if any were generated by playbooks from the previous 
    # step.
    ################################################################################

    launch_investigate_playbooks__playbooks_launched = json.loads(phantom.get_run_data(key="launch_investigate_playbooks:playbooks_launched"))

    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    playbooks_launched = launch_investigate_playbooks__playbooks_launched
    
    # return early if any of the launched playbooks are not completed
    if not phantom.completed(playbook_names=launch_investigate_playbooks__playbooks_launched):
        return
    
    playbook_outputs = []
    for playbook_name in playbooks_launched:
        note_title = phantom.collect2(container=container, datapath=["{}:playbook_output:note_title".format(playbook_name)])[0][0]
        note_content = phantom.collect2(container=container, datapath=["{}:playbook_output:note_content".format(playbook_name)])[0][0]
        phantom.add_note(container=container, content=note_content, note_format="markdown", note_type="general", title=note_title)
    
    
    #phantom.add_note(container=container, content=note, note_format="markdown", note_type="general", title='trustar test note')

    ################################################################################
    ## Custom Code End
    ################################################################################

    threat_intel_indicator_review(container=container)

    return


def threat_intel_indicator_review(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("threat_intel_indicator_review() called")

    # set user and message variables for phantom.prompt call

    user = "Administrator"
    message = """For each indicator below, please review the gathered information and mark the indicator for further action."""
    
    # add the note from each of the launched playbooks
    playbooks_launched = json.loads(phantom.get_run_data(key="launch_investigate_playbooks:playbooks_launched"))
    for playbook in playbooks_launched:
        message += '\n\n'
        message += phantom.collect2(container=container, datapath=["{}:playbook_output:note_title".format(playbook)])[0][0] + '\n'
        message += phantom.collect2(container=container, datapath=["{}:playbook_output:note_content".format(playbook)])[0][0] + '\n'

    # no parameters to add
    parameters = []
    
    # create two questions and responses for each indicator. the first chooses a tag from a preconfigured list, and the second accepts a freeform comma-separated list of tags
    response_types = []
    all_indicators = phantom.collect2(container=container, datapath=["collect_all_indicators:custom_function_result.data.all_indicators.*.cef_value","collect_all_indicators:custom_function_result.data.all_indicators.*.data_types"])

    
    for index, indicator in enumerate(all_indicators):
        response_types.append({
            "prompt": "Choose a tag for the indicator [{0}]".format(indicator[0]),
            "options": {
                "type": "list",
                "choices": [
                    "Tag to block",
                    "Tag as safe",
                    "Do nothing"]}})
        response_types.append({
            "prompt": "Add any other comma-separated freeform tags for the indicator [{}], or enter 'n' to not add more tags.".format(indicator[0]),
            "options": {
                "type": "message"}})

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="threat_intel_indicator_review", parameters=parameters, response_types=response_types, callback=process_responses)

    return

def process_responses(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("process_responses() called")

    threat_intel_indicator_review_result_data = phantom.collect2(container=container, datapath=["threat_intel_indicator_review:action_result.summary.responses","threat_intel_indicator_review:action_result.parameter.context.artifact_id"], action_results=results)
    collect_all_indicators_data_all_indicators = phantom.collect2(container=container, datapath=["collect_all_indicators:custom_function_result.data.all_indicators.*.cef_value"])

    threat_intel_indicator_review_summary_responses = [item[0] for item in threat_intel_indicator_review_result_data]
    collect_all_indicators_data_all_indicators___cef_value = [item[0] for item in collect_all_indicators_data_all_indicators]

    parameters = []

    parameters.append({
        "input_1": threat_intel_indicator_review_summary_responses,
        "input_2": collect_all_indicators_data_all_indicators___cef_value,
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

    responses = threat_intel_indicator_review_summary_responses[0]
    indicator_values = collect_all_indicators_data_all_indicators___cef_value

    # lookup table to turn prompt responses into tags to add. "Do nothing" is not included, so no tags will be added
    response_to_tag_map = {
        "Tag to block": "marked_for_block",
        "Tag as safe": "safe"
    }

    # overwrite the parameters list with a list of one indicator and one tag per parameter dictionary 
    parameters = []
    for indicator_index, indicator_value in enumerate(indicator_values):
        preconfigured_response = responses[indicator_index * 2]
        freeform_response = responses[indicator_index * 2 + 1]
        
        # handle the preconfigured responses
        if preconfigured_response in response_to_tag_map:
            phantom.comment(comment="Tagging the indicator {} with the preconfigured tag {}".format(indicator_value, response_to_tag_map[preconfigured_response]))
            parameters.append({"input_1": [indicator_value, response_to_tag_map[preconfigured_response]]})
        elif preconfigured_response != 'Do nothing':
            phantom.error('The response {} was chosen for the indicator {}, but that response is not in the set of allowed responses.'.format(preconfigured_response, indicator_value))
        
        # handle the freeform responses
        if freeform_response.lower() not in ['n', 'none', 'na', 'n/a']:
            freeform_tags = freeform_response.replace(' ','').split(',')
            for tag in freeform_tags:
                phantom.comment(comment="Tagging the indicator {} with the freeform tag {}".format(indicator_value, tag))
                parameters.append({"input_1": [indicator_value, tag]})

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/passthrough", parameters=parameters, name="process_responses", callback=tag_indicators)

    return


def tag_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("tag_indicators() called")

    process_responses__result = phantom.collect2(container=container, datapath=["process_responses:custom_function_result.data"])

    parameters = []

    # build parameters list for 'tag_indicators' call
    for process_responses__result_item in process_responses__result:
        parameters.append({
            "tags": process_responses__result_item[0],
            "indicator": process_responses__result_item[0],
            "overwrite": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    # overwrite the parameters, extracting the indicator and tag for each result from process_responses
    parameters = []
    for item in process_responses__result:
        parameters.append({
            "indicator": item[0][0]['item'],
            "tags": item[0][1]['item'],
            "overwrite": None
        })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="tag_indicators")

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