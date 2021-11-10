"""
This playbook was designed to be called by a user to process indicators that are marked as suspicious within the SOAR platform. Analysts will review indicators in a prompt and mark them as blocked or safe.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_suspect_indicators' block
    get_suspect_indicators(container=container)

    return

def get_suspect_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_suspect_indicators() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "tags_or": "suspicious, malicious",
        "tags_and": None,
        "container": id_value,
        "tags_exclude": "blocked, safe, marked_for_block",
        "indicator_timerange": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_get_by_tag", parameters=parameters, name="get_suspect_indicators", callback=indicators_decision)

    return


def response_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("response_filter() called")

    ################################################################################
    # Filter on any indicators that were selected for tagging as block or safe.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["process_responses:custom_function_result.data.*.item.response", "==", "Block"]
        ],
        name="response_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        tag_indicator_block(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["process_responses:custom_function_result.data.*.item.response", "==", "Tag as Safe"]
        ],
        name="response_filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        tag_indicator_safe(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


def select_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("select_indicators() called")

    # set user and message variables for phantom.prompt call
    custom_format__output = json.loads(phantom.get_run_data(key="custom_format:output"))
    
    user_id = phantom.get_effective_user()
    url = phantom.build_phantom_rest_url('ph_user', user_id)
    response = phantom.requests.get(url, verify=False).json()
    user = response['username']
    message = """Please review the list of suspect indicators and select an action.\n\n{0}""".format(custom_format__output)
	
    indicator_records = phantom.collect2(container=container, datapath=["get_suspect_indicators:custom_function_result.data.*.indicator_value"], action_results=results)
    
    
    indicator_value_list = [item[0] for item in indicator_records]
    
    # dynamic response generation
    response_types = []
    parameters = None
    for ind_val in indicator_value_list:
    	response_types.append({
                "prompt": "{0}".format(ind_val),
                "options": {
                    "type": "list",
                    "choices": [
                        "Block",
                        "Tag as Safe",
                        "Do Nothing"
                    ]
                }
            }
        )

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="select_indicators", parameters=parameters, response_types=response_types, callback=process_responses)

    return

def tag_indicator_block(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("tag_indicator_block() called")

    filtered_cf_result_0 = phantom.collect2(container=container, datapath=["filtered-data:response_filter:condition_1:process_responses:custom_function_result.data.*.item.indicator_id"])

    parameters = []

    # build parameters list for 'tag_indicator_block' call
    for filtered_cf_result_0_item in filtered_cf_result_0:
        parameters.append({
            "tags": "marked_for_block",
            "indicator": filtered_cf_result_0_item[0],
            "overwrite": "true",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="tag_indicator_block")

    return


def tag_indicator_safe(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("tag_indicator_safe() called")

    filtered_cf_result_0 = phantom.collect2(container=container, datapath=["filtered-data:response_filter:condition_2:process_responses:custom_function_result.data.*.item.indicator_id"])

    parameters = []

    # build parameters list for 'tag_indicator_safe' call
    for filtered_cf_result_0_item in filtered_cf_result_0:
        parameters.append({
            "tags": "safe",
            "indicator": filtered_cf_result_0_item[0],
            "overwrite": "true",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="tag_indicator_safe")

    return


def indicators_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicators_decision() called")

    ################################################################################
    # Determine if any suspect indicators were found.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_suspect_indicators:custom_function_result.data.*.indicator_value", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        custom_format(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def custom_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("custom_format() called")

    ################################################################################
    # Uses code to format an output that links the indicator values with the fields 
    # and artifacts where they occur.
    ################################################################################

    get_suspect_indicators_data = phantom.collect2(container=container, datapath=["get_suspect_indicators:custom_function_result.data.*.indicator_value","get_suspect_indicators:custom_function_result.data.*.indicator_tags"], scope="all")
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef","artifact:*.name"], scope="all")

    get_suspect_indicators_data___indicator_value = [item[0] for item in get_suspect_indicators_data]
    get_suspect_indicators_data___indicator_tags = [item[1] for item in get_suspect_indicators_data]
    container_artifact_header_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_header_item_1 = [item[1] for item in container_artifact_data]

    custom_format__output = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
	
    custom_format__output = ""
    for indicator, tags in zip(get_suspect_indicators_data___indicator_value, get_suspect_indicators_data___indicator_tags):
        custom_format__output += f"#### {indicator}\n\n"
        custom_format__output += f" - Tags: `{', '.join(tags)}`\n"
        artifact_list = []
        field_list = []
        for artifact_cef, artifact_name in zip(container_artifact_header_item_0, container_artifact_header_item_1):
            indicator_found = False
            for key, value in artifact_cef.items():
                if value == indicator:
                    field_list.append(key)
                    artifact_list.append(artifact_name)
                    
        if field_list or artifact_list:
            custom_format__output += f" - Fields: `{', '.join(list(set(field_list)))}`\n"
            custom_format__output += f" - Artifacts: `{', '.join(list(set(artifact_list)))}`"
            
        custom_format__output += "\n\n---\n\n"
                   	
                    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="custom_format:output", value=json.dumps(custom_format__output))

    select_indicators(container=container)

    return


def process_responses(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("process_responses() called")

    select_indicators_result_data = phantom.collect2(container=container, datapath=["select_indicators:action_result.summary.responses","select_indicators:action_result.parameter.context.artifact_id"], action_results=results)
    get_suspect_indicators_data = phantom.collect2(container=container, datapath=["get_suspect_indicators:custom_function_result.data.*.indicator_id"])

    select_indicators_summary_responses = [item[0] for item in select_indicators_result_data]
    get_suspect_indicators_data___indicator_id = [item[0] for item in get_suspect_indicators_data]

    parameters = []

    parameters.append({
        "input_1": select_indicators_summary_responses,
        "input_2": get_suspect_indicators_data___indicator_id,
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

    responses = select_indicators_summary_responses[0]
    
    # overwrite parameters
    parameters = []
    
    # merge responses with data
    for response, indicator_id in zip(responses, get_suspect_indicators_data___indicator_id):
    	parameters.append({'input_1': {'indicator_id': indicator_id, 'response': response}})
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/passthrough", parameters=parameters, name="process_responses", callback=response_filter)

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