"""
Use TruSTAR to gather threat information about indicators in a SOAR event. Tag the indicators with the normalized priority score from TruSTAR and summarize the findings in an analyst note. This playbook is meant to be used as a child playbook executed by a parent playbook such as &quot;threat_intel_investigate&quot;.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'indicator_reputation' block
    indicator_reputation(container=container)

    return

def indicator_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Query the Indicator API in TruSTAR to find threat intelligence scores and attributes 
    # about each of the indicators passed into the playbook.
    ################################################################################

    playbook_input_indicators = phantom.collect2(container=container, datapath=["playbook_input:indicators"])

    parameters = []

    # build parameters list for 'indicator_reputation' call
    for playbook_input_indicators_item in playbook_input_indicators:
        if playbook_input_indicators_item[0] is not None:
            parameters.append({
                "indicator_value": playbook_input_indicators_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("indicator reputation", parameters=parameters, name="indicator_reputation", assets=["trustar"], callback=indicator_reputation_callback)

    return


def indicator_reputation_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_reputation_callback() called")

    
    format_note(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    indicator_found(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def tag_indicator_with_priority_score(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("tag_indicator_with_priority_score() called")

    filtered_result_0_data_indicator_found = phantom.collect2(container=container, datapath=["filtered-data:indicator_found:condition_1:indicator_reputation:action_result.data.*.priorityScore","filtered-data:indicator_found:condition_1:indicator_reputation:action_result.parameter.indicator_value"])

    parameters = []

    # build parameters list for 'tag_indicator_with_priority_score' call
    for filtered_result_0_item_indicator_found in filtered_result_0_data_indicator_found:
        parameters.append({
            "tags": filtered_result_0_item_indicator_found[0],
            "indicator": filtered_result_0_item_indicator_found[1],
            "overwrite": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="tag_indicator_with_priority_score")

    return


def format_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note() called")

    ################################################################################
    # Combine the TruSTAR results into a note to pass up to the parent playbook. Build 
    # a markdown table of results with links to TruSTAR queries and select fields 
    # from the reputation information for each indicator.
    ################################################################################

    indicator_reputation_result_data = phantom.collect2(container=container, datapath=["indicator_reputation:action_result.parameter.indicator_value","indicator_reputation:action_result.data.*.observable.type","indicator_reputation:action_result.data.*.priorityScore","indicator_reputation:action_result.data.*.submissionTags","indicator_reputation:action_result.data.*.attributes","indicator_reputation:action_result.data.*.safelisted","indicator_reputation:action_result.data.*.scoreContexts.*.sourceName"], action_results=results)

    indicator_reputation_parameter_indicator_value = [item[0] for item in indicator_reputation_result_data]
    indicator_reputation_result_item_1 = [item[1] for item in indicator_reputation_result_data]
    indicator_reputation_result_item_2 = [item[2] for item in indicator_reputation_result_data]
    indicator_reputation_result_item_3 = [item[3] for item in indicator_reputation_result_data]
    indicator_reputation_result_item_4 = [item[4] for item in indicator_reputation_result_data]
    indicator_reputation_result_item_5 = [item[5] for item in indicator_reputation_result_data]
    indicator_reputation_result_item_6 = [item[6] for item in indicator_reputation_result_data]

    input_parameter_0 = ""
    input_parameter_1 = ""

    format_note__note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    import urllib.parse
    
    note = """
| Indicator | Type | Priority Score | Submission Tags | Attributes | Safe Listed? | Sources |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
    """
    
    for item in indicator_reputation_result_data:
        if item[1]:            
            # for the first column, use the indicator as the text and the trustar query as the href
            trustar_link = 'https://station.trustar.co/browse/search?q={}'.format(urllib.parse.quote(item[0]))
            indicator_markdown = '[{}]({})'.format(item[0], trustar_link)
            indicator_type = item[1]
            priority = item[2]
            submission_tags = json.dumps(item[3]).replace('[', '').replace(']', '')
            attributes = json.dumps(item[4]).replace('{', '').replace('}', '').replace('[', '').replace(']', '')
            safe_listed = item[5]
            sources = item[6]
            note += "|{}|{}|{}|{}|{}|{}|{}|\n".format(indicator_markdown, indicator_type, priority, submission_tags, attributes, safe_listed, sources)
        else:
            note += "|{}|Not found in TruSTAR||||||\n".format(item[0])

    format_note__note_content = note
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="format_note:note_content", value=json.dumps(format_note__note_content))

    return


def indicator_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_found() called")

    ################################################################################
    # Filter for indicators that were found in TruSTAR.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["indicator_reputation:action_result.summary.indicators_found", ">", 0]
        ],
        name="indicator_found:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        tag_indicator_with_priority_score(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_note__note_content = json.loads(phantom.get_run_data(key="format_note:note_content"))

    output = {
        "note_title": "TruSTAR Indicator Enrichment",
        "note_content": format_note__note_content,
    }

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

    phantom.save_playbook_output_data(output=output)

    return