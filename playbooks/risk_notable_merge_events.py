"""
This playbook finds related events based on key fields in a Risk Notable and allows the user to process the results and decide which events to merge into the current investigation.\t
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_effective_user' block
    get_effective_user(container=container)

    return

def workbook_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_list() called")

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_list", parameters=parameters, name="workbook_list", callback=join_combine_related_fields)

    return


def join_combine_related_fields(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_combine_related_fields() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_combine_related_fields_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_combine_related_fields_called", value="combine_related_fields")

    # call connected block "combine_related_fields"
    combine_related_fields(container=container, handle=handle)

    return


def combine_related_fields(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("combine_related_fields() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.risk_object","artifact:*.cef.threat_object","artifact:*.cef.description","artifact:*.id"], scope="all")
    deduplicate_threat_objects_data = phantom.collect2(container=container, datapath=["deduplicate_threat_objects:custom_function_result.data.*.item"], scope="all")

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_cef_item_1 = [item[1] for item in container_artifact_data]
    container_artifact_cef_item_2 = [item[2] for item in container_artifact_data]
    deduplicate_threat_objects_data___item = [item[0] for item in deduplicate_threat_objects_data]

    parameters = []

    parameters.append({
        "input_1": container_artifact_cef_item_0,
        "input_2": container_artifact_cef_item_1,
        "input_3": container_artifact_cef_item_2,
        "input_4": deduplicate_threat_objects_data___item,
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
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="combine_related_fields", callback=find_related_events)

    return


def find_related_events(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("find_related_events() called")

    id_value = container.get("id", None)
    combine_related_fields_data = phantom.collect2(container=container, datapath=["combine_related_fields:custom_function_result.data.*.item"])

    combine_related_fields_data___item = [item[0] for item in combine_related_fields_data]

    parameters = []

    parameters.append({
        "container": id_value,
        "value_list": combine_related_fields_data___item,
        "filter_label": None,
        "earliest_time": "-30d",
        "filter_status": None,
        "filter_in_case": None,
        "filter_severity": None,
        "minimum_match_count": 3,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/find_related_containers", parameters=parameters, name="find_related_events", callback=related_events_decision)

    return


def related_events_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("related_events_decision() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["find_related_events:custom_function_result.data.*.container_id", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_prompt(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["find_related_events:custom_function_result.data.*.container_id", "==", ""],
            ["workbook_list:custom_function_result.data.*.name", "==", "Risk Investigation"]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        workbook_task_update_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3
    found_match_3 = phantom.decision(
        container=container,
        conditions=[
            ["find_related_events:custom_function_result.data.*.container_id", "==", ""]
        ])

    # call connected blocks if condition 3 matched
    if found_match_3:
        add_note_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def format_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_prompt() called")

    ################################################################################
    # Format a prompt with a high-level list of related events
    ################################################################################

    template = """| Event ID | Name | # of Matches | Event Status | In Case | \n| ---: | :--- |  :---: | :---: | :---: | \n%%\n| [{0}]({6}) | `{1}` | {2} | {3}:{4} | {5} | \n%%"""

    # parameter list for template variable replacement
    parameters = [
        "find_related_events:custom_function_result.data.*.container_id",
        "find_related_events:custom_function_result.data.*.container_name",
        "find_related_events:custom_function_result.data.*.container_indicator_match_count",
        "find_related_events:custom_function_result.data.*.container_status",
        "find_related_events:custom_function_result.data.*.container_type",
        "find_related_events:custom_function_result.data.*.in_case",
        "find_related_events:custom_function_result.data.*.container_url"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_prompt")

    related_events(container=container)

    return


def workbook_task_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_task_update_1() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "owner": None,
        "status": None,
        "container": id_value,
        "task_name": "Investigate",
        "note_title": "[Auto-Generated] Find Related Events Summary",
        "note_content": "No related events based on input fields and minimum threshold.",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="workbook_task_update_1")

    return


def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_1() called")

    ################################################################################
    # Add a generic note letting the user know that no related events were found.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content="No related events based on input fields and minimum threshold.", note_format="markdown", note_type="general", title="[Auto-Generated] Find Related Events Summary")

    return


def related_events(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("related_events() called")

    ################################################################################
    # Prompt the user with a list of related events and allow them to select the merge 
    # option.
    ################################################################################

    # set user and message variables for phantom.prompt call

    user = json.loads(phantom.get_run_data(key='get_effective_user:username'))
    message = """Please review related events in the table below and then select an option.\n\n{0}\n\n### The merge process will:\n\n- Mark the current event as the parent case. If the Risk Notable workbook is present it will be added, otherwise, it will add the system default workbook.\n- Copy events, artifacts, and notes to the parent case.\n- Close the related events with a link to the parent case."""

    # parameter list for template variable replacement
    parameters = [
        "format_prompt:formatted_data"
    ]

    # responses
    response_types = [
        {
            "prompt": "Merge Response",
            "options": {
                "type": "list",
                "choices": [
                    "Merge All",
                    "Merge Individually",
                    "Do Nothing"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="related_events", parameters=parameters, response_types=response_types, callback=decision_2)

    return

def process_responses(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("process_responses() called")

    ################################################################################
    # Produces an output list of containers that the user decided to merge.
    ################################################################################

    event_details_result_data = phantom.collect2(container=container, datapath=["event_details:action_result.summary.responses"], action_results=results)

    event_details_summary_responses = [item[0] for item in event_details_result_data]

    process_responses__container_list = None
    process_responses__should_merge = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    process_responses__should_merge = False
    responses = event_details_summary_responses[0]
    # Grab run_key and convert to list
    container_list = json.loads(phantom.get_run_data(key='container_list'))
    if 'Merge Into Case' in responses:
        process_responses__container_list = []
        for container_id, response in zip(container_list, responses):
            if response.lower() == 'merge into case':
                process_responses__container_list.append(container_id)
                process_responses__should_merge = True

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="process_responses:container_list", value=json.dumps(process_responses__container_list))
    phantom.save_run_data(key="process_responses:should_merge", value=json.dumps(process_responses__should_merge))

    merge_any_decision(container=container)

    return


def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["related_events:action_result.summary.responses.0", "==", "Merge All"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        merge_all(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["related_events:action_result.summary.responses.0", "==", "Merge Individually"]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        custom_format(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 3
    join_format_end_note(action=action, success=success, container=container, results=results, handle=handle)

    return


def custom_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("custom_format() called")

    ################################################################################
    # Produce a custom format that calculates how many related indicators there are 
    # per container. This is used to truncate the output if it's over the specified 
    # amount.
    ################################################################################

    find_related_events_data = phantom.collect2(container=container, datapath=["find_related_events:custom_function_result.data.*.container_id","find_related_events:custom_function_result.data.*.indicator_ids","find_related_events:custom_function_result.data.*.container_name"])

    find_related_events_data___container_id = [item[0] for item in find_related_events_data]
    find_related_events_data___indicator_ids = [item[1] for item in find_related_events_data]
    find_related_events_data___container_name = [item[2] for item in find_related_events_data]

    custom_format__output = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Define base format - customize as needed
    custom_format__output = """Please review the following events and their associated indicators. Consider merging the related events into the current investigation.
    
The merge process will:
 - Mark the current event as the parent case. If no workbook has been added, it will use the default workbook.
 - Copy events, artifacts, and notes to the parent case.
 - Close the related events with a link to the parent case.
 
 """
    
    # Build phantom url for use later 
    base_url = phantom.get_base_url()
    url = phantom.build_phantom_rest_url('indicator')
    
    # Iterate through all inputs and append to base format
    for item1,item2,item3 in zip(find_related_events_data___container_id,find_related_events_data___indicator_ids,find_related_events_data___container_name):
        custom_format__output += "#### [Event {0}: {1}]({2}/mission/{0}/summary/evidence)\n\n".format(item1, item3, base_url)
        custom_format__output += "| Field Names | Values |\n"
        custom_format__output += "| --- | --- |\n"
        
        indicator_dict = {}

        # Find_related_containers only returns an indicator id, this converts the indicator id to an actual value
        # Only iterate through 10 indicators for easier readability
        for indicator in item2[0:10]:
            response = phantom.requests.get(uri = url + "/{}?_special_fields=true".format(indicator), verify=False).json()              
            value = response['value']
            fields = response.get('_special_fields')
            
            # Remove null items and join
            if isinstance(fields, list):
                fields = [item for item in fields if item]
                fields = sorted(fields)
                fields = ", ".join(fields)
                
            indicator_dict[value] = fields
            
        # sort dictionary alphabetically by value
        for k,v in sorted(indicator_dict.items(), key = lambda kv:(kv[1], kv[0])):
            if len(k) > 250:
                custom_format__output += "| {0} | ```{1}``` ***...truncated...*** | \n".format(v, k[:250])
            else:
                custom_format__output += "| {0} | ```{1}``` | \n".format(v, k)
            
        # If there were more than 10 indicators, add a note at the end letting the analyst know they can find more by following the event link    
        if len(item2) > 10:
            custom_format__output += "- ***+{0} additional related artifacts***".format(len(item2) - 10)
            
        custom_format__output += "\n---\n\n"

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="custom_format:output", value=json.dumps(custom_format__output))

    event_details(container=container)

    return


def merge_all(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_all() called")

    id_value = container.get("id", None)
    find_related_events_data = phantom.collect2(container=container, datapath=["find_related_events:custom_function_result.data.*.container_id"])

    find_related_events_data___container_id = [item[0] for item in find_related_events_data]

    parameters = []

    parameters.append({
        "workbook": None,
        "container_list": find_related_events_data___container_id,
        "close_containers": True,
        "target_container": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/container_merge", parameters=parameters, name="merge_all", callback=merge_all_format)

    return


def workbook_task_update_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_task_update_2() called")

    id_value = container.get("id", None)
    format_end_note = phantom.get_format_data(name="format_end_note")

    parameters = []

    parameters.append({
        "owner": None,
        "status": None,
        "container": id_value,
        "task_name": "Investigate",
        "note_title": "[Auto-Generated] Find Related Events Summary",
        "note_content": format_end_note,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="workbook_task_update_2")

    return


def join_format_end_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_format_end_note() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_format_end_note_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_format_end_note_called", value="format_end_note")

    # call connected block "format_end_note"
    format_end_note(container=container, handle=handle)

    return


def format_end_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_end_note() called")

    ################################################################################
    # Format a note with the information the user decided to not act upon.
    ################################################################################

    template = """User opted to not merge.\n\nPrevious results of find related events below.\n\n{0}"""

    # parameter list for template variable replacement
    parameters = [
        "format_prompt_1:formatted_data"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_end_note")

    workbook_decision_2(container=container)

    return


def workbook_decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["workbook_list:custom_function_result.data.*.name", "==", "Risk Investigation"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        workbook_task_update_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_note_2(action=action, success=success, container=container, results=results, handle=handle)

    return


def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_2() called")

    format_end_note = phantom.get_format_data(name="format_end_note")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_end_note, note_format="markdown", note_type="general", title="[Auto-Generated] Find Related Events Summary")

    return


def event_details(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("event_details() called")

    ################################################################################
    # A dynamic prompt to list out details for each container so that the user can 
    # decide which to merge.
    ################################################################################

    # set user and message variables for phantom.prompt call
    effective_user_id = phantom.get_effective_user()
    url = phantom.build_phantom_rest_url('ph_user', effective_user_id)
    response = phantom.requests.get(url, verify=False).json()
    user = response.get('username')
    message = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "custom_format:custom_function:output",
    ]
    
    # fetch data for dynamic response
    container_data = phantom.collect2(container=container, datapath=['find_related_events:custom_function_result.data.*.container_id', 'find_related_events:custom_function_result.data.*.container_name'], action_results=results)
    container_id_list = [item[0] for item in container_data]
    container_name_list = [item[1] for item in container_data]
    
    #Dynamic Responses:
    response_types = []
    for container_id, container_name in zip(container_id_list, container_name_list):
        response_types.append({
                "prompt": "Event {0}: {1}".format(container_id, container_name),
                "options": {
                    "type": "list",
                    "choices": [
                        "Merge Into Case",
                        "Ignore",
                    ]
                },
            })
        
    phantom.save_run_data(value=json.dumps(container_id_list), key="container_list", auto=True)

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="event_details", parameters=parameters, response_types=response_types, callback=process_responses)

    return

def merge_selected(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_selected() called")

    id_value = container.get("id", None)
    process_responses__container_list = json.loads(phantom.get_run_data(key="process_responses:container_list"))

    parameters = []

    parameters.append({
        "workbook": None,
        "container_list": process_responses__container_list,
        "close_containers": True,
        "target_container": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/container_merge", parameters=parameters, name="merge_selected", callback=merge_selected_callback)

    return


def merge_selected_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_selected_callback() called")

    
    event_id_filter(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    merge_individual_format(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def event_id_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("event_id_filter() called")

    ################################################################################
    # Produce a list of event ids to update in Splunk ES.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.event_id", "!=", ""]
        ],
        name="event_id_filter:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        update_notable(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def workbook_decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["workbook_list:custom_function_result.data.*.name", "==", "Risk Investigation"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        workbook_task_update_3(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_note_3(action=action, success=success, container=container, results=results, handle=handle)

    return


def workbook_task_update_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_task_update_3() called")

    id_value = container.get("id", None)
    merge_all_format = phantom.get_format_data(name="merge_all_format")

    parameters = []

    parameters.append({
        "owner": None,
        "status": None,
        "container": id_value,
        "task_name": "Investigate",
        "note_title": "[Auto-Generated] Related Events Merged",
        "note_content": merge_all_format,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="workbook_task_update_3")

    return


def merge_all_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_all_format() called")

    ################################################################################
    # Format a note with a list of all events merged.
    ################################################################################

    template = """Result of merge process:\n\nContainers merged into case {0} - {1}:\n%%\n- {2}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:name",
        "find_related_events:custom_function_result.data.*.container_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="merge_all_format")

    workbook_decision_3(container=container)

    return


def add_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_3() called")

    merge_all_format = phantom.get_format_data(name="merge_all_format")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=merge_all_format, note_format="markdown", note_type="general", title="[Auto-Generated] Related Events Merged")

    return


def workbook_decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_decision_4() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["workbook_list:custom_function_result.data.*.name", "==", "Risk Investigation"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        workbook_task_update_4(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_note_4(action=action, success=success, container=container, results=results, handle=handle)

    return


def workbook_task_update_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_task_update_4() called")

    id_value = container.get("id", None)
    merge_individual_format = phantom.get_format_data(name="merge_individual_format")

    parameters = []

    parameters.append({
        "owner": None,
        "status": None,
        "container": id_value,
        "task_name": "Investigate",
        "note_title": "[Auto-Generated] Related Events Merged",
        "note_content": merge_individual_format,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="workbook_task_update_4")

    return


def add_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_4() called")

    merge_individual_format = phantom.get_format_data(name="merge_individual_format")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=merge_individual_format, note_format="markdown", note_type="general", title="[Auto-Generated] Related Events Merged")

    return


def merge_individual_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_individual_format() called")

    ################################################################################
    # Format a note that shows the result of the merge process.
    ################################################################################

    template = """Result of merge process:\n\nContainers merged into case {0} - {1}:\n%%\n- {2}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:name",
        "process_responses:custom_function:container_list"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="merge_individual_format")

    workbook_decision_4(container=container)

    return


def merge_any_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_any_decision() called")

    ################################################################################
    # Determine if the user opted to merge at least 1 of the events.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["process_responses:custom_function:should_merge", "==", True]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        merge_selected(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_format_end_note(action=action, success=success, container=container, results=results, handle=handle)

    return


def get_effective_user(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_effective_user() called")

    ################################################################################
    # Determine which user launched this playbook.
    ################################################################################

    get_effective_user__username = None
    get_effective_user__user_type = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    effective_user_id = phantom.get_effective_user()
    url = phantom.build_phantom_rest_url('ph_user', effective_user_id)
    response_json = phantom.requests.get(url, verify=False).json()

    get_effective_user__username = response_json['username']
    get_effective_user__user_type = response_json['type']

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="get_effective_user:username", value=json.dumps(get_effective_user__username))
    phantom.save_run_data(key="get_effective_user:user_type", value=json.dumps(get_effective_user__user_type))

    decision_7(container=container)

    return


def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_7() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_effective_user:custom_function:user_type", "!=", "automation"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        workbook_list(action=action, success=success, container=container, results=results, handle=handle)
        deduplicate_threat_objects(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def update_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_notable() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    comment_formatted_string = phantom.format(
        container=container,
        template="""Case created: {0}\n\nName: {1}\n\nURL: {2}/summary""",
        parameters=[
            "container:id",
            "container:name",
            "container:url"
        ])

    ################################################################################
    # Update all Splunk Notables with a link to merged container. 
    ################################################################################

    filtered_artifact_0_data_event_id_filter = phantom.collect2(container=container, datapath=["filtered-data:event_id_filter:condition_1:artifact:*.cef.event_id","filtered-data:event_id_filter:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'update_notable' call
    for filtered_artifact_0_item_event_id_filter in filtered_artifact_0_data_event_id_filter:
        if filtered_artifact_0_item_event_id_filter[0] is not None:
            parameters.append({
                "comment": comment_formatted_string,
                "event_ids": filtered_artifact_0_item_event_id_filter[0],
                "context": {'artifact_id': filtered_artifact_0_item_event_id_filter[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update event", parameters=parameters, name="update_notable", assets=["splunk"])

    return


def deduplicate_threat_objects(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("deduplicate_threat_objects() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.data.*.threat_object","artifact:*.id"])

    container_artifact_header_item_0 = [item[0] for item in container_artifact_data]

    parameters = []

    parameters.append({
        "input_list": container_artifact_header_item_0,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_deduplicate", parameters=parameters, name="deduplicate_threat_objects", callback=join_combine_related_fields)

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