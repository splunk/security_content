"""
Accepts a user or device and identifies if related notables exists in a timeframe of last 24 hours.. Generates a global report and list of observables.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'input_filter' block
    input_filter(container=container)

    return

@phantom.playbook_block()
def input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("input_filter() called")

    ################################################################################
    # Creates a dataset without None values.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:search_term", "!=", None]
        ],
        name="input_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        comma_separated_user(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def search_notables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("search_notables() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""`notable` | search _raw IN ({0})\n""",
        parameters=[
            "comma_separated_user:formatted_data"
        ])

    ################################################################################
    # Retrieve a list of notables which matched the given search input.
    ################################################################################

    comma_separated_user = phantom.get_format_data(name="comma_separated_user")

    parameters = []

    if query_formatted_string is not None:
        parameters.append({
            "query": query_formatted_string,
            "command": "search",
            "display": "",
            "end_time": "now",
            "start_time": "-24h",
            "search_mode": "smart",
            "attach_result": True,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="search_notables", assets=["splunk"], callback=search_results_filter)

    return


@phantom.playbook_block()
def build_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_output() called")

    ################################################################################
    # Extract relevant data and add them to an observable array.
    ################################################################################

    process_results__output = json.loads(_ if (_ := phantom.get_run_data(key="process_results:output")) != "" else "null")  # pylint: disable=used-before-assignment

    build_output__observable_array = None
    build_output__name = None
    build_output__id = None
    build_output__number = None
    build_output__message = None
    build_output__start_time = None
    build_output__end_time = None
    build_output__assignee = None
    build_output__creator_name = None
    build_output__state = None
    build_output__notes = None
    build_output__comments = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    build_output__observable_array = []
    build_output__name = []
    build_output__id = []
    build_output__number = []
    build_output__message = []
    build_output__start_time = []
    build_output__end_time = []
    build_output__assignee = []
    build_output__creator_name = []
    build_output__state = []
    build_output__notes = []
    build_output__comments = []
    
            
    for key in process_results__output.keys():
        
        for result in process_results__output[key]:
            if "comment" in result:
                if isinstance(result["comment"], str):
                    comments = [result["comment"]]
                else:
                    comments = result["comment"]
            else:
                comments = []
        
            matched_fields = []
            for k, v in result.items():
                # generate matched fields where the searched entity appears
                if isinstance(v, str) and key.lower() in v.lower():
                    matched_fields.append(k)

            observable_object = {
                "value": key,
                "ticket": {
                    "name": result['rule_title'] if result.get('rule_title') else result.get("search_name"),
                    "id": result.get("event_id"),
                    "number": result.get("notable_xref_id"),
                    "message": result['rule_description'] if result.get("rule_description") else result.get("savedsearch_description"),
                    "start_time": result.get("_time"),
                    "end_time": "",
                    "assigned_to": result.get("owner"),
                    "creator_name": "",
                    "state": result.get("status_label"),
                    "notes": [],
                    "comments": comments
                },
                "matched_fields": matched_fields,
                "source": "Splunk Enterprise Security"
            }
            build_output__observable_array.append(observable_object)
            build_output__name.append(result.get("search_name"))
            build_output__id.append(result.get("event_id"))
            build_output__number.append(result.get("notable_xref_id"))
            build_output__message.append(result.get("savedsearch_description"))
            build_output__start_time.append(result.get("_time"))
            build_output__end_time.append("")
            build_output__assignee.append(result.get("owner"))
            build_output__creator_name.append("")
            build_output__state.append(result.get("status_label"))
            build_output__notes.append([])
            build_output__comments.append(comments)
        
        
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_output:observable_array", value=json.dumps(build_output__observable_array))
    phantom.save_run_data(key="build_output:name", value=json.dumps(build_output__name))
    phantom.save_run_data(key="build_output:id", value=json.dumps(build_output__id))
    phantom.save_run_data(key="build_output:number", value=json.dumps(build_output__number))
    phantom.save_run_data(key="build_output:message", value=json.dumps(build_output__message))
    phantom.save_run_data(key="build_output:start_time", value=json.dumps(build_output__start_time))
    phantom.save_run_data(key="build_output:end_time", value=json.dumps(build_output__end_time))
    phantom.save_run_data(key="build_output:assignee", value=json.dumps(build_output__assignee))
    phantom.save_run_data(key="build_output:creator_name", value=json.dumps(build_output__creator_name))
    phantom.save_run_data(key="build_output:state", value=json.dumps(build_output__state))
    phantom.save_run_data(key="build_output:notes", value=json.dumps(build_output__notes))
    phantom.save_run_data(key="build_output:comments", value=json.dumps(build_output__comments))

    format_report(container=container)

    return


@phantom.playbook_block()
def comma_separated_user(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("comma_separated_user() called")

    ################################################################################
    # Convert playbook user input list into comma separated string for Splunk query.
    ################################################################################

    template = """*{0}*"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:input_filter:condition_1:playbook_input:search_term"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="comma_separated_user", separator="*,*", drop_none=True)

    search_notables(container=container)

    return


@phantom.playbook_block()
def format_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_report() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR retrieved tickets from Splunk. The table below shows a summary of the information gathered.\n\n| Name | Number | Message | Start Time | End Time | Assignee | Creator Name | State | Source |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n%%\n| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | Splunk Enterprise Security |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "build_output:custom_function:name",
        "build_output:custom_function:number",
        "build_output:custom_function:message",
        "build_output:custom_function:start_time",
        "build_output:custom_function:end_time",
        "build_output:custom_function:assignee",
        "build_output:custom_function:creator_name",
        "build_output:custom_function:state"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_report")

    return


@phantom.playbook_block()
def process_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("process_results() called")

    ################################################################################
    # Iterates through the results of the search notable query to link playbook input 
    # search term to their associated notables.
    ################################################################################

    filtered_input_0_search_term = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_1:playbook_input:search_term"])
    filtered_result_0_data_search_results_filter = phantom.collect2(container=container, datapath=["filtered-data:search_results_filter:condition_1:search_notables:action_result.data"])

    filtered_input_0_search_term_values = [item[0] for item in filtered_input_0_search_term]
    filtered_result_0_data = [item[0] for item in filtered_result_0_data_search_results_filter]

    process_results__output = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    process_results__output = {}
    for search_term in filtered_input_0_search_term_values:
        process_results__output[search_term] = []
        for result in filtered_result_0_data:
            if not isinstance(result, list):
                list_result = [result]
            else:
                list_result = result
            for result_item in list_result:
                result_item_values = [item.lower() for item in result_item.values() if isinstance(item, str)]
                match = False
                for string_value in result_item_values:
                    if search_term.lower() in string_value:
                        match = True
                        break
                if match:
                    process_results__output[search_term].append({**result_item})

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="process_results:output", value=json.dumps(process_results__output))

    build_output(container=container)

    return


@phantom.playbook_block()
def search_results_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("search_results_filter() called")

    ################################################################################
    # Determine if search results exist from the previous query.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["search_notables:action_result.summary.total_events", ">", 0]
        ],
        name="search_results_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        process_results(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_report = phantom.get_format_data(name="format_report")
    build_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "observable": build_output__observable_array,
        "markdown_report": format_report,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return