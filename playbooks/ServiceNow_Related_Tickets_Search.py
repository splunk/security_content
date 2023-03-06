"""
Accepts a user or device and identifies if related tickets exists in a timeframe of last 30 days. Generates a global report and list of observables.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'default_table_list' block
    default_table_list(container=container)

    return

@phantom.playbook_block()
def default_table_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("default_table_list() called")

    ################################################################################
    # Adjust the table list variable to change which tables should be searched.
    ################################################################################

    default_table_list__output = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    # Default tables list to find related tickets. Adjust as needed.
    default_table_list = [
        'incident', 
        'change_request', 
        'change_task', 
        'problem',
        'sc_request', 
        'sc_task', 
        'sc_req_item',
    ]
    default_table_list__output = default_table_list
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="default_table_list:output", value=json.dumps(default_table_list__output))

    convert_table_list(container=container)

    return


@phantom.playbook_block()
def convert_table_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("convert_table_list() called")

    default_table_list__output = json.loads(_ if (_ := phantom.get_run_data(key="default_table_list:output")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "input_list": default_table_list__output,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="convert_table_list", callback=calculate_earliest_time)

    return


@phantom.playbook_block()
def space_delimiter_input(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("space_delimiter_input() called")

    ################################################################################
    # Convert playbook input into space delimiter string for ServiceNow query.
    ################################################################################

    template = """{0}\n"""

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

    phantom.format(container=container, template=template, parameters=parameters, name="space_delimiter_input", separator=" ", drop_none=True)

    run_ticket_query(container=container)

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
        space_delimiter_input(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def process_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("process_results() called")

    ################################################################################
    # Iterates through the results of the run ticket query to link playbook input 
    # search term to their associated tickets.
    ################################################################################

    filtered_input_0_search_term = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_1:playbook_input:search_term"])
    run_ticket_query_result_data = phantom.collect2(container=container, datapath=["run_ticket_query:action_result.data","run_ticket_query:action_result.parameter.query_table"], action_results=results)

    filtered_input_0_search_term_values = [item[0] for item in filtered_input_0_search_term]
    run_ticket_query_result_item_0 = [item[0] for item in run_ticket_query_result_data]
    run_ticket_query_parameter_query_table = [item[1] for item in run_ticket_query_result_data]

    process_results__output = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    process_results__output = {}
    for search_term in filtered_input_0_search_term_values:
        process_results__output[search_term] = []
        for result, query_table in zip(run_ticket_query_result_item_0, run_ticket_query_parameter_query_table):
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
                    process_results__output[search_term].append({**result_item, **{"ticket_type": query_table}})

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="process_results:output", value=json.dumps(process_results__output))

    build_output(container=container)

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
    build_output__number = None
    build_output__message = None
    build_output__start_time = None
    build_output__end_time = None
    build_output__assignee = None
    build_output__creator_name = None
    build_output__state = None
    build_output__matched_fields = None
    build_output__source_link = None
    build_output__source = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    import re 
    
    build_output__observable_array = []
    build_output__name = []
    build_output__number = []
    build_output__message = []
    build_output__start_time = []
    build_output__end_time = []
    build_output__assignee = []
    build_output__creator_name = []
    build_output__state = []
    build_output__matched_fields = []
    build_output__source_link = []
    build_output__source = []
    
    def generate_ticket_link(sample_url, ticket_type, sys_id):
        extract_host = re.search(r"https*:\/\/[^\/]+", sample_url).group(0)
        extract_host += f"/nav_to.do?uri={ticket_type}.do?sys_id={sys_id}"
        return extract_host
        
    for key in process_results__output.keys():
        
        for value in process_results__output[key]:
            assigned_to = None
            caller_id = None
            matched_fields = []
            if value.get("assigned_to"):
                assigned_to = value["assigned_to"]["display_value"]
            if value.get("caller_id"):
                caller_id = value["caller_id"]["display_value"]
            
            for k, v in value.items():
                # generate matched fields where the searched entity appears
                if isinstance(v, str) and key.lower() in v.lower():
                    matched_fields.append(k)
                # search for any link sample:
                if isinstance(v, dict):
                    sample_link = v.get('link')
            
            source_link = generate_ticket_link(sample_link, value['ticket_type'], value['sys_id'])
            observable_object = {
                "value": key,
                "ticket": {
                    "name": value["short_description"],
                    "id": value["sys_id"],
                    "number": value["number"],
                    "message": json.dumps(value["description"]),
                    "start_time": value["sys_created_on"],
                    "end_time": value["closed_at"],
                    "assigned_to": assigned_to,
                    "creator_name": caller_id,
                    "state": value["state"],
                    "notes": [value["work_notes"]],
                    "comments": [value["comments"]]
                },
                "matched_fields": matched_fields,
                "source": "ServiceNow",
                "source_link": source_link
            }
            build_output__observable_array.append(observable_object)
            build_output__name.append(value["short_description"])
            build_output__number.append(value["number"])
            build_output__message.append(json.dumps(value["description"]))  # eliminate new line issues
            build_output__start_time.append(value["sys_created_on"])
            build_output__end_time.append(value["closed_at"])
            build_output__assignee.append(assigned_to)
            build_output__creator_name.append(caller_id)
            build_output__state.append(value["state"])
            build_output__matched_fields.append(matched_fields)
            build_output__source.append("ServiceNow")
            build_output__source_link.append(source_link)
            #phantom.debug(observable_object)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_output:observable_array", value=json.dumps(build_output__observable_array))
    phantom.save_run_data(key="build_output:name", value=json.dumps(build_output__name))
    phantom.save_run_data(key="build_output:number", value=json.dumps(build_output__number))
    phantom.save_run_data(key="build_output:message", value=json.dumps(build_output__message))
    phantom.save_run_data(key="build_output:start_time", value=json.dumps(build_output__start_time))
    phantom.save_run_data(key="build_output:end_time", value=json.dumps(build_output__end_time))
    phantom.save_run_data(key="build_output:assignee", value=json.dumps(build_output__assignee))
    phantom.save_run_data(key="build_output:creator_name", value=json.dumps(build_output__creator_name))
    phantom.save_run_data(key="build_output:state", value=json.dumps(build_output__state))
    phantom.save_run_data(key="build_output:matched_fields", value=json.dumps(build_output__matched_fields))
    phantom.save_run_data(key="build_output:source_link", value=json.dumps(build_output__source_link))
    phantom.save_run_data(key="build_output:source", value=json.dumps(build_output__source))

    format_report(container=container)

    return


@phantom.playbook_block()
def calculate_earliest_time(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("calculate_earliest_time() called")

    create_time_value = container.get("create_time", None)

    parameters = []

    parameters.append({
        "input_datetime": create_time_value,
        "amount_to_modify": -30,
        "modification_unit": "days",
        "input_format_string": "%Y-%m-%d %H:%M:%S.%f+00",
        "output_format_string": "'%Y-%m-%d','%H:%M:%S'",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/datetime_modify", parameters=parameters, name="calculate_earliest_time", callback=input_filter)

    return


@phantom.playbook_block()
def run_ticket_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_ticket_query() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""sysparm_query=active=true^IR_OR_QUERY={0}^opened_at>javascript:gs.dateGenerate({1})&sysparm_display_value=true \n\n""",
        parameters=[
            "space_delimiter_input:formatted_data",
            "calculate_earliest_time:custom_function_result.data.datetime_string"
        ])

    ################################################################################
    # Perform a text search match within ServiceNow.
    ################################################################################

    calculate_earliest_time__result = phantom.collect2(container=container, datapath=["calculate_earliest_time:custom_function_result.data.datetime_string"])
    convert_table_list__result = phantom.collect2(container=container, datapath=["convert_table_list:custom_function_result.data.output"])
    space_delimiter_input = phantom.get_format_data(name="space_delimiter_input")

    parameters = []

    # build parameters list for 'run_ticket_query' call
    for calculate_earliest_time__result_item in calculate_earliest_time__result:
        for convert_table_list__result_item in convert_table_list__result:
            if query_formatted_string is not None and convert_table_list__result_item[0] is not None:
                parameters.append({
                    "query": query_formatted_string,
                    "max_results": 100,
                    "query_table": convert_table_list__result_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_ticket_query", assets=["servicenow"], callback=process_results)

    return


@phantom.playbook_block()
def format_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_report() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR retrieved tickets from Service Now. The table below shows a summary of the information gathered.\n\n| Name | Number | Message | Start Time | End Time | Assignee | Creator Name | State | Matched Fields | Source | Source Link |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n%%\n| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} | {10} |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "build_output:custom_function:name",
        "build_output:custom_function:number",
        "build_output:custom_function:message",
        "build_output:custom_function:start_time",
        "build_output:custom_function:end_time",
        "build_output:custom_function:assignee",
        "build_output:custom_function:creator_name",
        "build_output:custom_function:state",
        "build_output:custom_function:matched_fields",
        "build_output:custom_function:source",
        "build_output:custom_function:source_link"
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