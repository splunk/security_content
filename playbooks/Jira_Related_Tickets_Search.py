"""
Accepts a user or device and identifies if related tickets exists in a timeframe of last 30 days. Generates a global report and list of observables.
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
        name="input_filter:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        escape_input(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def process_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("process_results() called")

    ################################################################################
    # Iterates through the results of the run ticket query to link playbook input 
    # search term to their associated tickets.
    ################################################################################

    filtered_input_0_search_term = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_1:playbook_input:search_term"])
    run_ticket_query_result_data = phantom.collect2(container=container, datapath=["run_ticket_query:action_result.data"], action_results=results)

    filtered_input_0_search_term_values = [item[0] for item in filtered_input_0_search_term]
    run_ticket_query_result_item_0 = [item[0] for item in run_ticket_query_result_data]

    process_results__output = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    import re
    from collections import Counter

    def traverse_string_in_structure(data):
        """
        Return all strings in a Python data structure.

        Input: a Python data structure.
            If the input is a string, it is returned.
            If the input is a dictionary, all its values are traversed recursively.
            If the input is a list or tuple, all its items are traversed recursively.
            For other input types, they are not traversed.
        """
        if type(data) == str:
            yield data
        elif type(data) == dict:
            for i in data.values():
                yield from traverse_string_in_structure(i)
        elif type(data) in [list, tuple]:
            for i in data:
                yield from traverse_string_in_structure(i)
        else:
            pass

    def match_string_in_structure(search_term, data):
        """
        Look for exact match of a search term in a Python data structure.

        Input:
            search_term: text to be searched, case insensitive.
            data: a Python data structure to be searched, see traverse_string_in_structure().

        Output: A boolean value indicating whether search_term is found in data.
        """
        for i in traverse_string_in_structure(data):
            if search_term.lower() in i.lower():
                return True
        return False

    def match_string_in_jira_ticket(search_term, ticket):
        """
        Look for exact match of a search term in a Jira ticket.

        Input:
            search_term: text to be searched, case insensitive.
            ticket: a dictionary returned from the "list tickets" Jira action. Example:
            {
                "id": "1234567",
                "name": "JIRA-890",
                "fields": {
                    "votes": {...},
                    "security": null,
                    "customfield_1234": "Please fix JIRA-890",
                    "customfield_1235": null,
                    "customfield_1236": null,
                    ...
                },
                ...
            }

        Output: A list of field names in which the search term is found. e.g. ['name', 'votes', 'customfield_1234']
            Most field names can be accessed in ticket['fields'][field_name], with the exception that 'name' can be found in ticket['name'].
        """

        found_fields = []

        # Handle the exception ticket['name']
        if match_string_in_structure(search_term, ticket['name']):
            found_fields.append('name')

        # Handle ticket['fields'][field_name]
        for key, value in ticket['fields'].items():
            if match_string_in_structure(search_term, ticket['fields'][key]):
                found_fields.append(key)

        return found_fields

    def guess_jira_ticket_link(ticket):
        """
        Guess the link to Jira ticket.

        This function searches the ticket data structure for Jira host name. Then it constructs the link using the /browse/ endpoint.

        Input: a dictionary returned from the "list tickets" Jira action. Example:
            {
                "id": "1234567",
                "name": "JIRA-890",
                "fields": {...},
                ...
            }
        Output: a URL that points to the ticket, e.g. "https://jira.example.com/browse/JIRA-890"
        """

        origins = Counter()
        for i in traverse_string_in_structure(ticket):
            matched = re.match('https?:\/\/[^\/]+/', i)
            if matched is not None:
                origins[matched.group()] += 1
        try:
            origin = origins.most_common()[0][0]
            return f'{origin}browse/{ticket["name"]}'
        except (KeyError, IndexError):
            return None

    # Group tickets based on search term.
    process_results__output = {}
    for search_term in filtered_input_0_search_term_values:
        process_results__output[search_term] = []
        for ticket_list in run_ticket_query_result_item_0:
            for ticket in ticket_list:
                matched_fields = match_string_in_jira_ticket(search_term, ticket)
                if matched_fields:
                    process_results__output[search_term].append({
                        **ticket,
                        "matched_fields": matched_fields,
                        "source_link": guess_jira_ticket_link(ticket),
                    })

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
    # Extracts relevant data and add them to an observable array.
    ################################################################################

    process_results__output = json.loads(_ if (_ := phantom.get_run_data(key="process_results:output")) != "" else "null")  # pylint: disable=used-before-assignment

    build_output__observable_array = None
    build_output__summary = None
    build_output__name = None
    build_output__description = None
    build_output__create_time = None
    build_output__updated_time = None
    build_output__assignee = None
    build_output__reporter = None
    build_output__status = None
    build_output__ticket_type = None
    build_output__priority = None
    build_output__resolution = None
    build_output__matched_fields = None
    build_output__source_link = None
    build_output__source = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    def markdown_escape(string):
        """
        Escape a string in Markdown.

        Input: a string or an object that can be converted to string using str(). e.g. "index=* | top"
        Output: escaped string. e.g. "index=\* \| top"
        """

        # Must keep '\\' in the first, because it is used to escape other characters
        special_chars = ['\\', '`', '*', '_', '{', '}', '[', ']', '<', '>', '(', ')', '#', '+', '-', '.', '!', '|']
        ans = str(string)
        for i in special_chars:
            ans = ans.replace(i, '\\' + i)
        return ans

    build_output__observable_array = []
    build_output__summary = []
    build_output__name = []
    build_output__description = []
    build_output__create_time = []
    build_output__updated_time = []
    build_output__assignee = []
    build_output__reporter = []
    build_output__status = []
    build_output__ticket_type = []
    build_output__priority = []
    build_output__resolution = []
    build_output__matched_fields = []
    build_output__source_link = []
    build_output__source = []

    for key in process_results__output.keys():
        
        for value in process_results__output[key]:
            # Extract fields from ticket object.
            ticket = {}
            ticket['summary'] = value.get('summary')
            ticket['name'] = value.get('name')
            ticket['description'] = json.dumps(value['description'])  # eliminate new line issues
            ticket['create_time'] = value['fields'].get('created')
            ticket['updated_time'] = value['fields'].get('updated')
            asignee_dict = value['fields'].get('assignee')
            if asignee_dict is not None:
                ticket['assignee'] = asignee_dict.get('displayName', '')
            else:
                ticket['assignee'] = ''
            ticket['reporter'] = value.get('reporter')
            ticket['status'] = value.get('status')
            ticket['ticket_type'] = value.get('issue_type')
            ticket['priority'] = value.get('priority')
            ticket['resolution'] = value.get('resolution')
            ticket['matched_fields'] = value.get('matched_fields')
            ticket['source_link'] = value.get('source_link')
            ticket['source'] = 'Jira'

            # Extract comments (only included in the observable object, not in other output variables).
            ticket['comments'] = []
            for comment in value['fields']['comment']['comments']:
                ticket['comments'].append(comment['body'])
            
            # Construct observable object
            observable_object = {
                "value": key,
                "ticket": {
                    'name': markdown_escape(ticket['summary']),
                    'number': markdown_escape(ticket['name']),
                    'message': markdown_escape(ticket['description']),
                    'start_time': markdown_escape(ticket['create_time']),
                    'updated_time': markdown_escape(ticket['updated_time']),
                    'end_time': '',
                    'assignee': markdown_escape(ticket['assignee']),
                    'creator_name': markdown_escape(ticket['reporter']),
                    'state': markdown_escape(ticket['status']),
                    'ticket_type': markdown_escape(ticket['ticket_type']),
                    'priority': markdown_escape(ticket['priority']),
                    'resolution': markdown_escape(ticket['resolution']),
                },
                "matched_fields": value['matched_fields'],
                "source": ticket['source'],
                "source_link": ticket['source_link']
            }

            # Add results to VPE code output
            build_output__observable_array.append(observable_object)
            build_output__summary.append(markdown_escape(ticket['summary']))
            build_output__name.append(markdown_escape(ticket['name']))
            build_output__description.append(markdown_escape(ticket['description']))
            build_output__create_time.append(markdown_escape(ticket['create_time']))
            build_output__updated_time.append(markdown_escape(ticket['updated_time']))
            build_output__assignee.append(markdown_escape(ticket['assignee']))
            build_output__reporter.append(markdown_escape(ticket['reporter']))
            build_output__status.append(markdown_escape(ticket['status']))
            build_output__ticket_type.append(markdown_escape(ticket['ticket_type']))
            build_output__priority.append(markdown_escape(ticket['priority']))
            build_output__resolution.append(markdown_escape(ticket['resolution']))
            build_output__matched_fields.append(markdown_escape(ticket['matched_fields']))
            build_output__source_link.append(markdown_escape(ticket['source_link']))
            build_output__source.append(markdown_escape(ticket['source']))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_output:observable_array", value=json.dumps(build_output__observable_array))
    phantom.save_run_data(key="build_output:summary", value=json.dumps(build_output__summary))
    phantom.save_run_data(key="build_output:name", value=json.dumps(build_output__name))
    phantom.save_run_data(key="build_output:description", value=json.dumps(build_output__description))
    phantom.save_run_data(key="build_output:create_time", value=json.dumps(build_output__create_time))
    phantom.save_run_data(key="build_output:updated_time", value=json.dumps(build_output__updated_time))
    phantom.save_run_data(key="build_output:assignee", value=json.dumps(build_output__assignee))
    phantom.save_run_data(key="build_output:reporter", value=json.dumps(build_output__reporter))
    phantom.save_run_data(key="build_output:status", value=json.dumps(build_output__status))
    phantom.save_run_data(key="build_output:ticket_type", value=json.dumps(build_output__ticket_type))
    phantom.save_run_data(key="build_output:priority", value=json.dumps(build_output__priority))
    phantom.save_run_data(key="build_output:resolution", value=json.dumps(build_output__resolution))
    phantom.save_run_data(key="build_output:matched_fields", value=json.dumps(build_output__matched_fields))
    phantom.save_run_data(key="build_output:source_link", value=json.dumps(build_output__source_link))
    phantom.save_run_data(key="build_output:source", value=json.dumps(build_output__source))

    format_success_report(container=container)

    return


@phantom.playbook_block()
def run_ticket_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_ticket_query() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Performs a text search match within Jira.
    ################################################################################

    build_query = phantom.get_format_data(name="build_query")

    parameters = []

    parameters.append({
        "query": build_query,
        "max_results": 1000,
        "start_index": 0,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("list tickets", parameters=parameters, name="run_ticket_query", assets=["jira"], callback=handle_query_error)

    return


@phantom.playbook_block()
def format_success_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_success_report() called")

    ################################################################################
    # Formats a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR retrieved tickets from Jira. The table below shows a summary of the information gathered.\n\n| Summary | Name | Description | Create Time | Update Time | Assignee | Reporter | Status | Type | Priority | Resolution | Matched Fields | Source | Source Link |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n%%\n| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} | {10} | {11} | {12} | {13} |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "build_output:custom_function:summary",
        "build_output:custom_function:name",
        "build_output:custom_function:description",
        "build_output:custom_function:create_time",
        "build_output:custom_function:updated_time",
        "build_output:custom_function:assignee",
        "build_output:custom_function:reporter",
        "build_output:custom_function:status",
        "build_output:custom_function:ticket_type",
        "build_output:custom_function:priority",
        "build_output:custom_function:resolution",
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

    phantom.format(container=container, template=template, parameters=parameters, name="format_success_report")

    join_combine_reports(container=container)

    return


@phantom.playbook_block()
def escape_input(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("escape_input() called")

    ################################################################################
    # Escapes the input strings to be added to JQL.
    ################################################################################

    filtered_input_0_search_term = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_1:playbook_input:search_term"])

    filtered_input_0_search_term_values = [item[0] for item in filtered_input_0_search_term]

    escape_input__search_term = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    def escape_search_term(search_term):
        """
        Escape a string to allow it to be passed as part of JQL.

        This function escapes the following characters: "'", '"', '\t', '\n', '\r', and '\\'.

        Example:
            Function input: search_term="abc'def"
            Function return value: r"abc\\\'def"
            Intended JQL snippet: r'''text ~ "\"abc\\\'def\""'''
        """
        ans = search_term
        # Note: escape backslash ('\\') at the beginning, since other escapes generate backslash.
        ans = ans.replace('\\', r"\\\\")
        ans = ans.replace('\t', r'\\\t')
        ans = ans.replace('\n', r'\\\n')
        ans = ans.replace('\r', r'\\\r')
        ans = ans.replace('\"', r'\\\"')
        ans = ans.replace("\'", r"\\\'")
        return ans

    escape_input__search_term = []
    for i in filtered_input_0_search_term_values:
        escape_input__search_term.append(escape_search_term(i))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="escape_input:search_term", value=json.dumps(escape_input__search_term))

    build_query(container=container)

    return


@phantom.playbook_block()
def build_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_query() called")

    ################################################################################
    # Converts playbook input into a JQL query. The query searches for issues created 
    # less than 30 days ago that match at least one playbook input keyword.
    # 
    # The delimiter is set to '\"" OR text ~ "\"', so when multiple inputs are provided 
    # to the playbook, the request queries all keywords using OR in JQL.
    ################################################################################

    template = """(text ~ \"\\\"{0}\\\"\") AND created > -30d"""

    # parameter list for template variable replacement
    parameters = [
        "escape_input:custom_function:search_term"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="build_query", separator="\\\"\" OR text ~ \"\\\"", drop_none=True)

    run_ticket_query(container=container)

    return


@phantom.playbook_block()
def format_error_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_error_report() called")

    ################################################################################
    # Formats a report that contains error message from the run ticket query action.
    ################################################################################

    template = """SOAR is unable to retrieve tickets from Jira. Error message from Jira:\n```\n{0}\n```"""

    # parameter list for template variable replacement
    parameters = [
        "run_ticket_query:action_result.message"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_error_report")

    join_combine_reports(container=container)

    return


@phantom.playbook_block()
def handle_query_error(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("handle_query_error() called")

    ################################################################################
    # Checks whether the run ticket query action returns an error.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["run_ticket_query:action_result.status", "==", "success"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        process_results(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_error_report(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def join_combine_reports(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_combine_reports() called")

    if phantom.completed(action_names=["run_ticket_query"]):
        # call connected block "combine_reports"
        combine_reports(container=container, handle=handle)

    return


@phantom.playbook_block()
def combine_reports(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("combine_reports() called")

    ################################################################################
    # Combines reports from success path and error path.
    ################################################################################

    template = """{0}{1}"""

    # parameter list for template variable replacement
    parameters = [
        "format_success_report:formatted_data",
        "format_error_report:formatted_data"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="combine_reports", drop_none=True)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    combine_reports = phantom.get_format_data(name="combine_reports")
    build_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "observable": build_output__observable_array,
        "markdown_report": combine_reports,
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