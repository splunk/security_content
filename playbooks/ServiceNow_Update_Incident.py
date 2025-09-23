"""
This Playbook will take the output from automation run upstream in the playbook and send a report of that to a SNOW Incident of your choice. 
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'check_local_snow_incident' block
    check_local_snow_incident(container=container)

    return

@phantom.playbook_block()
def snow_format_incident_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("snow_format_incident_query() called")

    ################################################################################
    # This will format a query to look for SNOW incidents over the last 7 days for 
    # a entity in a detection
    ################################################################################

    template = """cmdb_ci.name={0}^sys_created_onONLast%207%20days\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:entity"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="snow_format_incident_query")

    list_snow_tickets(container=container)

    return


@phantom.playbook_block()
def list_snow_tickets(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_snow_tickets() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # this will list the SNOW Incidents relating to affected entity in the detection. 
    # 
    ################################################################################

    snow_format_incident_query = phantom.get_format_data(name="snow_format_incident_query")

    parameters = []

    parameters.append({
        "table": "incident",
        "filter": snow_format_incident_query,
        "max_results": 100,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("list tickets", parameters=parameters, name="list_snow_tickets", assets=["servicenow"], callback=snow_incident_markdown)

    return


@phantom.playbook_block()
def snow_incident_markdown(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("snow_incident_markdown() called")

    ################################################################################
    # This will give you a table of the SNOW incidents related to the detection entity 
    # affected.
    ################################################################################

    template = """#### SNOW Related Incidents\n| Ticket Number | Short Description | ID | Severity | Priority | Opened On | Closed On |\n| --- | --- | --- | --- | --- | --- | --- | \n%%\n| {0} | {1} | {2} | {3} | {4} | {5} | {6} | \n%%"""

    # parameter list for template variable replacement
    parameters = [
        "list_snow_tickets:action_result.data.*.number",
        "list_snow_tickets:action_result.data.*.short_description",
        "list_snow_tickets:action_result.data.*.sys_id",
        "list_snow_tickets:artifact:*.severity",
        "list_snow_tickets:action_result.data.*.priority",
        "list_snow_tickets:action_result.data.*.opened_at",
        "list_snow_tickets:action_result.data.*.closed_at"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="snow_incident_markdown")

    input_snow_incident(container=container)

    return


@phantom.playbook_block()
def input_snow_incident(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("input_snow_incident() called")

    ################################################################################
    # this will operate two queries. 
    # 1. Query ES or SOAR for Snow Incident in the investigation or case already documented
    # 2. Query the SNOW incidents 
    # 
    # Then prompt our user that submitted the automation to input the SNOW incident 
    # they want to update. 
    ################################################################################

    # set approver and message variables for phantom.prompt call

    user = phantom.collect2(container=container, datapath=["playbook:launching_user.name"])[0][0]
    role = None
    message = """Associated Service Now Incidents\n{0}"""

    # parameter list for template variable replacement
    parameters = [
        "snow_incident_markdown:formatted_data",
        "playbook_input:snow_incident"
    ]

    # responses
    response_types = [
        {
            "prompt": "Add Snow Incident number",
            "options": {
                "type": "message",
                "required": True,
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="input_snow_incident", parameters=parameters, response_types=response_types, callback=convert_note_to_json)

    return


@phantom.playbook_block()
def convert_note_to_json(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("convert_note_to_json() called")

    ################################################################################
    # this takes the Observables from SOAR automation and converts to json fromat 
    # that SOAR will accept. 
    ################################################################################

    template = """{{\"comments\":\"{0}\"}}\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:note"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="convert_note_to_json")

    string_remove_crlf(container=container)

    return


@phantom.playbook_block()
def string_remove_crlf(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("string_remove_crlf() called")

    ################################################################################
    # Remove any \n characters from the input string
    ################################################################################

    convert_note_to_json = phantom.get_format_data(name="convert_note_to_json")

    parameters = []

    parameters.append({
        "input_string": convert_note_to_json,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/string_remove_crlf", parameters=parameters, name="string_remove_crlf", callback=string_uri_decode)

    return


@phantom.playbook_block()
def update_servicenow_incident(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_servicenow_incident() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    fields_formatted_string = phantom.format(
        container=container,
        template="""{0}\n""",
        parameters=[
            "string_uri_decode:custom_function_result.data.decoded_string"
        ])

    ################################################################################
    # This will input the note that was configured to be sent from parent playbook 
    # in the start block to the Service Now Incident. 
    ################################################################################

    input_snow_incident_result_data = phantom.collect2(container=container, datapath=["input_snow_incident:action_result.summary.responses.0","input_snow_incident:action_result.parameter.context.artifact_id"], action_results=results)
    string_uri_decode__result = phantom.collect2(container=container, datapath=["string_uri_decode:custom_function_result.data.decoded_string"])

    parameters = []

    # build parameters list for 'update_servicenow_incident' call
    for input_snow_incident_result_item in input_snow_incident_result_data:
        for string_uri_decode__result_item in string_uri_decode__result:
            if input_snow_incident_result_item[0] is not None:
                parameters.append({
                    "id": input_snow_incident_result_item[0],
                    "table": "incident",
                    "fields": fields_formatted_string,
                    "context": {'artifact_id': input_snow_incident_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update ticket", parameters=parameters, name="update_servicenow_incident", assets=["servicenow"])

    return


@phantom.playbook_block()
def check_local_snow_incident(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("check_local_snow_incident() called")

    ################################################################################
    # Looks for snow_incident field
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_input:snow_incident", "!=", ""]
        ],
        conditions_dps=[
            ["playbook_input:snow_incident", "!=", ""]
        ],
        name="check_local_snow_incident:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        convert_note_to_json2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    snow_format_incident_query(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def convert_note_to_json2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("convert_note_to_json2() called")

    ################################################################################
    # this takes the Observables from SOAR automation and converts to json fromat 
    # that SOAR will accept. 
    ################################################################################

    template = """{{\"comments\":\"{0}\"}}\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:note"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="convert_note_to_json2")

    string_remove_crlf_2(container=container)

    return


@phantom.playbook_block()
def string_remove_crlf_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("string_remove_crlf_2() called")

    ################################################################################
    # Remove any \n characters from the input string
    ################################################################################

    convert_note_to_json2 = phantom.get_format_data(name="convert_note_to_json2")

    parameters = []

    parameters.append({
        "input_string": convert_note_to_json2,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/string_remove_crlf", parameters=parameters, name="string_remove_crlf_2", callback=stiring_uri_decode2)

    return


@phantom.playbook_block()
def update_servicenow_incident_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_servicenow_incident_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    fields_formatted_string = phantom.format(
        container=container,
        template="""{0}\n""",
        parameters=[
            "stiring_uri_decode2:custom_function_result.data.decoded_string"
        ])

    ################################################################################
    # This will input the note that was configured to be sent from parent playbook 
    # in the start block to the Service Now Incident. 
    ################################################################################

    playbook_input_snow_incident = phantom.collect2(container=container, datapath=["playbook_input:snow_incident"])
    stiring_uri_decode2__result = phantom.collect2(container=container, datapath=["stiring_uri_decode2:custom_function_result.data.decoded_string"])

    parameters = []

    # build parameters list for 'update_servicenow_incident_2' call
    for playbook_input_snow_incident_item in playbook_input_snow_incident:
        for stiring_uri_decode2__result_item in stiring_uri_decode2__result:
            if playbook_input_snow_incident_item[0] is not None:
                parameters.append({
                    "id": playbook_input_snow_incident_item[0],
                    "table": "incident",
                    "fields": fields_formatted_string,
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update ticket", parameters=parameters, name="update_servicenow_incident_2", assets=["servicenow"])

    return


@phantom.playbook_block()
def string_uri_decode(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("string_uri_decode() called")

    ################################################################################
    # Remove any uri encoding
    ################################################################################

    string_remove_crlf__result = phantom.collect2(container=container, datapath=["string_remove_crlf:custom_function_result.data.sanitized_string"])

    parameters = []

    # build parameters list for 'string_uri_decode' call
    for string_remove_crlf__result_item in string_remove_crlf__result:
        parameters.append({
            "input_string": string_remove_crlf__result_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/string_uri_decode", parameters=parameters, name="string_uri_decode", callback=update_servicenow_incident)

    return


@phantom.playbook_block()
def stiring_uri_decode2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("stiring_uri_decode2() called")

    ################################################################################
    # Remove any uri encoding
    ################################################################################

    string_remove_crlf_2__result = phantom.collect2(container=container, datapath=["string_remove_crlf_2:custom_function_result.data.sanitized_string"])

    parameters = []

    # build parameters list for 'stiring_uri_decode2' call
    for string_remove_crlf_2__result_item in string_remove_crlf_2__result:
        parameters.append({
            "input_string": string_remove_crlf_2__result_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/string_uri_decode", parameters=parameters, name="stiring_uri_decode2", callback=update_servicenow_incident_2)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return