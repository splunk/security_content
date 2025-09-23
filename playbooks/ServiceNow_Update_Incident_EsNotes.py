"""
This ES Playbook will be added as the last phase in a response plan to send all the notes from an investigation to the SNOW incident created earlier in investigation.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'finding_and_investigation_notes' block
    finding_and_investigation_notes(container=container)

    return

@phantom.playbook_block()
def finding_and_investigation_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("finding_and_investigation_notes() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # This will retrieve that notes from your investigation. Not only the General 
    # notes but any notes in Response plans also. 
    ################################################################################

    finding_data = phantom.collect2(container=container, datapath=["finding:id"])

    parameters = []

    # build parameters list for 'finding_and_investigation_notes' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None:
            parameters.append({
                "id": finding_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get notes in finding or investigation", parameters=parameters, name="finding_and_investigation_notes", assets=["builtin_mc_connector"], callback=list_demux)

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
        "loop_convert_to_html:formatted_data.*"
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

    finding_data = phantom.collect2(container=container, datapath=["finding:custom_fields.snow_incident"])
    string_uri_decode__result = phantom.collect2(container=container, datapath=["string_uri_decode:custom_function_result.data.decoded_string"])

    parameters = []

    # build parameters list for 'update_servicenow_incident' call
    for finding_data_item in finding_data:
        for string_uri_decode__result_item in string_uri_decode__result:
            if finding_data_item[0] is not None:
                parameters.append({
                    "id": finding_data_item[0],
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

    phantom.act("update ticket", parameters=parameters, name="update_servicenow_incident", assets=["servicenow"])

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
def list_demux(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_demux() called")

    ################################################################################
    # We use to take the multiple notes that may be in a ES investigation and convert 
    # them into something we can loop thru and format better. 
    ################################################################################

    finding_and_investigation_notes_result_data = phantom.collect2(container=container, datapath=["finding_and_investigation_notes:action_result.data.*.items","finding_and_investigation_notes:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'list_demux' call
    for finding_and_investigation_notes_result_item in finding_and_investigation_notes_result_data:
        parameters.append({
            "input_list": finding_and_investigation_notes_result_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="list_demux", callback=loop_convert_to_html)

    return


@phantom.playbook_block()
def loop_convert_to_html(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("loop_convert_to_html() called")

    ################################################################################
    # This block loops thru the items in the ES notes and  converts the ES data to 
    # HTML which for service now looks better. 
    ################################################################################

    template = """[code]\n<h4>ES Notes</h4>\n%%\n<b>Task</b> {4}\n<br/><b>Author</b> {3}\n<br/><b>Created Time</b> {2}\n<br/><b>title</b> {1}\n<br/><b>content</b> {0}\n<br/><br/>\n%%\n[/code]"""

    # parameter list for template variable replacement
    parameters = [
        "list_demux:custom_function_result.data.output.content",
        "list_demux:custom_function_result.data.output.title",
        "list_demux:custom_function_result.data.output.create_time",
        "list_demux:custom_function_result.data.output.author.realname",
        "list_demux:custom_function_result.data.output.response_plan_info.response_task.name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="loop_convert_to_html")

    convert_note_to_json(container=container)

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