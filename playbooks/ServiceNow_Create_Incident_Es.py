"""
This Playbook was designed to be added to a Response Plan inside of Enterprise Security 8.x, to create a correlating SNOW incident and a custom field inside of the ES investigation to continue to track the investigation. 
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'create_snow_ticket' block
    create_snow_ticket(container=container)

    return

@phantom.playbook_block()
def create_snow_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_snow_ticket() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # This will create a Service Now ticket to track your Security Investigation in 
    # SNOW
    ################################################################################

    finding_data = phantom.collect2(container=container, datapath=["finding:consolidated_findings.source","finding:consolidated_findings.rule_title"])

    parameters = []

    # build parameters list for 'create_snow_ticket' call
    for finding_data_item in finding_data:
        parameters.append({
            "table": "incident",
            "description": finding_data_item[0],
            "short_description": finding_data_item[1],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create ticket", parameters=parameters, name="create_snow_ticket", assets=["servicenow"], callback=create_snow_ticket_callback)

    return


@phantom.playbook_block()
def create_snow_ticket_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_snow_ticket_callback() called")

    
    create_snow_incident_field(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    snow_ticket_number_note(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def create_snow_incident_field(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_snow_incident_field() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    #  We create this so that you can use it downstream with other ServiceNow playbooks 
    # to update the Snow Incident as you work thru the investigation.  
    ################################################################################

    create_snow_ticket_result_data = phantom.collect2(container=container, datapath=["create_snow_ticket:action_result.data.*.number","create_snow_ticket:action_result.parameter.context.artifact_id"], action_results=results)
    finding_data = phantom.collect2(container=container, datapath=["finding:id"])

    parameters = []

    # build parameters list for 'create_snow_incident_field' call
    for create_snow_ticket_result_item in create_snow_ticket_result_data:
        for finding_data_item in finding_data:
            if finding_data_item[0] is not None:
                parameters.append({
                    "pairs": [
                        { "name": "snow_incident", "value": create_snow_ticket_result_item[0] },
                    ],
                    "incident_id": finding_data_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("set custom fields", parameters=parameters, name="create_snow_incident_field", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def snow_ticket_number_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("snow_ticket_number_note() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""ServiceNow ticket created: {0}\n""",
        parameters=[
            "create_snow_ticket:action_result.data.*.number"
        ])

    ################################################################################
    # We add the Snow ticket number as a note in the Investigation (or Finding)
    ################################################################################

    finding_data = phantom.collect2(container=container, datapath=["finding:id"])
    create_snow_ticket_result_data = phantom.collect2(container=container, datapath=["create_snow_ticket:action_result.data.*.number","create_snow_ticket:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'snow_ticket_number_note' call
    for finding_data_item in finding_data:
        for create_snow_ticket_result_item in create_snow_ticket_result_data:
            if finding_data_item[0] is not None and content_formatted_string is not None:
                parameters.append({
                    "id": finding_data_item[0],
                    "title": "ServiceNow ticket created",
                    "content": content_formatted_string,
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add finding or investigation note", parameters=parameters, name="snow_ticket_number_note", assets=["builtin_mc_connector"])

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