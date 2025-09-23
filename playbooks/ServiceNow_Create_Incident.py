"""
This Playbook will take the output from automation run upstream in the playbook and send a report of that to a SNOW Incident of your choice. 
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'create_snow_incident' block
    create_snow_incident(container=container)

    return

@phantom.playbook_block()
def create_snow_incident(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_snow_incident() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # This will create a Service Now(SNOW) Incident and pass the Container Name as 
    # the Title of the incident and Description as the Description in the incident
    ################################################################################

    description_value = container.get("description", None)
    name_value = container.get("name", None)

    parameters = []

    parameters.append({
        "table": "incident",
        "description": description_value,
        "short_description": name_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create ticket", parameters=parameters, name="create_snow_incident", assets=["servicenow"], callback=add_snow_incident_number)

    return


@phantom.playbook_block()
def add_snow_incident_number(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_snow_incident_number() called")

    ################################################################################
    # This will add an artifact for the SNOW Incident in the SOAR Container that can 
    # be used later to update the SNOW incident with other actions take. 
    ################################################################################

    id_value = container.get("id", None)
    create_snow_incident_result_data = phantom.collect2(container=container, datapath=["create_snow_incident:action_result.data.*.number","create_snow_incident:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_snow_incident_number' call
    for create_snow_incident_result_item in create_snow_incident_result_data:
        parameters.append({
            "name": "Service Now Incident Create",
            "tags": None,
            "label": "create_snow_incident",
            "severity": None,
            "cef_field": "snow_incident",
            "cef_value": create_snow_incident_result_item[0],
            "container": id_value,
            "input_json": None,
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="add_snow_incident_number")

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