"""
This playbook prepares a Risk Notable for investigation. First, it ensures that a &quot;Risk Notable&quot; links back to the original notable event with a card pinned to the HUD. It then posts a link to this container in the comment field of Enterprise Security. Finally, it updates the container name, description, and severity to reflect the data in the Notable artifact.\t
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'event_id_filter' block
    event_id_filter(container=container)

    return

def event_id_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("event_id_filter() called")

    ################################################################################
    # Only proceed if the event_id value is present. The event_id is also sometimes 
    # called a Notable ID.
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
        mark_evidence_artifact(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["artifact:*.cef.event_id", "!=", ""],
            ["artifact:*.name", "==", "Field Values"]
        ],
        name="event_id_filter:condition_2",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        artifact_update_notable(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


def artifact_update_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_update_notable() called")

    filtered_artifact_0_data_event_id_filter = phantom.collect2(container=container, datapath=["filtered-data:event_id_filter:condition_2:artifact:*.id","filtered-data:event_id_filter:condition_2:artifact:*.id"], scope="all")

    parameters = []

    # build parameters list for 'artifact_update_notable' call
    for filtered_artifact_0_item_event_id_filter in filtered_artifact_0_data_event_id_filter:
        parameters.append({
            "name": "Notable Artifact",
            "tags": None,
            "label": None,
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "input_json": None,
            "artifact_id": filtered_artifact_0_item_event_id_filter[0],
            "cef_data_type": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="artifact_update_notable")

    return


def mark_evidence_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("mark_evidence_artifact() called")

    id_value = container.get("id", None)
    filtered_artifact_0_data_event_id_filter = phantom.collect2(container=container, datapath=["filtered-data:event_id_filter:condition_1:artifact:*.id","filtered-data:event_id_filter:condition_1:artifact:*.id"], scope="all")

    parameters = []

    # build parameters list for 'mark_evidence_artifact' call
    for filtered_artifact_0_item_event_id_filter in filtered_artifact_0_data_event_id_filter:
        parameters.append({
            "container": id_value,
            "content_type": "artifact_id",
            "input_object": filtered_artifact_0_item_event_id_filter[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/mark_evidence", parameters=parameters, name="mark_evidence_artifact", callback=asset_get_splunk)

    return


def asset_get_splunk(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("asset_get_splunk() called")

    parameters = []

    parameters.append({
        "asset": "splunk",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/asset_get_attributes", parameters=parameters, name="asset_get_splunk", callback=asset_get_splunk_callback)

    return


def asset_get_splunk_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("asset_get_splunk_callback() called")

    
    format_es_url(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    format_es_note(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    format_event_name(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def format_es_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_es_url() called")

    ################################################################################
    # Format a URL for the link back to the Notable ID. Change the port number as 
    # needed.
    ################################################################################

    template = """https://{0}/en-US/app/SplunkEnterpriseSecuritySuite/incident_review?earliest={1}&latest=now&search=event_id%3D{2}"""

    # parameter list for template variable replacement
    parameters = [
        "asset_get_splunk:custom_function_result.data.configuration.device",
        "filtered-data:event_id_filter:condition_1:artifact:*.cef.info_min_time",
        "filtered-data:event_id_filter:condition_1:artifact:*.cef.event_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_es_url", scope="all")

    pin_es_url(container=container)

    return


def pin_es_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_es_url() called")

    ################################################################################
    # Pin the Enterprise Security URL
    ################################################################################

    format_es_url = phantom.get_format_data(name="format_es_url")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=format_es_url, message="Enterprise Security URL", name="es_url", pin_style="grey", pin_type="card")

    container = phantom.get_container(container.get('id', None))

    return


def format_es_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_es_note() called")

    ################################################################################
    # Format a note with the current event information.
    ################################################################################

    template = """SOAR event created: {0}\nComplete details can be found here: {1}/summary/evidence"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:url"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_es_note", scope="all")

    update_notable(container=container)

    return


def update_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_notable() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Update the notable event  in Enterprise Security with a link back to this container
    ################################################################################

    filtered_artifact_0_data_event_id_filter = phantom.collect2(container=container, datapath=["filtered-data:event_id_filter:condition_1:artifact:*.cef.event_id","filtered-data:event_id_filter:condition_1:artifact:*.id"], scope="all")
    format_es_note = phantom.get_format_data(name="format_es_note")

    parameters = []

    # build parameters list for 'update_notable' call
    for filtered_artifact_0_item_event_id_filter in filtered_artifact_0_data_event_id_filter:
        if filtered_artifact_0_item_event_id_filter[0] is not None:
            parameters.append({
                "status": "in progress",
                "comment": format_es_note,
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


def format_event_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_event_name() called")

    ################################################################################
    # Format the event name as 'Source: Risk Object'
    ################################################################################

    template = """{0}: {1}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:event_id_filter:condition_1:artifact:*.cef.source",
        "filtered-data:event_id_filter:condition_1:artifact:*.cef.risk_object"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_event_name", scope="all")

    container_update_info(container=container)

    return


def container_update_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("container_update_info() called")

    id_value = container.get("id", None)
    filtered_artifact_0_data_event_id_filter = phantom.collect2(container=container, datapath=["filtered-data:event_id_filter:condition_1:artifact:*.cef.urgency","filtered-data:event_id_filter:condition_1:artifact:*.cef.source","filtered-data:event_id_filter:condition_1:artifact:*.id"], scope="all")
    format_event_name = phantom.get_format_data(name="format_event_name")

    parameters = []

    # build parameters list for 'container_update_info' call
    for filtered_artifact_0_item_event_id_filter in filtered_artifact_0_data_event_id_filter:
        parameters.append({
            "name": format_event_name,
            "tags": None,
            "label": None,
            "owner": None,
            "status": None,
            "severity": filtered_artifact_0_item_event_id_filter[0],
            "input_json": None,
            "description": filtered_artifact_0_item_event_id_filter[1],
            "sensitivity": None,
            "container_input": id_value,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/container_update", parameters=parameters, name="container_update_info", callback=artifact_update_severity)

    return


def artifact_update_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_update_severity() called")

    filtered_artifact_0_data_event_id_filter = phantom.collect2(container=container, datapath=["filtered-data:event_id_filter:condition_1:artifact:*.cef.urgency","filtered-data:event_id_filter:condition_1:artifact:*.cef.risk_object","filtered-data:event_id_filter:condition_1:artifact:*.id","filtered-data:event_id_filter:condition_1:artifact:*.cef.risk_object_type","filtered-data:event_id_filter:condition_1:artifact:*.id"], scope="all")

    parameters = []

    # build parameters list for 'artifact_update_severity' call
    for filtered_artifact_0_item_event_id_filter in filtered_artifact_0_data_event_id_filter:
        parameters.append({
            "name": None,
            "tags": None,
            "label": None,
            "severity": filtered_artifact_0_item_event_id_filter[0],
            "cef_field": "risk_object",
            "cef_value": filtered_artifact_0_item_event_id_filter[1],
            "input_json": None,
            "artifact_id": filtered_artifact_0_item_event_id_filter[2],
            "cef_data_type": filtered_artifact_0_item_event_id_filter[3],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="artifact_update_severity")

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