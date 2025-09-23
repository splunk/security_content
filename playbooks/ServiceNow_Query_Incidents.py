"""
This will query your SNOW Incident table looking for incidents that have a cmdb_ci entry that matches your affected entity in the detections from ES or SOAR and give a report of the found SNOW Incidents 
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'snow_format_incident_query' block
    snow_format_incident_query(container=container)

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

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    snow_incident_markdown = phantom.get_format_data(name="snow_incident_markdown")

    output = {
        "snow_tickets": snow_incident_markdown,
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