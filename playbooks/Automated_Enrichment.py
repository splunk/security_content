"""
Moves the status to open and then launches the Dynamic playbooks for Reputation Analysis, Attribute Lookup, and Related Tickets.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'set_open_status' block
    set_open_status(container=container)

    return

@phantom.playbook_block()
def dynamic_identifier_reputation_analysis(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dynamic_identifier_reputation_analysis() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Dynamic_Identifier_Reputation_Analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Dynamic_Identifier_Reputation_Analysis", container=container)

    dynamic_attribute_lookup(container=container)

    return


@phantom.playbook_block()
def dynamic_attribute_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dynamic_attribute_lookup() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Dynamic_Attribute_Lookup", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Dynamic_Attribute_Lookup", container=container)

    dynamic_related_ticket_search(container=container)

    return


@phantom.playbook_block()
def dynamic_related_ticket_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dynamic_related_ticket_search() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Dynamic_Related_Tickets_Search", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Dynamic_Related_Tickets_Search", container=container)

    return


@phantom.playbook_block()
def set_open_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_open_status() called")

    ################################################################################
    # Change the event status to open before launching the playbooks.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="open")

    container = phantom.get_container(container.get('id', None))

    dynamic_identifier_reputation_analysis(container=container)

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