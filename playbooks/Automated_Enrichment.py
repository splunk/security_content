"""
Moves the status to open and then launches the Dispatch playbooks for Reputation Analysis, Attribute Lookup, and Related Tickets.
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
def identifier_reputation_analysis_dispatch(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("identifier_reputation_analysis_dispatch() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Identifier_Activity_Analysis_Dispatch", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Identifier_Activity_Analysis_Dispatch", container=container, name="identifier_reputation_analysis_dispatch", callback=attribute_lookup_dispatch)

    return


@phantom.playbook_block()
def attribute_lookup_dispatch(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("attribute_lookup_dispatch() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Attribute_Lookup_Dispatch", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Attribute_Lookup_Dispatch", container=container)

    related_ticket_search_dispatch(container=container)

    return


@phantom.playbook_block()
def related_ticket_search_dispatch(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("related_ticket_search_dispatch() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Related_Tickets_Search_Dispatch", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Related_Tickets_Search_Dispatch", container=container)

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

    identifier_reputation_analysis_dispatch(container=container)

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