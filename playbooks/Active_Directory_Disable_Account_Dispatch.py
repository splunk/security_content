"""
Accepts user name that needs to be disabled in Active Directory. Generates a report and observable output based on the status of account locking or disabling.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'username_filter' block
    username_filter(container=container)

    return

@phantom.playbook_block()
def dispatch_account_disable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_account_disable() called")

    inputs = {
        "playbook_repo": [],
        "playbook_tags": ["disable_account"],
        "artifact_ids_include": [],
        "indicator_tags_exclude": [],
        "indicator_tags_include": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/dispatch_input_playbooks", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/dispatch_input_playbooks", container=container, name="dispatch_account_disable", callback=observable_output_filter, inputs=inputs)

    return


@phantom.playbook_block()
def username_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("username_filter() called")

    ################################################################################
    # Filter user name inputs to route inputs to appropriate actions.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.act", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        dispatch_account_disable(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    artifacts_check_comment(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def artifacts_check_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifacts_check_comment() called")

    ################################################################################
    # no valid username or user principal name artifacts input
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="no valid username or user principal name artifacts input")

    return


@phantom.playbook_block()
def observable_output_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("observable_output_filter() called")

    ################################################################################
    # Filter to check if observable output is successfully generated or not.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["dispatch_account_disable:playbook_output:observable", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        normalized_observable_filter(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    observable_check_comment(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def normalized_observable_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalized_observable_filter() called")

    ################################################################################
    # This block uses custom code for normalizing observable result of input playbooks 
    # tag as disable_account. The normalized output will be used in merging 4 different 
    # types of disable_account used to locked users in active directory.
    ################################################################################

    dispatch_account_disable_output_observable = phantom.collect2(container=container, datapath=["dispatch_account_disable:playbook_output:observable"])

    dispatch_account_disable_output_observable_values = [item[0] for item in dispatch_account_disable_output_observable]

    normalized_observable_filter__observable_value = None
    normalized_observable_filter__observable_type = None
    normalized_observable_filter__observable_merge_report = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    normalized_observable_filter__observable_message = []
    normalized_observable_filter__observable_value = []
    normalized_observable_filter__observable_merge_report = []
    fmt_output = ""
    output_observable_values =  [(i or "") for i in dispatch_account_disable_output_observable_values]
    
    #phantom.debug("output_observable_values: {}".format(output_observable_values))
    for observable_item in output_observable_values:
        if observable_item['status'] == "success":
            user_name = observable_item['value'].split("@")[0]
            normalized_observable_filter__observable_value.append(user_name)
            fmt_output += "{} | {} | {} | {} | \n".format(observable_item['value'], observable_item['type'], observable_item['message'], observable_item['status'])
            normalized_observable_filter__observable_merge_report.append(fmt_output)
    normalized_observable_filter__observable_value = normalized_observable_filter__observable_value[0]
    normalized_observable_filter__observable_type = "Disable Account"
    #phantom.debug(normalized_observable_filter__observable_merge_report)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalized_observable_filter:observable_value", value=json.dumps(normalized_observable_filter__observable_value))
    phantom.save_run_data(key="normalized_observable_filter:observable_type", value=json.dumps(normalized_observable_filter__observable_type))
    phantom.save_run_data(key="normalized_observable_filter:observable_merge_report", value=json.dumps(normalized_observable_filter__observable_merge_report))

    merge_report(container=container)

    return


@phantom.playbook_block()
def observable_check_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("observable_check_comment() called")

    ################################################################################
    # observable output of input playbooks not exits.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="observable output of input playbooks not exits.")

    return


@phantom.playbook_block()
def merge_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_report() called")

    ################################################################################
    # summary report for all disable account input playbooks.
    ################################################################################

    template = """SOAR retrieved tickets from Splunk. The table below shows a summary of the information gathered.\\n\\n\n| value | type | message | status |\n| --- | --- | --- | --- |\n%%\n| {0}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "normalized_observable_filter:custom_function:observable_merge_report"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug(phantom.format(container=container, template=template, parameters=parameters, name="merge_report"))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="merge_report")

    tag_indicators(container=container)

    return


@phantom.playbook_block()
def tag_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("tag_indicators() called")

    ################################################################################
    # adding indicator tag for each disabled account.
    ################################################################################

    normalized_observable_filter__observable_type = json.loads(_ if (_ := phantom.get_run_data(key="normalized_observable_filter:observable_type")) != "" else "null")  # pylint: disable=used-before-assignment
    normalized_observable_filter__observable_value = json.loads(_ if (_ := phantom.get_run_data(key="normalized_observable_filter:observable_value")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "tags": normalized_observable_filter__observable_type,
        "indicator": normalized_observable_filter__observable_value,
        "overwrite": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="tag_indicators", callback=update_workbook_task)

    return


@phantom.playbook_block()
def update_workbook_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_workbook_task() called")

    ################################################################################
    # update workbook task of this dispatch playbook
    ################################################################################

    id_value = container.get("id", None)
    merge_report = phantom.get_format_data(name="merge_report")

    parameters = []

    parameters.append({
        "owner": None,
        "status": "complete",
        "container": id_value,
        "task_name": "playbook",
        "note_title": "AD Disable Account Report",
        "note_content": merge_report,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="update_workbook_task")

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