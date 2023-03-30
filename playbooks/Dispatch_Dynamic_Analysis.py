"""
Accepts a URL or vault_id and does reputation analysis on the objects. Generates a global report and a per observable sub-report and normalized score. The score can be customized based on a variety of factors.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'decision_1' block
    decision_1(container=container)

    return

@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
            ["artifact:*.cef.vaultId", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        dispatch_detonation_playbooks(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    artifacts_check_comment(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def dispatch_detonation_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_detonation_playbooks() called")

    inputs = {
        "playbook_repo": [],
        "playbook_tags": ["sandbox"],
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
    playbook_run_id = phantom.playbook("community/dispatch_input_playbooks", container=container, name="dispatch_detonation_playbooks", callback=decision_2, inputs=inputs)

    return


@phantom.playbook_block()
def artifacts_check_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifacts_check_comment() called")

    ################################################################################
    # no url or vault_id artifacts inputs
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="no url or vault_id artifacts inputs")

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["dispatch_detonation_playbooks:playbook_output:observable", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        normalized_observables_report(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    detonations_output_check_comment(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def merge_report_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_report_1() called")

    ################################################################################
    # summary report for all sandbox detonation input playbooks.
    ################################################################################

    template = """SOAR retrieved tickets from Splunk. The table below shows a summary of the information gathered.\\n\\n\n\n    | value | Score | Confidence | Source \n    | ---   | ---   | ---        | ---    \n    | \n    %%\n    {0}\n\n        \n"""

    # parameter list for template variable replacement
    parameters = [
        "normalized_observables_report:custom_function:sandbox_merge_report"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(phantom.format(container=container, template=template, parameters=parameters, name="merge_report_1"))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="merge_report_1")

    indicator_tag(container=container)

    return


@phantom.playbook_block()
def normalized_observables_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalized_observables_report() called")

    ################################################################################
    # This block uses custom code for normalizing observable result of input playbooks 
    # tag as sandbox. The normalized output will be used in merging 4 different types 
    # of sandbox used to detonated url or vault_id.
    ################################################################################

    dispatch_detonation_playbooks_output_observable = phantom.collect2(container=container, datapath=["dispatch_detonation_playbooks:playbook_output:observable"])

    dispatch_detonation_playbooks_output_observable_values = [item[0] for item in dispatch_detonation_playbooks_output_observable]

    normalized_observables_report__sandbox_merge_report = None
    normalized_observables_report__observable_value = None
    normalized_observables_report__observable_type = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    normalized_observables_report__sandbox_merge_report = []

    normalized_observables_report__observable_value = []
    normalized_observables_report__observable_type = []
    format_observable = ""
    output_observable_values =  [(i or "") for i in dispatch_detonation_playbooks_output_observable_values] 
    
    for observable_item in output_observable_values:
        if isinstance(observable_item, dict):
            normalized_observables_report__observable_value.append(observable_item['value'])
            normalized_observables_report__observable_type.append(observable_item['type'])
            format_observable += "{} | {} | {} | {} \n".format(observable_item['value'], observable_item['sandbox']['score'], observable_item['sandbox']['confidence'], observable_item['source'])
    normalized_observables_report__sandbox_merge_report.append(format_observable)
    
    #phantom.debug("{} len:{}".format(normalized_observables_report__sandbox_merge_report, len(normalized_observables_report__sandbox_merge_report)))
    normalized_observables_report__observable_value = normalized_observables_report__observable_value[0]
    normalized_observables_report__observable_type = normalized_observables_report__observable_type[0]

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalized_observables_report:sandbox_merge_report", value=json.dumps(normalized_observables_report__sandbox_merge_report))
    phantom.save_run_data(key="normalized_observables_report:observable_value", value=json.dumps(normalized_observables_report__observable_value))
    phantom.save_run_data(key="normalized_observables_report:observable_type", value=json.dumps(normalized_observables_report__observable_type))

    merge_report_1(container=container)

    return


@phantom.playbook_block()
def indicator_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_tag() called")

    normalized_observables_report__observable_type = json.loads(_ if (_ := phantom.get_run_data(key="normalized_observables_report:observable_type")) != "" else "null")  # pylint: disable=used-before-assignment
    normalized_observables_report__observable_value = json.loads(_ if (_ := phantom.get_run_data(key="normalized_observables_report:observable_value")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "tags": normalized_observables_report__observable_type,
        "indicator": normalized_observables_report__observable_value,
        "overwrite": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="indicator_tag", callback=workbook_update_task)

    return


@phantom.playbook_block()
def workbook_update_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_update_task() called")

    id_value = container.get("id", None)
    merge_report_1 = phantom.get_format_data(name="merge_report_1")

    parameters = []

    parameters.append({
        "owner": None,
        "status": "complete",
        "container": id_value,
        "task_name": "playbook",
        "note_title": "Automatic Dynamic Analysis Report",
        "note_content": merge_report_1,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="workbook_update_task")

    return


@phantom.playbook_block()
def detonations_output_check_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("detonations_output_check_comment() called")

    ################################################################################
    # observable output of detonation playbooks not exits.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="observable output of detonation playbooks not exits")

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