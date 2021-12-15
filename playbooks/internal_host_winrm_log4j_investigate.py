"""
Published in response to CVE-2021-44228, this playbook scans the endpoint for the presence of &quot;jndilookup.class&quot; in all .jar, .jsp, and .jspx files. The presence of that string could indicate a log4j vulnerability.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'run_traversal_script' block
    run_traversal_script(container=container)

    return

def run_traversal_script(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_traversal_script() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Run a script to locate all drives and traverse them for the presence of the 
    # jndilookup.class
    ################################################################################

    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])

    parameters = []

    # build parameters list for 'run_traversal_script' call
    for playbook_input_ip_or_hostname_item in playbook_input_ip_or_hostname:
        parameters.append({
            "script_str": "$ProgressPreference = 'SilentlyContinue'; Get-PSDrive -PSProvider FileSystem | foreach {(gci ($_.Root) -rec -force -include ('*.jsp', '*.jspx', '*.jar') -ea 0 | foreach {select-string \"JndiLookup.class\" $_} | Select-Object -Property LineNumber, Path )} | ConvertTo-Json",
            "ip_hostname": playbook_input_ip_or_hostname_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run script", parameters=parameters, name="run_traversal_script", assets=["winrm"], callback=results_decision)

    return


def custom_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("custom_format() called")

    ################################################################################
    # Parse out the JSON returned by the traversal script
    ################################################################################

    run_traversal_script_result_data = phantom.collect2(container=container, datapath=["run_traversal_script:action_result.data.*.std_out"], action_results=results)
    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])

    run_traversal_script_result_item_0 = [item[0] for item in run_traversal_script_result_data]
    playbook_input_ip_or_hostname_values = [item[0] for item in playbook_input_ip_or_hostname]

    custom_format__note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    custom_format__note_content = ""
    for script_result_item, ip_hostname in zip(run_traversal_script_result_item_0, playbook_input_ip_or_hostname_values):
        try:
            custom_format__note_content += f"### Device - {ip_hostname}\n"
            custom_format__note_content += " | Path | LineNumber |\n"
            custom_format__note_content += "| --- | --- |\n"
            result_to_json = json.loads(script_result_item)
            for json_result in result_to_json:
                custom_format__note_content += f"| {json_result['Path']} | {json_result['LineNumber']} |\n"
            custom_format__note_content += "\n&nbsp;"
        except:
            phantom.error("Unable to parse JSON")
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="custom_format:note_content", value=json.dumps(custom_format__note_content))

    add_note_2(container=container)

    return


def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_2() called")

    custom_format__note_content = json.loads(phantom.get_run_data(key="custom_format:note_content"))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=custom_format__note_content, note_format="markdown", note_type="general", title="Evidence of jndilookup.class for CVE-2021-44228")

    return


def results_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("results_decision() called")

    ################################################################################
    # Only proceed if stdout has results
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["run_traversal_script:action_result.data.*.std_out", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        custom_format(action=action, success=success, container=container, results=results, handle=handle)
        return

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