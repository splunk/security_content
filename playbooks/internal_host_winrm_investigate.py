"""
Published in response to CVE-2021-44228, this playbook performs a general investigation on key aspects of a windows device using windows remote management. Important files related to the endpoint are generated, bundled into a zip, and copied to the container vault.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_processes' block
    list_processes(container=container)

    return

def run_data_collect_script(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_data_collect_script() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Enumerates autoruns, installed programs, listening network connections, running 
    # processes, registered services, scheduled tasks, local users, and local groups. 
    # It then exports to CSV. Finally, all information is exported to zip.
    ################################################################################

    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])
    format_data_collect_script__as_list = phantom.get_format_data(name="format_data_collect_script__as_list")

    parameters = []

    # build parameters list for 'run_data_collect_script' call
    for playbook_input_ip_or_hostname_item in playbook_input_ip_or_hostname:
        parameters.append({
            "script_str": format_data_collect_script__as_list,
            "ip_hostname": playbook_input_ip_or_hostname_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []

    # build parameters list for 'run_data_collect_script' call
    for playbook_input_ip_or_hostname_item, formatted_part in zip(playbook_input_ip_or_hostname, format_data_collect_script__as_list):
            parameters.append({
                "script_str": formatted_part,
                "ip_hostname": playbook_input_ip_or_hostname_item[0],
            })


    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run script", parameters=parameters, name="run_data_collect_script", assets=["winrm"], callback=format_zip)

    return


def get_zip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_zip() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Fetches the zip created by the data capture script and uploads to vault.
    ################################################################################

    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])
    format_zip__as_list = phantom.get_format_data(name="format_zip__as_list")

    parameters = []

    # build parameters list for 'get_zip' call
    for playbook_input_ip_or_hostname_item in playbook_input_ip_or_hostname:
        if format_zip__as_list is not None:
            parameters.append({
                "file_path": format_zip__as_list,
                "ip_hostname": playbook_input_ip_or_hostname_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    parameters = []

    # build parameters list for 'get_zip' call
    for playbook_input_ip_or_hostname_item, formatted_part in zip(playbook_input_ip_or_hostname, format_zip__as_list):
        parameters.append({
            "ip_hostname": playbook_input_ip_or_hostname_item[0],
            "file_path": formatted_part,
        })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get file", parameters=parameters, name="get_zip", assets=["winrm"], callback=format_file_removal)

    return


def remove_data_capture_files(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("remove_data_capture_files() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Removes the temporary files created by the data collection script
    ################################################################################

    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])
    format_file_removal__as_list = phantom.get_format_data(name="format_file_removal__as_list")

    parameters = []

    # build parameters list for 'remove_data_capture_files' call
    for playbook_input_ip_or_hostname_item in playbook_input_ip_or_hostname:
        parameters.append({
            "script_str": format_file_removal__as_list,
            "ip_hostname": playbook_input_ip_or_hostname_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []

    # build parameters list for 'remove_data_capture_files' call
    for playbook_input_ip_or_hostname_item, formatted_part in zip(playbook_input_ip_or_hostname, format_file_removal__as_list):
        parameters.append({
            "script_str": formatted_part,
            "ip_hostname": playbook_input_ip_or_hostname_item[0],
        })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run script", parameters=parameters, name="remove_data_capture_files", assets=["winrm"])

    return


def format_data_collect_script(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_data_collect_script() called")

    template = """%%\n$ProgressPreference = 'SilentlyContinue'; Get-CimInstance -ClassName Win32_StartupCommand | Export-Csv -Path .\\{0}-SOARFetch-Autorun.csv -NoType; Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*  | Export-Csv -Path .\\{0}-SOARFetch-InstalledPrograms.csv -NoType; Get-NetTCPConnection -State Listen | Export-Csv -Path .\\{0}-SOARFetch-NetworkConnections.csv -NoType; Get-Process -IncludeUserName | Export-Csv -Path .\\{0}-SOARFetch-Processes.csv -NoType; Get-Service  | Export-Csv -Path .\\{0}-SOARFetch-Services.csv -NoType; Get-ScheduledTask  | Export-Csv -Path .\\{0}-SOARFetch-ScheduledTasks.csv -NoType; Get-LocalUser | Export-Csv -Path .\\{0}-SOARFetch-Users.csv -NoType; Get-LocalGroup | Export-Csv -Path .\\{0}-SOARFetch-Groups.csv -NoType; Compress-Archive -Path .\\{0}-SOARFetch* .\\{0}-SOARFetch.zip; \n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ip_or_hostname"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_data_collect_script")

    run_data_collect_script(container=container)

    return


def list_processes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_processes() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # List running processes
    ################################################################################

    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])

    parameters = []

    # build parameters list for 'list_processes' call
    for playbook_input_ip_or_hostname_item in playbook_input_ip_or_hostname:
        parameters.append({
            "ip_hostname": playbook_input_ip_or_hostname_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("list processes", parameters=parameters, name="list_processes", assets=["winrm"], callback=list_connections)

    return


def list_connections(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_connections() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # List current connections
    ################################################################################

    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])

    parameters = []

    # build parameters list for 'list_connections' call
    for playbook_input_ip_or_hostname_item in playbook_input_ip_or_hostname:
        parameters.append({
            "ip_hostname": playbook_input_ip_or_hostname_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("list connections", parameters=parameters, name="list_connections", assets=["winrm"], callback=list_sessions)

    return


def list_sessions(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_sessions() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # List active sessions
    ################################################################################

    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])

    parameters = []

    # build parameters list for 'list_sessions' call
    for playbook_input_ip_or_hostname_item in playbook_input_ip_or_hostname:
        parameters.append({
            "ip_hostname": playbook_input_ip_or_hostname_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("list sessions", parameters=parameters, name="list_sessions", assets=["winrm"], callback=format_data_collect_script)

    return


def format_zip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_zip() called")

    ################################################################################
    # Format a dynamic string where the ZIP is located.
    ################################################################################

    template = """%%\n.\\{0}-SOARFetch.zip\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ip_or_hostname"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_zip")

    get_zip(container=container)

    return


def format_file_removal(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_file_removal() called")

    ################################################################################
    # Format dynamic string for file removal
    ################################################################################

    template = """%%\nRemove-Item -Path .\\{0}-SOARFetch*\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ip_or_hostname"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_file_removal")

    remove_data_capture_files(container=container)

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