"""
Published in response to CVE-2021-44228, this playbook investigates an internal unix host using SSH. This pushes a bash script to the endpoint and runs it, collecting generic information about the processes, user activity, and network activity. This includes the process list, login history, cron jobs, and open sockets. The results are zipped up in .csv files and added to the vault for an analyst to review.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_processes_1' block
    list_processes_1(container=container)
    # call 'list_connections_1' block
    list_connections_1(container=container)
    # call 'list_firewall_rules_1' block
    list_firewall_rules_1(container=container)
    # call 'write_embedded_bash_script_to_vault' block
    write_embedded_bash_script_to_vault(container=container)

    return

def list_processes_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_processes_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])

    parameters = []

    # build parameters list for 'list_processes_1' call
    for playbook_input_ip_or_hostname_item in playbook_input_ip_or_hostname:
        if playbook_input_ip_or_hostname_item[0] is not None:
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

    phantom.act("list processes", parameters=parameters, name="list_processes_1", assets=["ssh"])

    return


def list_connections_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_connections_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])

    parameters = []

    # build parameters list for 'list_connections_1' call
    for playbook_input_ip_or_hostname_item in playbook_input_ip_or_hostname:
        if playbook_input_ip_or_hostname_item[0] is not None:
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

    phantom.act("list connections", parameters=parameters, name="list_connections_1", assets=["ssh"])

    return


def list_firewall_rules_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_firewall_rules_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])

    parameters = []

    # build parameters list for 'list_firewall_rules_1' call
    for playbook_input_ip_or_hostname_item in playbook_input_ip_or_hostname:
        if playbook_input_ip_or_hostname_item[0] is not None:
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

    phantom.act("list firewall rules", parameters=parameters, name="list_firewall_rules_1", assets=["ssh"])

    return


def write_embedded_bash_script_to_vault(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("write_embedded_bash_script_to_vault() called")

    parameters = []

    parameters.append({
        "input_1": None,
        "input_2": None,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    bash_script = r"""
#!/bin/bash

# This script is part of the Splunk SOAR playbook called internal_host_ssh_log4j_investigate. It gathers 
# system information as part of a unix endpoint investigation. The output is a human-readable log and a 
# set of .csv files to be copied back to SOAR

echo "##############################################################"
echo "splunk_soar_internal_host_ssh_investigate.sh"
echo "##############################################################"
echo ""
echo "[+] Basic system configuration:"

echo "key,value" > /tmp/basic_system_configuration.csv

echo "hostname: $(uname -n | tr -d "\n")"
echo "hostname,$(uname -n | tr -d "\n")" >> /tmp/basic_system_configuration.csv

echo "current time: $(date +%F_%T)"
echo "current time,$(date +%F_%T)" >> /tmp/basic_system_configuration.csv

echo "IP address: $(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | tr '\n' ' ')"
echo "IP address,$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | tr '\n' ' ')" >> /tmp/basic_system_configuration.csv

echo "OS release: $(cat /etc/*release | sort -u | tr "\n" ";")"
echo "OS release,$(cat /etc/*release | sort -u | tr "\n" ";")" >> /tmp/basic_system_configuration.csv

echo "OS issue: $(cat /etc/issue)"
echo "OS issue,$(cat /etc/issue)" >> /tmp/basic_system_configuration.csv

echo "OS kernel: $(uname -a)"
echo "OS kernel,$(uname -a)" >> /tmp/basic_system_configuration.csv

echo ""
echo "USER,PID,%CPU,%MEM,VSZ,RSS,TTY,STAT,START,TIME,COMMAND" > /tmp/process_list.csv
echo "$(ps aux)" >> /tmp/process_list.csv
echo "[+] Process list:"
echo "$(ps aux)"

echo ""
echo "UNIT,LOAD,ACTIVE,SUB,DESCRIPTION" > /tmp/service_list.csv
echo "$(systemctl)" >> /tmp/service_list.csv
echo "[+] Service list:"
echo "$(systemctl)"

echo ""
echo "$(last -a)" > /tmp/login_history.csv
echo "[+] login history:"
echo "$(last -a)"

echo ""
echo "$(ss -tunapl)" > /tmp/open_sockets.csv
echo "[+] Open sockets:"
echo "$(ss -tunapl)"

echo ""
echo "cron_job" > /tmp/cron_jobs.csv
echo "$(for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null | grep -v '^#'; done)" >> /tmp/cron_jobs.csv
echo "[+] Cron jobs:"
echo "$(for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null | grep -v '^#'; done)"

echo ""
echo "[+] Zip up the outputs ..."
zip -j /tmp/$1_ssh_output.zip /tmp/basic_system_configuration.csv /tmp/process_list.csv /tmp/service_list.csv /tmp/login_history.csv /tmp/open_sockets.csv /tmp/cron_jobs.csv
echo "wrote zip file to /tmp/$1_ssh_output.zip; next we will copy it back to SOAR"
"""

    file_name = 'splunk_soar_internal_host_ssh_investigate.sh'
    file_path = '/opt/phantom/vault/tmp/{}'.format(file_name)
    with open(file_path, 'w') as bash_script_file:
        bash_script_file.write(bash_script)
        
    success, message, vault_id = phantom.vault_add(file_location=file_path, file_name=file_name)
    parameters = [{'input_1': vault_id}]
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/passthrough", parameters=parameters, name="write_embedded_bash_script_to_vault", callback=upload_bash_script)

    return


def upload_bash_script(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("upload_bash_script() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    write_embedded_bash_script_to_vault_data = phantom.collect2(container=container, datapath=["write_embedded_bash_script_to_vault:custom_function_result.data.*.item"])
    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])

    parameters = []

    # build parameters list for 'upload_bash_script' call
    for write_embedded_bash_script_to_vault_data_item in write_embedded_bash_script_to_vault_data:
        for playbook_input_ip_or_hostname_item in playbook_input_ip_or_hostname:
            if write_embedded_bash_script_to_vault_data_item[0] is not None and playbook_input_ip_or_hostname_item[0] is not None:
                parameters.append({
                    "vault_id": write_embedded_bash_script_to_vault_data_item[0],
                    "ip_hostname": playbook_input_ip_or_hostname_item[0],
                    "file_destination": "/tmp/",
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("put file", parameters=parameters, name="upload_bash_script", assets=["ssh"], callback=run_bash_script)

    return


def run_bash_script(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_bash_script() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])

    parameters = []

    # build parameters list for 'run_bash_script' call
    for playbook_input_ip_or_hostname_item in playbook_input_ip_or_hostname:
        if playbook_input_ip_or_hostname_item[0] is not None:
            parameters.append({
                "command": "bash /tmp/splunk_soar_internal_host_ssh_investigate.sh",
                "ip_hostname": playbook_input_ip_or_hostname_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # pass the ip_hostname as an argument so it can be used in the output zip file name
    for parameter in parameters:
        parameter['command'] = parameter['command'] + ' ' + parameter['ip_hostname']

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="run_bash_script", assets=["ssh"], callback=get_output_zip_file)

    return


def get_output_zip_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_output_zip_file() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])

    parameters = []

    # build parameters list for 'get_output_zip_file' call
    for playbook_input_ip_or_hostname_item in playbook_input_ip_or_hostname:
        if playbook_input_ip_or_hostname_item[0] is not None:
            parameters.append({
                "file_path": playbook_input_ip_or_hostname_item[0],
                "ip_hostname": playbook_input_ip_or_hostname_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    for parameter in parameters:
        parameter['file_path'] = '/tmp/' + parameter['file_path'] + '_ssh_output.zip'

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get file", parameters=parameters, name="get_output_zip_file", assets=["ssh"])

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