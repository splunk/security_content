"""
Published in response to CVE-2021-44228, \n this playbook investigates an internal unix host using SSH. This pushes a bash script to the endpoint and runs it, collecting information specific to the December 2021 log4j vulnerability disclosure. This includes the java version installed on the host, any running java processes, and the results of a scan for the affected JndiLookup.class file or log4j .jar files.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'add_embedded_bash_script_to_vault' block
    add_embedded_bash_script_to_vault(container=container)

    return

def add_embedded_bash_script_to_vault(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_embedded_bash_script_to_vault() called")

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
  
# This script is part of the Splunk SOAR playbook called internal_host_ssh_log4j_investigate. It shows
# the installed java version, lists any running java processes, performs a search for the JndiLookup.class
# file in any .jar files found on disk, and searches any .war files for a log4j jar. The output is a human-readable
# log and a set of .csv files to be copied back to SOAR

echo "##############################################################"
echo "splunk_soar_internal_host_ssh_log4j_investigate.sh"
echo "##############################################################"
echo ""

echo "java environment configuration" > /tmp/java_environment.csv
echo "[+] Checking Java version:"
echo "$(java -version)"
echo "java version:" >> /tmp/java_environment.csv
java -version 2>> /tmp/java_environment.csv

echo ""
echo "[+] Checking running Java processes with ps:"
echo "$(ps aux | grep java)"
echo "ps java processes:" >> /tmp/java_environment.csv
echo "$(ps aux | grep java)" >> /tmp/java_environment.csv

echo ""
echo "[+] Checking running Java processes with jps:"
echo "$(jps -v)"
echo "jps java processes:" >> /tmp/java_environment.csv
echo "$(jps -v)" >> /tmp/java_environment.csv

echo "[+] Search .jar files for JndiLookup.class files ..."
echo "jar_files" > /tmp/jars_with_jndi.csv
find / 2>/dev/null -name '*.jar' -type f -print0 | xargs -0 grep JndiLookup.class | awk '{print $3}' | while read -r file
do
    if [ -f "$file" ]; then
        echo "JndiLookup.class found in .jar file: $file"
        echo "$file" >> /tmp/jars_with_jndi.csv
    fi
done

echo ""
echo "[+] Search .war files for log4j .jar files ..."
echo "war_file,jar_size,jar_time_modified,jar_file" > /tmp/wars_with_jars.csv
find / 2>/dev/null -name '*.war' -type f -print0 | xargs -0 grep log4j | awk '{print $3}' | while read -r war_file
do
    if [ -f "$war_file" ]; then
        unzip -l "$war_file" | grep log4j | awk '{print $1"," $2" "$3","$4}' | while read -r jar_file
        do
            echo ".war file $war_file was found containing the file $jar_file"
            echo "$war_file,$jar_file" >> /tmp/wars_with_jars.csv
        done
    fi
done

echo "[+] Zip up the outputs ..."
zip -j /tmp/$1_ssh_log4j_output.zip /tmp/java_environment.csv /tmp/jars_with_jndi.csv /tmp/wars_with_jars.csv
echo "wrote zip file to /tmp/$1_ssh_log4j_output.zip; next we will copy it back to SOAR"
"""
    
    file_name = 'splunk_soar_internal_host_ssh_log4j_investigate.sh'
    file_path = '/opt/phantom/vault/tmp/{}'.format(file_name)
    with open(file_path, 'w') as bash_script_file:
        bash_script_file.write(bash_script)
        
    success, message, vault_id = phantom.vault_add(file_location=file_path, file_name=file_name)
    parameters = [{'input_1': vault_id}]

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/passthrough", parameters=parameters, name="add_embedded_bash_script_to_vault", callback=upload_bash_script)

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
                "command": "bash /tmp/splunk_soar_internal_host_ssh_log4j_investigate.sh",
                "ip_hostname": playbook_input_ip_or_hostname_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # append the ip_hostname as an argument so it can be used in the output zip file name
    for parameter in parameters:
        parameter['command'] = parameter['command'] + ' ' + parameter['ip_hostname']

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="run_bash_script", assets=["ssh"], callback=get_output_zip_file)

    return


def upload_bash_script(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("upload_bash_script() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    add_embedded_bash_script_to_vault_data = phantom.collect2(container=container, datapath=["add_embedded_bash_script_to_vault:custom_function_result.data.*.item"])
    playbook_input_ip_or_hostname = phantom.collect2(container=container, datapath=["playbook_input:ip_or_hostname"])

    parameters = []

    # build parameters list for 'upload_bash_script' call
    for add_embedded_bash_script_to_vault_data_item in add_embedded_bash_script_to_vault_data:
        for playbook_input_ip_or_hostname_item in playbook_input_ip_or_hostname:
            if add_embedded_bash_script_to_vault_data_item[0] is not None and playbook_input_ip_or_hostname_item[0] is not None:
                parameters.append({
                    "vault_id": add_embedded_bash_script_to_vault_data_item[0],
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
        parameter['file_path'] = '/tmp/' + parameter['file_path'] + '_ssh_log4j_output.zip'

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