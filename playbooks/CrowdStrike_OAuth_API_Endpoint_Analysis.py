"""
Accepts a hostname or device id as input and collects running processes, network connections and various system information from the device via Crowdstrike. We then generate an observable report for each. This can be customized based on user preference.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'input_filter' block
    input_filter(container=container)

    return

@phantom.playbook_block()
def input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("input_filter() called")

    ################################################################################
    # Determines if the provided inputs are present in the dataset.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:device", "!=", ""]
        ],
        name="input_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_fql(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_fql(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_fql() called")

    ################################################################################
    # Format the FQL query to get the input device information using its ID or hostname.
    ################################################################################

    template = """%%\nhostname:['{0}'],device_id:['{0}']\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:device"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_fql")

    query_device(container=container)

    return


@phantom.playbook_block()
def query_device(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("query_device() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Get information about the device to unquarantine using its hostname or device 
    # id.
    ################################################################################

    format_fql__as_list = phantom.get_format_data(name="format_fql__as_list")

    parameters = []

    # build parameters list for 'query_device' call
    for format_fql__item in format_fql__as_list:
        parameters.append({
            "limit": 50,
            "filter": format_fql__item,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("query device", parameters=parameters, name="query_device", assets=["crowdstrike_oauth_api"], callback=query_device_callback)

    return


@phantom.playbook_block()
def query_device_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("query_device_callback() called")

    
    create_session(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    get_system_info(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def create_session(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_session() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Create a Real Time Response (RTR) session on CS Falcon to interact with the 
    # endpoint.
    ################################################################################

    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.device_id","query_device:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'create_session' call
    for query_device_result_item in query_device_result_data:
        if query_device_result_item[0] is not None:
            parameters.append({
                "device_id": query_device_result_item[0],
                "context": {'artifact_id': query_device_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create session", parameters=parameters, name="create_session", assets=["crowdstrike_oauth_api"], callback=create_session_callback)

    return


@phantom.playbook_block()
def create_session_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_session_callback() called")

    
    run_admin_command_ps(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    run_admin_command_netstat(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    run_admin_command_services(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def run_admin_command_ps(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_admin_command_ps() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Gets a list of running processes on the specified endpoint.
    ################################################################################

    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.device_id","query_device:action_result.parameter.context.artifact_id"], action_results=results)
    create_session_result_data = phantom.collect2(container=container, datapath=["create_session:action_result.data.*.resources.*.session_id","create_session:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'run_admin_command_ps' call
    for query_device_result_item in query_device_result_data:
        for create_session_result_item in create_session_result_data:
            if query_device_result_item[0] is not None and create_session_result_item[0] is not None:
                parameters.append({
                    "command": "ps",
                    "device_id": query_device_result_item[0],
                    "session_id": create_session_result_item[0],
                    "context": {'artifact_id': create_session_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run admin command", parameters=parameters, name="run_admin_command_ps", assets=["crowdstrike_oauth_api"], callback=process_process_observables)

    return


@phantom.playbook_block()
def process_process_observables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("process_process_observables() called")

    ################################################################################
    # Format a normalized output for each process
    ################################################################################

    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.hostname"], action_results=results)
    run_admin_command_ps_result_data = phantom.collect2(container=container, datapath=["run_admin_command_ps:action_result.parameter","run_admin_command_ps:action_result.data","run_admin_command_ps:action_result.status","run_admin_command_ps:action_result.message"], action_results=results)

    query_device_result_item_0 = [item[0] for item in query_device_result_data]
    run_admin_command_ps_result_item_0 = [item[0] for item in run_admin_command_ps_result_data]
    run_admin_command_ps_result_item_1 = [item[1] for item in run_admin_command_ps_result_data]
    run_admin_command_ps_result_item_2 = [item[2] for item in run_admin_command_ps_result_data]
    run_admin_command_ps_result_message = [item[3] for item in run_admin_command_ps_result_data]

    process_process_observables__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    import re
    process_process_observables__observable_array = []
    i = 0
        
    ################################################################################
    # This returns process information from stdout as text, with lines separated by newlines (\n).
    # For example:
    #
    # Name                Id Start Time (UTC-7)   WorkingMemory(kb)    CPU(s) HandleCount Path                                                              
    # ----                -- ------------------   -----------------    ------ ----------- ----                                                              
    # conhost           2216 4/8/2025 12:14:21 PM             5,612      0.05          93 C:\Windows\system32\conhost.exe                                   
    # conhost           4192 4/8/2025 12:14:21 PM             5,620      0.03          93 C:\Windows\system32\conhost.exe   
    # CSFalconService    488 3/27/2025 9:05:13 AM            60,196    312.31         671  
    # csrss              672 3/11/2025 4:21:37 AM             4,476    667.27         500
    # powershell        3768 4/8/2025 12:14:21 PM            60,892      0.66         511 C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
    # VGAuthService     2412 3/11/2025 4:21:42 AM            10,920      0.05         149 C:\Program Files\VMware\VMware Tools\VMware                       
    #                                                                                     VGAuth\VGAuthService.exe                                          
    # vm3dservice       2440 3/11/2025 4:21:42 AM             6,096      0.02         123 C:\Windows\system32\vm3dservice.exe                               
    # vm3dservice       2568 3/11/2025 4:21:42 AM             6,564      0.03         110 C:\Windows\system32\vm3dservice.exe                               
    # vm3dservice       4248 3/11/2025 4:25:31 AM             6,564      0.08         111 C:\Windows\system32\vm3dservice.exe   
    
    for system in run_admin_command_ps_result_item_1:
        device_id = run_admin_command_ps_result_item_0[i].get("device_id")
        hostname = query_device_result_item_0[i]
        
        observable = {
                "source": "Crowdstrike OAuth API",
                "type": "Endpoint",
                "activity_name": "Process Collection",
                "uid": device_id,
                "hostname": hostname,
                "status": run_admin_command_ps_result_item_2[i],
                "status_detail": run_admin_command_ps_result_message[i],
                "process_artifacts": []
            }
        
        stdout = system[0]["resources"][0]["stdout"]
        
        # Skip header lines and read each one using REGEX (for lack of a better way).
        for line in stdout.split('\n')[3:]:
            pattern = re.compile('^(?P<name>\w+)\s+(?P<pid>\d+)\s+(?P<start_time>[\d\/:\s]+(AM|PM))\s+(?P<working_memory>[\d,]+)\s+(?P<cpu>[\d,\.]+)\s+(?P<handle_count>\d+)\s(?P<path>.*)$')
            matches = pattern.match(line)
            orphan_matches = pattern.match(line)
            
            if matches:
                name = matches.group('name')
                pid = matches.group('pid')
                start_time = matches.group('start_time')
                working_memory = matches.group('working_memory')
                cpu = matches.group('cpu')
                handle_count = matches.group('handle_count')
                path = matches.group('path')          
                
                # Skip lines we don't care about.
                if line.strip() and name not in ['Idle','System']:
                    observable['process_artifacts'].append(
                        {
                            "name": name,
                            "pid": pid,
                            "path": path.strip(),
                            "created_time": start_time,
                            "xattributes": [
                                {
                                    "working_memory": working_memory,
                                    "handle_count": handle_count,
                                    "cpu": cpu
                                }
                            ]
                        }
                    )
            else:
                # Some paths are continued on the next line... fold them back into the correct observable.
                orphan_pattern = re.compile('^\s+(?P<orphaned_path>.*?)\s+$')
                orphan_matches = orphan_pattern.match(line)
                
                if orphan_matches:
                    orphaned_path = orphan_matches.group('orphaned_path')
                    previous_observable = observable['process_artifacts'][-1]
                    if previous_observable:
                        previous_observable["path"] = previous_observable["path"] + " " + orphaned_path
                    
  
        #phantom.debug(f"observable = {observable}")
        process_process_observables__observable_array.append(observable)
        i+=1
        
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="process_process_observables:observable_array", value=json.dumps(process_process_observables__observable_array))

    join_delete_session(container=container)

    return


@phantom.playbook_block()
def run_admin_command_netstat(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_admin_command_netstat() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # List the open sockets & network ports on the specified endpoint.
    ################################################################################

    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.device_id","query_device:action_result.parameter.context.artifact_id"], action_results=results)
    create_session_result_data = phantom.collect2(container=container, datapath=["create_session:action_result.data.*.resources.*.session_id","create_session:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'run_admin_command_netstat' call
    for query_device_result_item in query_device_result_data:
        for create_session_result_item in create_session_result_data:
            if query_device_result_item[0] is not None and create_session_result_item[0] is not None:
                parameters.append({
                    "command": "netstat",
                    "device_id": query_device_result_item[0],
                    "session_id": create_session_result_item[0],
                    "context": {'artifact_id': create_session_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run admin command", parameters=parameters, name="run_admin_command_netstat", assets=["crowdstrike_oauth_api"], callback=process_network_observables)

    return


@phantom.playbook_block()
def process_network_observables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("process_network_observables() called")

    ################################################################################
    # Format a normalized output for each network connection
    ################################################################################

    run_admin_command_netstat_result_data = phantom.collect2(container=container, datapath=["run_admin_command_netstat:action_result.parameter.device_id","run_admin_command_netstat:action_result.status","run_admin_command_netstat:action_result.message","run_admin_command_netstat:action_result.data"], action_results=results)
    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.hostname"], action_results=results)

    run_admin_command_netstat_parameter_device_id = [item[0] for item in run_admin_command_netstat_result_data]
    run_admin_command_netstat_result_item_1 = [item[1] for item in run_admin_command_netstat_result_data]
    run_admin_command_netstat_result_message = [item[2] for item in run_admin_command_netstat_result_data]
    run_admin_command_netstat_result_item_3 = [item[3] for item in run_admin_command_netstat_result_data]
    query_device_result_item_0 = [item[0] for item in query_device_result_data]

    process_network_observables__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    import re
    process_network_observables__observable_array = []
    i = 0
    
    ################################################################################
    # This returns network connection information from stdout as text, with lines separated by newlines (\n).
    # For example:
    #
    # Proto Local Address                    Foreign Address         State Owning Process Id Owning Process Name             Process Start Time (UTC-8)
    # ----- -------------                    ---------------         ----- ----------------- -------------------             --------------------------
    # TCP   :::49689                         :::0                   Listen               920 C:\Windows\system32\lsass.exe   10/25/2024 10:28:22 AM    
    # TCP   :::49675                         :::0                   Listen              2060 C:\Windows\system32\svchost.exe 10/25/2024 10:28:13 AM    
    # TCP   :::49669                         :::0                   Listen              2164 C:\Windows\System32\spoolsv.exe 10/25/2024 10:28:13 AM    
    # TCP   :::49666                         :::0                   Listen              1056 C:\Windows\system32\svchost.exe 10/25/2024 10:28:13 AM    
    # TCP   :::49665                         :::0                   Listen              1116 C:\Windows\System32\svchost.exe 10/25/2024 10:28:12 AM    
    # TCP   :::49664                         :::0                   Listen               768                                 10/25/2024 10:28:12 AM    
    # TCP   :::3389                          :::0                   Listen              1048 C:\Windows\System32\svchost.exe 10/25/2024 10:28:13 AM    
    # TCP   :::445                           :::0                   Listen                 4                                 10/25/2024 10:28:13 AM    
    # TCP   :::135                           :::0                   Listen               352 C:\Windows\system32\svchost.exe 10/25/2024 10:28:12 AM    
    # TCP   0.0.0.0:58808                    0.0.0.0:0               Bound              1056 C:\Windows\system32\svchost.exe 11/23/2024 9:31:16 PM     
    # TCP   10.1.19.4:59929                  54.241.197.58:443 Established                 4                                 2/24/2025 2:34:34 PM      
    # TCP   10.1.19.4:58808                  13.64.180.106:443 Established              1056 C:\Windows\system32\svchost.exe 11/23/2024 9:31:16 PM     
    # TCP   0.0.0.0:49689                    0.0.0.0:0              Listen               920 C:\Windows\system32\lsass.exe   10/25/2024 10:28:22 AM    
    # TCP   0.0.0.0:49679                    0.0.0.0:0              Listen               904                                 10/25/2024 10:28:13 AM    
    # TCP   0.0.0.0:49675                    0.0.0.0:0              Listen              2060 C:\Windows\system32\svchost.exe 10/25/2024 10:28:13 AM    
    # TCP   0.0.0.0:49669                    0.0.0.0:0              Listen              2164 C:\Windows\System32\spoolsv.exe 10/25/2024 10:28:13 AM    
    # UDP   ::1:60661                        *:*                    Listen              5472 C:\Windows\system32\svchost.exe 10/26/2024 9:03:09 AM     
    # UDP   fe80::9c8b:6e28:cc9:6e2e%2:60660 *:*                    Listen              5472 C:\Windows\system32\svchost.exe 10/26/2024 9:03:09 AM     
    # UDP   :::5355                          *:*                    Listen              1488 C:\Windows\System32\svchost.exe 2/25/2025 6:52:43 AM      
    # UDP   :::5353                          *:*                    Listen              1488 C:\Windows\System32\svchost.exe 2/25/2025 6:52:43 AM      

    for system in run_admin_command_netstat_result_item_3:
        device_id = run_admin_command_netstat_parameter_device_id[i]
        hostname = query_device_result_item_0[i]
    
        observable = {
            "source": "Crowdstrike OAuth API",
            "type": "Endpoint",
            "activity_name": "Network Connections Collection",
            "uid": device_id,
            "hostname": hostname,
            "status": run_admin_command_netstat_result_item_1[i],
            "status_detail": run_admin_command_netstat_result_message[i],
            "network_artifacts": []
        }

        phantom.debug(f"system -> {system}")
        
        stdout = system[0]["resources"][0]["stdout"]
        if stdout:
            # Skip header lines and read each one, extracting fields via REGEX (for lack of a better way).
            for line in stdout.split('\n')[3:]:                                                
                line_groups = re.search('^(\w+)\s+(.*?)\s+(.*?)\s+(\w+)\s+(\d+)\s(.*?)\s(\d.*?)\s+$', line)
                
                if line_groups:
                    proto = line_groups.group(1)
                    local_address = line_groups.group(2)
                    foreign_address = line_groups.group(3)
                    state = line_groups.group(4)
                    process_id = line_groups.group(5)
                    process_path = line_groups.group(6)
                    start_time = line_groups.group(7)
                   
                    observable['network_artifacts'].append(
                         {
                             "protocol_name": proto,
                             "local_address": local_address,
                             "foreign_address": foreign_address,
                             "state": state,
                             "start_time": start_time,
                             "process": [
                                 {
                                     "pid": process_id,
                                     "path": process_path
                                 }
                             ]
                         }
                    )           

        #phantom.debug(observable)
        process_network_observables__observable_array.append(observable)
        i+=1
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="process_network_observables:observable_array", value=json.dumps(process_network_observables__observable_array))

    join_delete_session(container=container)

    return


@phantom.playbook_block()
def get_system_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_system_info() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Get information from the endpoint.
    ################################################################################

    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.device_id","query_device:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_system_info' call
    for query_device_result_item in query_device_result_data:
        if query_device_result_item[0] is not None:
            parameters.append({
                "id": query_device_result_item[0],
                "context": {'artifact_id': query_device_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get system info", parameters=parameters, name="get_system_info", assets=["crowdstrike_oauth_api"], callback=process_system_observables)

    return


@phantom.playbook_block()
def process_system_observables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("process_system_observables() called")

    ################################################################################
    # Format a normalized output for the endpoint.
    ################################################################################

    get_system_info_result_data = phantom.collect2(container=container, datapath=["get_system_info:action_result.status","get_system_info:action_result.message","get_system_info:action_result.data"], action_results=results)

    get_system_info_result_item_0 = [item[0] for item in get_system_info_result_data]
    get_system_info_result_message = [item[1] for item in get_system_info_result_data]
    get_system_info_result_item_2 = [item[2] for item in get_system_info_result_data]

    process_system_observables__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    process_system_observables__observable_array = []
    i = 0
    
    for system in get_system_info_result_item_2:
        data = system[0]
        if data:
            observable = {
                "source": "Crowdstrike OAuth API",         
                "type": "Endpoint",     
                "activity_name": "System Collection",
                "uid": data['device_id'],
                "hostname": data['hostname'],
                "status": get_system_info_result_item_0[i],
                "status_detail": get_system_info_result_message[i],
                "endpoint_artifacts": [
                    {
                        "agents": [
                            {
                                "type": "Endpoint Detection and Response",
                                "type_id": 1,
                                "uid": data['cid'],
                                "vendor_name": "Crowdstrike",
                                "version": data['agent_version']                        
                            }
                        ],
                        "ip": data['local_ip'],
                        "external_ip": data['external_ip'],
                        "mac": data['mac_address'],
                        "domain": data['machine_domain'],
                        "type": data['product_type_desc'],
                        "last_seen": data['last_seen'],
                        "last_reboot": data['last_reboot'],
                        "last_login_user_sid": data.get('last_login_user_sid', ''),
                        "last_login_timestamp": data.get('last_login_timestamp', ''),
                        "operating_system": {
                            "build:": data['os_build'],
                            "kernel_release": data['kernel_version'],
                            "name": data['os_product_name'],
                            "type": data['platform_name'],
                            "version": data['os_version']
                        },
                        "hw_info": {
                            "bios_manufacturer": data['bios_manufacturer'],
                            "bios_version": data['bios_version'],
                            "serial_number": data['serial_number'],
                            "chassis": data['chassis_type_desc']
                        }
                    }
                ]
            }
        
        policies = []
        for policy in data['policies']:
            policies.append(
                {
                    "name": policy['policy_type'],
                    "uid": policy['policy_id'],
                    "is_applied": policy['applied']
                }
            )
            observable['endpoint_artifacts'][0]['agents'][0]['policies'] = policies
        
        #phantom.debug(f"---> OBSERVABLE: {observable}")
        process_system_observables__observable_array.append(observable)
        i+=1

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="process_system_observables:observable_array", value=json.dumps(process_system_observables__observable_array))

    return


@phantom.playbook_block()
def join_delete_session(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_delete_session() called")

    if phantom.completed(action_names=["run_admin_command_ps", "run_admin_command_netstat", "run_admin_command_services"]):
        # call connected block "delete_session"
        delete_session(container=container, handle=handle)

    return


@phantom.playbook_block()
def delete_session(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("delete_session() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Deletes the Real Time Response (RTR) session on CS Falcon.
    ################################################################################

    create_session_result_data = phantom.collect2(container=container, datapath=["create_session:action_result.summary.session_id","create_session:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'delete_session' call
    for create_session_result_item in create_session_result_data:
        if create_session_result_item[0] is not None:
            parameters.append({
                "session_id": create_session_result_item[0],
                "context": {'artifact_id': create_session_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("delete session", parameters=parameters, name="delete_session", assets=["crowdstrike_oauth_api"])

    return


@phantom.playbook_block()
def run_admin_command_services(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_admin_command_services() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Runs a set of Powershell commands to gather details about the services on the 
    # endpoint.  This requires that the host response policy permits it on the CrowdStrike 
    # side.
    ################################################################################

    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.device_id","query_device:action_result.parameter.context.artifact_id"], action_results=results)
    create_session_result_data = phantom.collect2(container=container, datapath=["create_session:action_result.data.*.resources.*.session_id","create_session:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'run_admin_command_services' call
    for query_device_result_item in query_device_result_data:
        for create_session_result_item in create_session_result_data:
            if query_device_result_item[0] is not None and create_session_result_item[0] is not None:
                parameters.append({
                    "data": "-Raw=```Get-Service | Select-Object -Property Name, DisplayName, Status, ServiceType, StartType | ConvertTo-Json```",
                    "command": "runscript",
                    "device_id": query_device_result_item[0],
                    "session_id": create_session_result_item[0],
                    "context": {'artifact_id': create_session_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run admin command", parameters=parameters, name="run_admin_command_services", assets=["crowdstrike_oauth_api"], callback=process_service_observables)

    return


@phantom.playbook_block()
def process_service_observables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("process_service_observables() called")

    ################################################################################
    # Format a normalized output for each service
    ################################################################################

    query_device_result_data = phantom.collect2(container=container, datapath=["query_device:action_result.data.*.device_id","query_device:action_result.data.*.hostname"], action_results=results)
    run_admin_command_services_result_data = phantom.collect2(container=container, datapath=["run_admin_command_services:action_result.data.*.resources","run_admin_command_services:action_result.status","run_admin_command_services:action_result.message"], action_results=results)

    query_device_result_item_0 = [item[0] for item in query_device_result_data]
    query_device_result_item_1 = [item[1] for item in query_device_result_data]
    run_admin_command_services_result_item_0 = [item[0] for item in run_admin_command_services_result_data]
    run_admin_command_services_result_item_1 = [item[1] for item in run_admin_command_services_result_data]
    run_admin_command_services_result_message = [item[2] for item in run_admin_command_services_result_data]

    process_service_observables__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    import json
    
    # Ref: https://learn.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicestartmode?view=net-9.0-pp
    ocsf_start_type_mapping = {
        "0": { "id": "1", "type": "Boot" },     # Boot -> Boot
        "1": { "id": "2", "type": "System" },   # System -> System
        "2": { "id": "3", "type": "Auto" },     # Automatic -> Auto
        "3": { "id": "4", "type": "Demand" },   # Manual -> Demand
        "4": { "id": "5", "type": "Disabled" }  # Disabled -> Disabled
    }
    
    # Ref: https://learn.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicetype?view=net-9.0-pp
    ocsf_service_type_mapping = {
        # Unused for now.  OCSF doesn't seem to properly support BITWISE ENUMs yet.
        # See "service_type_id" at https://schema.ocsf.io/1.4.0/objects/win/win_service
    }
    
    process_service_observables__observable_array = []
    for device_id, hostname, services, status, messsage in zip(query_device_result_item_0, query_device_result_item_1, run_admin_command_services_result_item_0, run_admin_command_services_result_item_1, run_admin_command_services_result_message):
        
        observable = {
            "source": "Crowdstrike OAuth API",
            "type": "Endpoint",
            "activity_name": "Services Collection",
            "uid": device_id,
            "hostname": hostname,
            "status": status,
            "status_detail": messsage,
            "service_artifacts": []
        }
        
        if services[0] and services[0]["stdout"]:
            services_json = json.loads(services[0]["stdout"])
            for service in services_json:
                start_type = ocsf_start_type_mapping.get(str(service["StartType"]))
          
                observable["service_artifacts"].append({
                    "type_id": 3, 
                    "type": "Service",
                    "name": service["Name"],
                    "display_name": service["DisplayName"],
                    "service_start_type_id": start_type["id"],
                    "service_start_type": start_type["type"], 
                    "service_type_id": service["ServiceType"], # No mapping to OCSF yet, see comment above.
                })
            
        process_service_observables__observable_array.append(observable)
      
    #phantom.debug(process_service_observables__observable_array)
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="process_service_observables:observable_array", value=json.dumps(process_service_observables__observable_array))

    join_delete_session(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    process_process_observables__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="process_process_observables:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    process_network_observables__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="process_network_observables:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    process_system_observables__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="process_system_observables:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    process_service_observables__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="process_service_observables:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "process_observable": process_process_observables__observable_array,
        "network_observable": process_network_observables__observable_array,
        "endpoint_observable": process_system_observables__observable_array,
        "service_observable": process_service_observables__observable_array,
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