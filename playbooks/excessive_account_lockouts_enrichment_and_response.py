"""
This Playbook is part of the Splunk Analytic Story called Account Monitoring and Controls. It is made to be run when the Detection Search within that story called "Detect Excessive Account Lockouts From Endpoint" is used to identify a potential attack in which multiple Active Directory user accounts are locked out from logging in because an adversary attempted incorrect credentials repeatedly against many user accounts. This Playbook runs the Context-gathering and Investigative searches linked in the Splunk Analytic Story to enrich the event with a broad array of information about the users and computers involved. Then the Playbook uses Windows Remote Management to login to the source of the lockouts, gather more information, and allow Phantom to shutdown the server after prompting an analyst or responder.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'if_matches_analytic_story' block
    if_matches_analytic_story(container=container)

    return

"""
Build the search to check the Authentication Data Model for the recent login history of the target computer used to cause account lockouts
"""
def format_endpoint_auth_logs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_endpoint_auth_logs() called')
    
    template = """| tstats count from datamodel=Authentication where Authentication.dest={0} earliest=-15m by _time, Authentication.dest, Authentication.user, Authentication.app, Authentication.action | `drop_dm_object_name(\"Authentication\")`"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_endpoint_auth_logs")

    query_endpoint_auth_logs(container=container)

    return

"""
Run the search to check the Authentication Data Model for the recent login history of the target computer used to cause account lockouts
"""
def query_endpoint_auth_logs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('query_endpoint_auth_logs() called')

    # collect data for 'query_endpoint_auth_logs' call
    formatted_data_1 = phantom.get_format_data(name='format_endpoint_auth_logs')

    parameters = []
    
    # build parameters list for 'query_endpoint_auth_logs' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=query_endpoint_auth_logs_callback, name="query_endpoint_auth_logs")

    return

def query_endpoint_auth_logs_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('query_endpoint_auth_logs_callback() called')
    
    format_user_identity_info(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    format_user_risk_mod(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Build a search to find other Notable Events triggered against the same endpoint
"""
def format_notable_history(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_notable_history() called')
    
    template = """| search `notable` | search dest={0} | table _time, rule_name, owner, priority, severity, status_description, event_id"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_notable_history")

    query_notable_history(container=container)

    return

"""
Run a search to find other Notable Events triggered against the same endpoint
"""
def query_notable_history(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('query_notable_history() called')

    # collect data for 'query_notable_history' call
    formatted_data_1 = phantom.get_format_data(name='format_notable_history')

    parameters = []
    
    # build parameters list for 'query_notable_history' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=format_notable_info, name="query_notable_history")

    return

"""
Build a search to gather more information from the Notable Event that was sent to Phantom
"""
def format_notable_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_notable_info() called')
    
    template = """| search `notable_by_id({0})` | table time, rule_name, dest, dest_asset_id, dest_owner, priority, severity, owner, status_description"""

    # parameter list for template variable replacement
    parameters = [
        "query_notable_history:action_result.data.0.event_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_notable_info")

    query_notable_info(container=container)

    return

"""
Run a search to gather more information from the Notable Event that was sent to Phantom
"""
def query_notable_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('query_notable_info() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'query_notable_info' call
    formatted_data_1 = phantom.get_format_data(name='format_notable_info')

    parameters = []
    
    # build parameters list for 'query_notable_info' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=join_add_comment_2, name="query_notable_info")

    return

"""
Build a search to query the Risk framework for the score of the affected endpoint
"""
def format_endpoint_risk_mod(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_endpoint_risk_mod() called')
    
    template = """| from datamodel:Risk.All_Risk | search risk_object_type=system risk_object={0} | stats count sum(risk_score) as risk_score values(search_name)  min(_time) as firstTime max(_time) as lastTime by risk_object | `ctime(firstTime)` | `ctime(lastTime)`"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_endpoint_risk_mod")

    query_endpoint_risk_mod(container=container)

    return

"""
Run a search to query the Risk framework for the score of the affected endpoint
"""
def query_endpoint_risk_mod(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('query_endpoint_risk_mod() called')

    # collect data for 'query_endpoint_risk_mod' call
    formatted_data_1 = phantom.get_format_data(name='format_endpoint_risk_mod')

    parameters = []
    
    # build parameters list for 'query_endpoint_risk_mod' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=join_add_comment_2, name="query_endpoint_risk_mod")

    return

"""
Build a search to check risk scores for each user identified in the previous Authentication search
"""
def format_user_risk_mod(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_user_risk_mod() called')
    
    template = """| from datamodel:Risk.All_Risk | search risk_object_type=user risk_object IN ({0}) earliest=-15m | stats count sum(risk_score) as risk_score values(search_name)  min(_time) as firstTime max(_time) as lastTime by risk_object |`ctime(firstTime)` |`ctime(lastTime)`"""

    # parameter list for template variable replacement
    parameters = [
        "query_endpoint_auth_logs:action_result.data.*.user",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_user_risk_mod")

    query_user_risk_mod(container=container)

    return

"""
Run a search to check risk scores for each user identified in the previous Authentication search
"""
def query_user_risk_mod(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('query_user_risk_mod() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'query_user_risk_mod' call
    formatted_data_1 = phantom.get_format_data(name='format_user_risk_mod')

    parameters = []
    
    # build parameters list for 'query_user_risk_mod' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=join_add_comment_2, name="query_user_risk_mod")

    return

"""
Build a search to query the Identity framework for the category and watchlist status of all users found in the previous Authentication search
"""
def format_user_identity_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_user_identity_info() called')
    
    template = """| `identities` | search identity IN ({0}) | table _time, identity, first, last, email, category, watchlist"""

    # parameter list for template variable replacement
    parameters = [
        "query_endpoint_auth_logs:action_result.data.*.user",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_user_identity_info")

    query_user_identity_info(container=container)

    return

"""
Run a search to query the Identity framework for the category and watchlist status of all users found in the previous Authentication search
"""
def query_user_identity_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('query_user_identity_info() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'query_user_identity_info' call
    formatted_data_1 = phantom.get_format_data(name='format_user_identity_info')

    parameters = []
    
    # build parameters list for 'query_user_identity_info' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=join_add_comment_2, name="query_user_identity_info")

    return

"""
Build a search to query for modifications to the access rights associated with the affected endpoint, which could show newly available resources accessible to an adversary
"""
def endpoint_rights_mod(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('endpoint_rights_mod() called')
    
    template = """| search index=wineventlog (EventCode=4718 OR EventCode=4717) dest={0} | rename user as \"Account Modified\" | table _time, dest, \"Account Modified\", Access_Right, signature"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="endpoint_rights_mod")

    query_endpoint_rights(container=container)

    return

"""
Run a search to query for modifications to the access rights associated with the affected endpoint, which could show newly available resources accessible to an adversary
"""
def query_endpoint_rights(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('query_endpoint_rights() called')

    # collect data for 'query_endpoint_rights' call
    formatted_data_1 = phantom.get_format_data(name='endpoint_rights_mod')

    parameters = []
    
    # build parameters list for 'query_endpoint_rights' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=join_add_comment_2, name="query_endpoint_rights")

    return

"""
Build a search to query for modifications to the access rights associated with the affected user, which could show newly available resources accessible to an adversary
"""
def user_rights_mod(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('user_rights_mod() called')
    
    template = """| search index=wineventlog (EventCode=4718 OR EventCode=4717) user=* | rename user as \"Account Modified\" | table _time, dest, \"Account Modified\", Access_Right, signature"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="user_rights_mod")

    query_user_rights(container=container)

    return

"""
Run a search to query for modifications to the access rights associated with the affected user, which could show newly available resources accessible to an adversary
"""
def query_user_rights(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('query_user_rights() called')

    # collect data for 'query_user_rights' call
    formatted_data_1 = phantom.get_format_data(name='user_rights_mod')

    parameters = []
    
    # build parameters list for 'query_user_rights' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=join_add_comment_2, name="query_user_rights")

    return

"""
List Remote Desktop Services session including system sessions and users remotely logged in
"""
def list_sessions_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_sessions_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_sessions_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'list_sessions_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip_hostname': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="list sessions", parameters=parameters, assets=['winrm'], callback=list_sessions_1_callback, name="list_sessions_1")

    return

def list_sessions_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('list_sessions_1_callback() called')
    
    join_account_lockout_endpoint_shutdown(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    format_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
List active TCP sessions including the process ID's using "netstat -no"
"""
def list_connections_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_connections_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_connections_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'list_connections_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip_hostname': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="list connections", parameters=parameters, assets=['winrm'], callback=join_account_lockout_endpoint_shutdown, name="list_connections_1")

    return

"""
List all existing system and user logon sessions using a WMI query against Win32_LoggedOnUser
"""
def list_logged_on_users(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_logged_on_users() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_logged_on_users' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'list_logged_on_users' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'async': "",
                'parser': "",
                'shell_id': "",
                'command_id': "",
                'script_str': "Get-CimInstance Win32_LoggedOnUser | Select-Object -ExpandProperty Antecedent | Get-Unique | Select-Object Name, Domain | ConvertTo-JSON",
                'ip_hostname': container_item[0],
                'script_file': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="run script", parameters=parameters, assets=['winrm'], callback=join_account_lockout_endpoint_shutdown, name="list_logged_on_users")

    return

"""
List all running processes
"""
def list_processes_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_processes_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_processes_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'list_processes_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip_hostname': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="list processes", parameters=parameters, assets=['winrm'], callback=join_account_lockout_endpoint_shutdown, name="list_processes_1")

    return

"""
Ask an analyst if they want to initiate a system shutdown against the affected endpoint
"""
def account_lockout_endpoint_shutdown(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('account_lockout_endpoint_shutdown() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Do you want to shutdown the system?"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="account_lockout_endpoint_shutdown", response_types=response_types, callback=decision_1)

    return

def join_account_lockout_endpoint_shutdown(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_account_lockout_endpoint_shutdown() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['list_processes_1', 'list_logged_on_users', 'list_connections_1', 'list_sessions_1']):
        
        # call connected block "account_lockout_endpoint_shutdown"
        account_lockout_endpoint_shutdown(container=container, handle=handle)
    
    return

"""
If the analyst responded "Yes" then proceed with the shutdown
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["account_lockout_endpoint_shutdown:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        shutdown_system_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        shutdown_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    add_comment_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    no_shutdown_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Shutdown the system over WinRM using "& shutdown.exe /s /t 5" and display a comment to any logged in users
"""
def shutdown_system_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('shutdown_system_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'shutdown_system_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'shutdown_system_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'comment': "remote shutdown from Phantom playbook endpoint_excessive_account_lockouts",
                'ip_hostname': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="shutdown system", parameters=parameters, assets=['winrm'], name="shutdown_system_1")

    return

"""
Since the analyst decided not to shutdown the endpoint, display a comment showing the end of the playbook
"""
def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_1() called')

    phantom.comment(container=container, comment="prompted Phantom user decided not to shutdown the system")

    return

"""
Only run this playbook if the event matches the detection signature of the Splunk Analytic Story
"""
def if_matches_analytic_story(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('if_matches_analytic_story() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.signature", "==", "A user account was locked out"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_endpoint_auth_logs(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        format_notable_history(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        format_endpoint_risk_mod(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        endpoint_rights_mod(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        user_rights_mod(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Write a comment to Mission Control to show that the Splunk searches are completed and now the Playbook is transitioning to WinRM commands
"""
def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_2() called')

    phantom.comment(container=container, comment="finished splunk searches, starting WinRM investigation")
    list_sessions_1(container=container)
    list_connections_1(container=container)
    list_logged_on_users(container=container)
    list_processes_1(container=container)

    return

def join_add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_add_comment_2() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['query_endpoint_risk_mod', 'query_notable_info', 'query_user_identity_info', 'query_user_risk_mod', 'query_endpoint_rights', 'query_user_rights']):
        
        # call connected block "add_comment_2"
        add_comment_2(container=container, handle=handle)
    
    return

"""
Add a comment to the Notable Event showing that the playbook is waiting at an analyst prompt, including a link to access the Mission Control for this playbook run.
"""
def prompt_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_comment() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'prompt_comment' call
    results_data_1 = phantom.collect2(container=container, datapath=['query_notable_history:action_result.data.0.event_id', 'query_notable_history:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_comment')

    parameters = []
    
    # build parameters list for 'prompt_comment' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'owner': "",
                'status': "",
                'comment': formatted_data_1,
                'urgency': "",
                'event_ids': results_item_1[0],
                'integer_status': "",
                'wait_for_confirmation': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="update event", parameters=parameters, assets=['splunk'], name="prompt_comment")

    return

"""
Build a comment to the Notable Event showing that the playbook is waiting at an analyst prompt, including a link to access the Mission Control for this playbook run.
"""
def format_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_comment() called')
    
    template = """A Phantom playbook has enriched the event and is waiting for a prompt. Use this Mission Control link to view and respond: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "container:url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_comment")

    prompt_comment(container=container)

    return

"""
Add a comment to the Notable Event showing that an analyst decided to shut down the affected Windows machine.
"""
def shutdown_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('shutdown_comment() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'shutdown_comment' call
    results_data_1 = phantom.collect2(container=container, datapath=['query_notable_history:action_result.data.0.event_id', 'query_notable_history:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'shutdown_comment' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'owner': "",
                'status': "",
                'comment': "A Phantom playbook shut down the affected Windows machine with approval from an analyst.",
                'urgency': "",
                'event_ids': results_item_1[0],
                'integer_status': "",
                'wait_for_confirmation': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="update event", parameters=parameters, assets=['splunk'], name="shutdown_comment")

    return

"""
Add a comment to the Notable Event showing that an analyst decided not to shut down the affected Windows machine.
"""
def no_shutdown_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('no_shutdown_comment() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'no_shutdown_comment' call
    results_data_1 = phantom.collect2(container=container, datapath=['query_notable_history:action_result.data.0.event_id', 'query_notable_history:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'no_shutdown_comment' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'owner': "",
                'status': "",
                'comment': "An analyst decided not to shut down the affected Windows machine so no action was taken.",
                'urgency': "",
                'event_ids': results_item_1[0],
                'integer_status': "",
                'wait_for_confirmation': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="update event", parameters=parameters, assets=['splunk'], name="no_shutdown_comment")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return