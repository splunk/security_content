"""
This playbook retrieves IP addresses, domains, and file hashes, blocks them on various services, and adds them to specific blocklists as custom lists.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    # call 'filter_2' block
    filter_2(container=container)

    # call 'filter_3' block
    filter_3(container=container)

    return

def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_ip_1() called')

    # collect data for 'block_ip_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_4:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_4:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_ip_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                'vsys': "",
                'is_source_address': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="block ip", parameters=parameters, assets=['pan'], callback=add_to_IP_blocklist, name="block_ip_1")

    return

def block_hash_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_hash_2() called')

    # collect data for 'block_hash_2' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_6:condition_1:artifact:*.cef.fileHash', 'filtered-data:filter_6:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_hash_2' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                'comment': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="block hash", parameters=parameters, assets=['carbonblack'], callback=add_to_hash_blocklist, name="block_hash_2")

    return

def block_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_domain_1() called')

    # collect data for 'block_domain_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:filter_5:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_domain_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': filtered_artifacts_item_1[0],
                'disable_safeguards': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="block domain", parameters=parameters, assets=['opendns_umbrella'], callback=add_to_domain_blocklist, name="block_domain_1")

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Checking to see if this domain address is in the custom list called "domain_blocklist"
"""
def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_2:condition_1:artifact:*.cef.destinationDnsDomain", "in", "custom_list:domain_blocklist"],
        ],
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_domain_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Checking to see if this filehash is in the custom list called "filehash_blocklist"
"""
def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_3:condition_1:artifact:*.cef.fileHash", "in", "custom_list:filehash_blocklist"],
        ],
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_hash_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
The file hash is added to the custom list 'filehash_blocklist' in order to prevent the Playbook from attempting to block a file hash that has already been blocked.
"""
def add_to_hash_blocklist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_to_hash_blocklist() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_to_hash_blocklist' call
    results_data_1 = phantom.collect2(container=container, datapath=['block_hash_2:action_result.parameter.hash', 'block_hash_2:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'add_to_hash_blocklist' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'list': "custom_list:filehash_blocklist",
                'create': True,
                'new_row': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="add listitem", parameters=parameters, assets=['phantom'], name="add_to_hash_blocklist", parent_action=action)

    return

"""
The domain is added to the custom list 'domain_blocklist' in order to prevent the Playbook from attempting to block a domain that has already been blocked.
"""
def add_to_domain_blocklist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_to_domain_blocklist() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_to_domain_blocklist' call
    results_data_1 = phantom.collect2(container=container, datapath=['block_domain_1:action_result.parameter.domain', 'block_domain_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'add_to_domain_blocklist' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'list': "custom_list:domain_blocklist",
                'create': True,
                'new_row': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="add listitem", parameters=parameters, assets=['phantom'], name="add_to_domain_blocklist", parent_action=action)

    return

"""
The IP address is added to the custom list 'ip_address_blocklist' in order to prevent the Playbook from attempting to block an IP address that has already been blocked.
"""
def add_to_IP_blocklist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_to_IP_blocklist() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_to_IP_blocklist' call
    results_data_1 = phantom.collect2(container=container, datapath=['block_ip_1:action_result.parameter.ip', 'block_ip_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'add_to_IP_blocklist' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'list': "custom_list:ip_address_blocklist",
                'create': True,
                'new_row': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="add listitem", parameters=parameters, assets=['phantom'], name="add_to_IP_blocklist", parent_action=action)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Checking to see if this IP address is in the custom list called "ip_address_blocklist"
"""
def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_1:condition_1:artifact:*.cef.destinationAddress", "not in", "custom_list:ip_address_blocklist"],
        ],
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_ip_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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