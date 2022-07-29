"""
Hunt for internal sightings of malicious files or connections to malicious domains or IP addresses.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

"""
The hunting Playbook queries a number of internal security technologies in order to determine if any of the artifacts present in your data source have been observed in your environment.
"""

def get_specific_assets(action, include_products=None):
    
    supported_assets = phantom.get_assets(action=action)
    # phantom.debug("Action Supported Assets")
    # phantom.debug(supported_assets)
    
    if not supported_assets:
        # no supported products configured
        return []
    
    if not include_products:
        # no product filters, so return whatever we found
        return [x['name'] for x in supported_assets]
    
    if include_products:
        
        if (type(include_products) != list):
            phantom.debug("Please specify a list for filter_products")
            return []
        
        # make the product names sent to this funcion lower
        include_products = [x.lower() for x in include_products]
        
        # get products that are configured and asked for
        assets_matched = [x['name'] for x in supported_assets if x['product_name'].lower() in include_products]
        # phantom.debug("Action Supported Matches")
        # phantom.debug(assets_matched)
        return assets_matched
       
    # should not reach here
    return []

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'hunt_domain_1' block
    hunt_domain_1(container=container)

    # call 'hunt_file_1' block
    hunt_file_1(container=container)

    # call 'run_query_1' block
    run_query_1(container=container)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["hunt_domain_1:action_result.summary.device_count", ">", 0],
            ["artifact:*.cef.destinationDnsDomain", "==", "hunt_domain_1:action_result.parameter.domain"],
        ],
        logical_operator='and',
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_system_info_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def get_system_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    
    assets = get_specific_assets("get system info", ["Carbon Black"])
    
    if (not assets):
        phantom.debug("Carbon Black::get system info not found returning.")
        
    # collect data for 'get_system_info_1' call
    filtered_container_data = phantom.collect2(container=container, datapath=['filtered-artifact:*.cef.sourceAddress', 'filtered-artifact:*.id'], filter_artifacts=filtered_artifacts)

    parameters = []
    
    # build parameters list for 'get_system_info_1' call
    for filtered_container_item in filtered_container_data:
        if filtered_container_item[0]:
            parameters.append({
                'ip_hostname': filtered_container_item[0],
            })

    if parameters:
        phantom.act("get system info", parameters=parameters, assets=assets, name="get_system_info_1")    
    else:
        phantom.error("'get_system_info_1' will not be executed due to lack of parameters")
    
    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["hunt_file_1:action_result.data.*.binary.total_results", ">", 0],
            ["artifact:*.cef.fileHash", "==", "hunt_file_1:action_result.parameter.hash"],
        ],
        logical_operator='and',
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["action_result.summary.positives", "==", 0],
            ["artifact:*.cef.fileHash", "==", "file_reputation_1:action_result.parameter.hash"],
        ],
        logical_operator='and',
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_file_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def hunt_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):

    assets = get_specific_assets("hunt domain", ["Falcon Host API"])
    
    if (not assets):
        phantom.debug("hunt domain/Falcon Host API not found returning.")

    # collect data for 'hunt_domain_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_domain_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                'count_only': True,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("hunt domain", parameters=parameters, assets=assets, callback=filter_1, name="hunt_domain_1")    
    else:
        phantom.error("'hunt_domain_1' will not be executed due to lack of parameters")
    
    return

def get_file_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    
    assets = get_specific_assets("get file", ["Carbon Black"])
    
    if (not assets):
        phantom.debug("Carbon Black::get file not found returning.")
    
    # collect data for 'get_file_2' call
    filtered_container_data = phantom.collect2(container=container, datapath=['filtered-artifact:*.cef.fileHash', 'filtered-artifact:*.id'], filter_artifacts=filtered_artifacts)

    parameters = []
    
    # build parameters list for 'get_file_2' call
    for filtered_container_item in filtered_container_data:
        if filtered_container_item[0]:
            parameters.append({
                'hash': filtered_container_item[0],
            })

    if parameters:
        phantom.act("get file", parameters=parameters, assets=assets, callback=filter_3, name="get_file_2")    
    else:
        phantom.error("'get_file_2' will not be executed due to lack of parameters")
    
    return

def detonate_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    
    assets = get_specific_assets("detonate file", ["Threat Grid"])
    
    if (not assets):
        phantom.debug("Threat Grid::detonate file not found returning.")
    
    # collect data for 'detonate_file_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["get_file_2:filtered-action_result.data.*.vault_id", "get_file_2:filtered-action_result.parameter.context.artifact_id"], action_results=filtered_results)

    parameters = []
    
    # build parameters list for 'detonate_file_1' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'vault_id': filtered_results_item_1[0],
                'file_name': "",
                'vm': "",
                'force_analysis': "",
                'private': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    if parameters:
        phantom.act("detonate file", parameters=parameters, assets=assets, name="detonate_file_1")    
    else:
        phantom.error("'detonate_file_1' will not be executed due to lack of parameters")
    
    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_file_2:action_result.data.*.vault_id", "!=", ""],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        detonate_file_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    
    assets = get_specific_assets("file reputation", ["TitaniumCloud"])
    
    if (not assets):
        phantom.debug("ReversingLabs/TitaniumCloud::file reputation not found returning.")

    # collect data for 'file_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['filtered-artifact:*.cef.fileHash', 'filtered-artifact:*.id'], filter_artifacts=filtered_artifacts)
    
    phantom.debug(container_data)

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("file reputation", parameters=parameters, assets=assets, name="file_reputation_1", callback=filter_2)    
    else:
        phantom.error("'file_reputation_1' will not be executed due to lack of parameters")
    
    return

def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):

    assets = get_specific_assets("run query", ["Splunk Enterprise", "Carbon Black"])
    
    if (not assets):
        phantom.debug("Did not find any asset configured, supporting run query")
        return
    
    container_data_src = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])
    container_data_dst = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'run_query_1' call
    
    phantom.debug("Got the following assets:")
    phantom.debug(','.join([x for x in assets]))
    
    for container_item in container_data_src:
        if container_item[0]:
            parameters.append({
                'query': container_item[0],
                'display': "",
                'type': "process",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
                })
            
    for container_item in container_data_dst:
        if container_item[0]:
            parameters.append({
                'query': container_item[0],
                'display': "",
                'type': "process",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
                })
            
    if (parameters):
        phantom.act("run query", parameters=parameters, assets=assets, name="run_query_1")
    else:
        phantom.error("'run_query_1' will not be executed due to lack of parameters")
                
    return

def hunt_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):

    assets = get_specific_assets("hunt file", ["Carbon Black"])
    
    if (not assets):
        phantom.debug("Carbon Black::hunt file not found returning.")
        
    # collect data for 'hunt_file_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_file_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                'range': "",
                'type': "binary",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("hunt file", parameters=parameters, assets=assets, name="hunt_file_1", callback=filter_4)    
    else:
        phantom.error("'hunt_file_1' will not be executed due to lack of parameters")
    
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