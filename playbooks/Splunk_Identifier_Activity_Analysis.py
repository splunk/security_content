"""
Accepts a file_hash, domain name, URL, or IP Address, and asks Splunk for a list of devices and users that have interacted with each. It then produces a normalized output and summary table. Defaults to -30d searches.
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
def input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("input_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:url", "!=", None]
        ],
        name="input_filter:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        parse_url(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:file", "!=", None]
        ],
        name="input_filter:condition_2",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        build_file_query(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:domain", "!=", None]
        ],
        name="input_filter:condition_3",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        build_domain_query(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids and results for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:ip", "!=", None]
        ],
        name="input_filter:condition_4",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        build_ip_query(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    return


@phantom.playbook_block()
def build_url_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_url_query() called")

    ################################################################################
    # Query may need editing to reflect your splunk environment
    ################################################################################

    template = """count fillnull_value=\"Unknown\" from datamodel=Web.Web where Web.url IN (\n%%\n\"*{0}{1}*\" \n%%\n) by Web.src Web.user Web.url | `drop_dm_object_name(\"Web\")` | `get_asset(src)` | fields url, src, src_asset_id, src_dns, src_ip, user | fillnull value=\"Unknown\""""

    # parameter list for template variable replacement
    parameters = [
        "parse_url:custom_function_result.data.netloc",
        "parse_url:custom_function_result.data.path"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="build_url_query")

    run_url_query(container=container)

    return


@phantom.playbook_block()
def build_file_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_file_query() called")

    ################################################################################
    # Query may need editing to reflect your splunk environment
    ################################################################################

    template = """count fillnull_value=\"Unknown\" values(Processes.process_name) as process_name from datamodel=Endpoint.Processes where (Processes.process_hash IN (\n%%\n\"{0}\" \n%%\n) OR Processes.process_hash IN (\n%%\n\"*{0}*\" \n%%\n)) by Processes.dest Processes.user Processes.process_hash | `drop_dm_object_name(\"Processes\")` | `get_asset(dest)` | fields process_hash, process_name, dest, dest_asset_id, dest_dns, dest_ip, user | fillnull value=\"Unknown\""""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:input_filter:condition_2:playbook_input:file"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="build_file_query")

    run_file_query(container=container)

    return


@phantom.playbook_block()
def build_domain_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_domain_query() called")

    ################################################################################
    # Query may need editing to reflect your splunk environment
    ################################################################################

    template = """count from datamodel=Network_Resolution where DNS.query IN (\n%%\n\"{0}\" \n%%\n)  by DNS.src DNS.query | `drop_dm_object_name(\"DNS\")` | `get_asset(src)` | fields query, src, src_asset_id, src_dns, src_ip, src_owner |rename src_owner as src_user | fillnull value=\"Unknown\""""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:input_filter:condition_3:playbook_input:domain"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="build_domain_query")

    run_domain_query(container=container)

    return


@phantom.playbook_block()
def build_ip_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_ip_query() called")

    ################################################################################
    # Query may need editing to reflect your splunk environment
    ################################################################################

    template = """count fillnull_value=\"Unknown\" from datamodel=Network_Traffic where  All_Traffic.dest_ip IN (\n%%\n\"{0}\" \n%%\n)  by All_Traffic.src All_Traffic.user All_Traffic.dest_ip | `drop_dm_object_name(\"All_Traffic\")` | `get_asset(src)` | fields src, src_asset_id, src_dns, src_ip, dest_ip, user | fillnull value=\"Unknown\""""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:input_filter:condition_4:playbook_input:ip"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="build_ip_query")

    run_ip_query(container=container)

    return


@phantom.playbook_block()
def run_url_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_url_query() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # May need to change search command dependent on your format block
    ################################################################################

    build_url_query = phantom.get_format_data(name="build_url_query")

    parameters = []

    if build_url_query is not None:
        parameters.append({
            "query": build_url_query,
            "command": "tstats",
            "start_time": "-30d",
            "search_mode": "smart",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_url_query", assets=["splunk"], callback=filter_url_query)

    return


@phantom.playbook_block()
def run_file_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_file_query() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # May need to change search command dependent on your format block
    ################################################################################

    build_file_query = phantom.get_format_data(name="build_file_query")

    parameters = []

    if build_file_query is not None:
        parameters.append({
            "query": build_file_query,
            "command": "tstats",
            "start_time": "-30d",
            "search_mode": "smart",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_file_query", assets=["splunk"], callback=filter_file_query)

    return


@phantom.playbook_block()
def run_domain_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_domain_query() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # May need to change search command dependent on your format block
    ################################################################################

    build_domain_query = phantom.get_format_data(name="build_domain_query")

    parameters = []

    if build_domain_query is not None:
        parameters.append({
            "query": build_domain_query,
            "command": "tstats",
            "start_time": "-30d",
            "search_mode": "smart",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_domain_query", assets=["splunk"], callback=filter_domain_query)

    return


@phantom.playbook_block()
def run_ip_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_ip_query() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # May need to change search command dependent on your format block
    ################################################################################

    build_ip_query = phantom.get_format_data(name="build_ip_query")

    parameters = []

    if build_ip_query is not None:
        parameters.append({
            "query": build_ip_query,
            "command": "tstats",
            "display": "src, src_asset_id, src_dns, src_ip",
            "start_time": "-30d",
            "search_mode": "smart",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_ip_query", assets=["splunk"], callback=filter_ip_query)

    return


@phantom.playbook_block()
def filter_url_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_url_query() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["run_url_query:action_result.summary.total_events", ">", 0]
        ],
        name="filter_url_query:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_url_report(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_file_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_file_query() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["run_file_query:action_result.summary.total_events", ">", 0]
        ],
        name="filter_file_query:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_file_report(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_domain_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_domain_query() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["run_domain_query:action_result.summary.total_events", ">", 0]
        ],
        name="filter_domain_query:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_domain_report(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_ip_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_ip_query() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["run_ip_query:action_result.summary.total_events", ">", 0]
        ],
        name="filter_ip_query:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_ip_report(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_url_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_url_report() called")

    ################################################################################
    # Markdown report used in calling playbook
    ################################################################################

    template = """SOAR searched for occurrences of `{0}` within your environment using Splunk. The table below shows a summary of the information gathered.\n\n| URL | Computer | IP Address | Asset ID | User | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} | {4} | Splunk |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:input_filter:condition_1:playbook_input:url",
        "filtered-data:filter_url_query:condition_1:run_url_query:action_result.data.*.src_dns",
        "filtered-data:filter_url_query:condition_1:run_url_query:action_result.data.*.src_ip",
        "filtered-data:filter_url_query:condition_1:run_url_query:action_result.data.*.src_asset_id",
        "filtered-data:filter_url_query:condition_1:run_url_query:action_result.data.*.user"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_url_report", drop_none=True)

    build_url_output(container=container)

    return


@phantom.playbook_block()
def format_file_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_file_report() called")

    ################################################################################
    # Markdown report used in calling playbook
    ################################################################################

    template = """SOAR searched for occurrences of `{0}` within your environment using Splunk. The table below shows a summary of the information gathered.\n\n| File | Process Name | Computer | IP Address | Asset ID | User | Source |\n| --- | --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {5} | {1} | {2} | {3} | {4} | Splunk |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:input_filter:condition_2:playbook_input:file",
        "filtered-data:filter_file_query:condition_1:run_file_query:action_result.data.*.dest_dns",
        "filtered-data:filter_file_query:condition_1:run_file_query:action_result.data.*.dest_ip",
        "filtered-data:filter_file_query:condition_1:run_file_query:action_result.data.*.dest_asset_id",
        "filtered-data:filter_file_query:condition_1:run_file_query:action_result.data.*.user",
        "filtered-data:filter_file_query:condition_1:run_file_query:action_result.data.*.process_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_file_report", drop_none=True)

    build_file_output(container=container)

    return


@phantom.playbook_block()
def format_domain_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_domain_report() called")

    ################################################################################
    # Markdown report used in calling playbook
    ################################################################################

    template = """SOAR searched for occurrences of `{0}` within your environment using Splunk. The table below shows a summary of the information gathered.\n\n| Domain | Computer | IP Address | Asset ID | User | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} | {4} | Splunk |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:input_filter:condition_3:playbook_input:domain",
        "filtered-data:filter_domain_query:condition_1:run_domain_query:action_result.data.*.src_dns",
        "filtered-data:filter_domain_query:condition_1:run_domain_query:action_result.data.*.src_ip",
        "filtered-data:filter_domain_query:condition_1:run_domain_query:action_result.data.*.src_asset_id",
        "filtered-data:filter_domain_query:condition_1:run_domain_query:action_result.data.*.src_user"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_domain_report", drop_none=True)

    build_domain_output(container=container)

    return


@phantom.playbook_block()
def format_ip_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_ip_report() called")

    ################################################################################
    # Markdown report used in calling playbook
    ################################################################################

    template = """SOAR searched for occurrences of `{0}` within your environment using Splunk. The table below shows a summary of the information gathered.\n\n| IP | Computer | IP Address | Asset ID | User | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} | {4} | Splunk |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:input_filter:condition_4:playbook_input:ip",
        "filtered-data:filter_ip_query:condition_1:run_ip_query:action_result.data.*.src_dns",
        "filtered-data:filter_ip_query:condition_1:run_ip_query:action_result.data.*.src_ip",
        "filtered-data:filter_ip_query:condition_1:run_ip_query:action_result.data.*.src_asset_id",
        "filtered-data:filter_ip_query:condition_1:run_ip_query:action_result.data.*.user"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_report", drop_none=True)

    build_ip_output(container=container)

    return


@phantom.playbook_block()
def build_url_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_url_output() called")

    ################################################################################
    # Observable object expected by calling playbook
    ################################################################################

    filtered_result_0_data_filter_url_query = phantom.collect2(container=container, datapath=["filtered-data:filter_url_query:condition_1:run_url_query:action_result.data.*.url","filtered-data:filter_url_query:condition_1:run_url_query:action_result.data.*.src_dns","filtered-data:filter_url_query:condition_1:run_url_query:action_result.data.*.src_ip","filtered-data:filter_url_query:condition_1:run_url_query:action_result.data.*.src_asset_id","filtered-data:filter_url_query:condition_1:run_url_query:action_result.data.*.user"])

    filtered_result_0_data___url = [item[0] for item in filtered_result_0_data_filter_url_query]
    filtered_result_0_data___src_dns = [item[1] for item in filtered_result_0_data_filter_url_query]
    filtered_result_0_data___src_ip = [item[2] for item in filtered_result_0_data_filter_url_query]
    filtered_result_0_data___src_asset_id = [item[3] for item in filtered_result_0_data_filter_url_query]
    filtered_result_0_data___user = [item[4] for item in filtered_result_0_data_filter_url_query]

    build_url_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Init variables + convenience naming
    build_url_output__observable_array = []
    observable_dict = {}
    
    # Build device list
    for indicator, dns, ip, asset_id, user in zip(filtered_result_0_data___url, filtered_result_0_data___src_dns, filtered_result_0_data___src_ip, filtered_result_0_data___src_asset_id, filtered_result_0_data___user): 
        
        device = {
            "name": dns,
            "id": asset_id, 
            "ip_address": ip,
            "operating_system": "Unknown",
            "user": user
        }

        # Drop devices from list if we don't know anything about them
        if device.get("name") == "Unknown" and device.get("id") == "Unknown" and device.get("ip_address") == "Unknown" and device.get("user") == "Unknown":
            continue

        # Add to or update observable_dict
        if observable_dict.get('indicator'):
            observable_dict['identifier_activity'].append(device)
        else:
            observable_dict[indicator] ={
                "value": indicator,
                "type": "url",
                "source": "Splunk",
                "identifier_activity": [device]
            }

    for key in observable_dict.keys():
        observable_dict[key]['total_count'] = len(observable_dict[key]['identifier_activity'])
        build_url_output__observable_array.append(observable_dict[key])

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_url_output:observable_array", value=json.dumps(build_url_output__observable_array))

    return


@phantom.playbook_block()
def build_file_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_file_output() called")

    ################################################################################
    # Observable object expected by calling playbook
    ################################################################################

    filtered_result_0_data_filter_file_query = phantom.collect2(container=container, datapath=["filtered-data:filter_file_query:condition_1:run_file_query:action_result.data.*.process_hash","filtered-data:filter_file_query:condition_1:run_file_query:action_result.data.*.dest_dns","filtered-data:filter_file_query:condition_1:run_file_query:action_result.data.*.dest_ip","filtered-data:filter_file_query:condition_1:run_file_query:action_result.data.*.dest_asset_id","filtered-data:filter_file_query:condition_1:run_file_query:action_result.data.*.user"])

    filtered_result_0_data___process_hash = [item[0] for item in filtered_result_0_data_filter_file_query]
    filtered_result_0_data___dest_dns = [item[1] for item in filtered_result_0_data_filter_file_query]
    filtered_result_0_data___dest_ip = [item[2] for item in filtered_result_0_data_filter_file_query]
    filtered_result_0_data___dest_asset_id = [item[3] for item in filtered_result_0_data_filter_file_query]
    filtered_result_0_data___user = [item[4] for item in filtered_result_0_data_filter_file_query]

    build_file_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    
    # Init variables + convenience naming
    build_file_output__observable_array = []
    observable_dict = {}
    
    # Build device list
    for indicator, dns, ip, asset_id, user in zip(filtered_result_0_data___process_hash, filtered_result_0_data___dest_dns, filtered_result_0_data___dest_ip, filtered_result_0_data___dest_asset_id, filtered_result_0_data___user): 
        
        device = {
            "name": dns,
            "id": asset_id, 
            "ip_address": ip,
            "operating_system": "Unknown",
            "user": user
        }

        # Drop devices from list if we don't know anything about them
        if device.get("name") == "Unknown" and device.get("id") == "Unknown" and device.get("ip_address") == "Unknown" and device.get("user") == "Unknown":
            continue

        # Add to or update observable_dict
        if observable_dict.get('indicator'):
            observable_dict['identifier_activity'].append(device)
        else:
            observable_dict[indicator] ={
                "value": indicator,
                "type": "hash",
                "source": "Splunk",
                "identifier_activity": [device]
            }

    for key in observable_dict.keys():
        observable_dict[key]['total_count'] = len(observable_dict[key]['identifier_activity'])
        build_file_output__observable_array.append(observable_dict[key])

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_file_output:observable_array", value=json.dumps(build_file_output__observable_array))

    return


@phantom.playbook_block()
def build_domain_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_domain_output() called")

    ################################################################################
    # Observable object expected by calling playbook
    ################################################################################

    filtered_result_0_data_filter_domain_query = phantom.collect2(container=container, datapath=["filtered-data:filter_domain_query:condition_1:run_domain_query:action_result.data.*.query","filtered-data:filter_domain_query:condition_1:run_domain_query:action_result.data.*.src_dns","filtered-data:filter_domain_query:condition_1:run_domain_query:action_result.data.*.src_ip","filtered-data:filter_domain_query:condition_1:run_domain_query:action_result.data.*.src_asset_id","filtered-data:filter_domain_query:condition_1:run_domain_query:action_result.data.*.src_user"])

    filtered_result_0_data___query = [item[0] for item in filtered_result_0_data_filter_domain_query]
    filtered_result_0_data___src_dns = [item[1] for item in filtered_result_0_data_filter_domain_query]
    filtered_result_0_data___src_ip = [item[2] for item in filtered_result_0_data_filter_domain_query]
    filtered_result_0_data___src_asset_id = [item[3] for item in filtered_result_0_data_filter_domain_query]
    filtered_result_0_data___src_user = [item[4] for item in filtered_result_0_data_filter_domain_query]

    build_domain_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Init variables + convenience naming
    build_domain_output__observable_array = []
    observable_dict = {}
    
    # Build device list
    for indicator, dns, ip, asset_id, user in zip(filtered_result_0_data___query, filtered_result_0_data___src_dns, filtered_result_0_data___src_ip, filtered_result_0_data___src_asset_id, filtered_result_0_data___src_user): 
        
        device = {
            "name": dns,
            "id": asset_id, 
            "ip_address": ip,
            "operating_system": "Unknown",
            "user": user
        }

        # Drop devices from list if we don't know anything about them
        if device.get("name") == "Unknown" and device.get("id") == "Unknown" and device.get("ip_address") == "Unknown" and device.get("user") == "Unknown":
            continue

        # Add to or update observable_dict
        if observable_dict.get('indicator'):
            observable_dict['identifier_activity'].append(device)
        else:
            observable_dict[indicator] ={
                "value": indicator,
                "type": "url",
                "source": "Splunk",
                "identifier_activity": [device]
            }

    for key in observable_dict.keys():
        observable_dict[key]['total_count'] = len(observable_dict[key]['identifier_activity'])
        build_domain_output__observable_array.append(observable_dict[key])
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_domain_output:observable_array", value=json.dumps(build_domain_output__observable_array))

    return


@phantom.playbook_block()
def build_ip_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_ip_output() called")

    ################################################################################
    # Observable object expected by calling playbook
    ################################################################################

    filtered_result_0_data_filter_ip_query = phantom.collect2(container=container, datapath=["filtered-data:filter_ip_query:condition_1:run_ip_query:action_result.data.*.dest_ip","filtered-data:filter_ip_query:condition_1:run_ip_query:action_result.data.*.src_dns","filtered-data:filter_ip_query:condition_1:run_ip_query:action_result.data.*.src_ip","filtered-data:filter_ip_query:condition_1:run_ip_query:action_result.data.*.src_asset_id","filtered-data:filter_ip_query:condition_1:run_ip_query:action_result.data.*.user"])

    filtered_result_0_data___dest_ip = [item[0] for item in filtered_result_0_data_filter_ip_query]
    filtered_result_0_data___src_dns = [item[1] for item in filtered_result_0_data_filter_ip_query]
    filtered_result_0_data___src_ip = [item[2] for item in filtered_result_0_data_filter_ip_query]
    filtered_result_0_data___src_asset_id = [item[3] for item in filtered_result_0_data_filter_ip_query]
    filtered_result_0_data___user = [item[4] for item in filtered_result_0_data_filter_ip_query]

    build_ip_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    # Init variables + convenience naming
    build_ip_output__observable_array = []
    observable_dict = {}

    # Build device list
    for indicator, dns, ip, asset_id, user in zip(filtered_result_0_data___dest_ip, filtered_result_0_data___src_dns, filtered_result_0_data___src_ip, filtered_result_0_data___src_asset_id, filtered_result_0_data___user): 
        
        device = {
            "name": dns,
            "id": asset_id, 
            "ip_address": ip,
            "operating_system": "Unknown",
            "user": user
        }

        # Drop devices from list if we don't know anything about them
        if device.get("name") == "Unknown" and device.get("id") == "Unknown" and device.get("ip_address") == "Unknown" and device.get("user") == "Unknown":
            continue

        # Add to or update observable_dict
        if observable_dict.get('indicator'):
            observable_dict['identifier_activity'].append(device)
        else:
            observable_dict[indicator] ={
                "value": indicator,
                "type": "url",
                "source": "Splunk",
                "identifier_activity": [device]
            }

    for key in observable_dict.keys():
        observable_dict[key]['total_count'] = len(observable_dict[key]['identifier_activity'])
        build_ip_output__observable_array.append(observable_dict[key])
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_ip_output:observable_array", value=json.dumps(build_ip_output__observable_array))

    return


@phantom.playbook_block()
def parse_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("parse_url() called")

    playbook_input_url = phantom.collect2(container=container, datapath=["playbook_input:url"])

    parameters = []

    # build parameters list for 'parse_url' call
    for playbook_input_url_item in playbook_input_url:
        parameters.append({
            "input_url": playbook_input_url_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/url_parse", parameters=parameters, name="parse_url", callback=build_url_query)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_url_report = phantom.get_format_data(name="format_url_report")
    format_file_report = phantom.get_format_data(name="format_file_report")
    format_domain_report = phantom.get_format_data(name="format_domain_report")
    format_ip_report = phantom.get_format_data(name="format_ip_report")
    build_url_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_url_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    build_domain_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_domain_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    build_ip_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_ip_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    build_file_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_file_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    observable_combined_value = phantom.concatenate(build_url_output__observable_array, build_domain_output__observable_array, build_ip_output__observable_array, build_file_output__observable_array)
    markdown_report_combined_value = phantom.concatenate(format_url_report, format_file_report, format_domain_report, format_ip_report)

    output = {
        "observable": observable_combined_value,
        "markdown_report": markdown_report_combined_value,
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