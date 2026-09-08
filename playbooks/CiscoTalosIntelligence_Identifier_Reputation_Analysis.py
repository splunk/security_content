"""
Accepts a URL, IP or Domain and does reputation analysis on the objects. Generates a threat level, threat categories and AUP categories that are formatted and added to a container as a note.
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
    # Filter to pass in a url, domain or ip to it's appropriate action
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:url", "!=", ""]
        ],
        name="input_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        url_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:domain", "!=", ""]
        ],
        name="input_filter:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        domain_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:ip", "!=", ""]
        ],
        name="input_filter:condition_3",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        ip_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return


@phantom.playbook_block()
def url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Use Talos to get threat data on an url
    ################################################################################

    filtered_input_0_url = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_1:playbook_input:url"])

    parameters = []

    # build parameters list for 'url_reputation' call
    for filtered_input_0_url_item in filtered_input_0_url:
        if filtered_input_0_url_item[0] is not None:
            parameters.append({
                "url": filtered_input_0_url_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url reputation", parameters=parameters, name="url_reputation", assets=["cisco_talos_intelligence"], callback=url_reputation_filter)

    return


@phantom.playbook_block()
def domain_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("domain_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Use Talos to get threat data on a domain
    ################################################################################

    filtered_input_0_domain = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_2:playbook_input:domain"])

    parameters = []

    # build parameters list for 'domain_reputation' call
    for filtered_input_0_domain_item in filtered_input_0_domain:
        if filtered_input_0_domain_item[0] is not None:
            parameters.append({
                "domain": filtered_input_0_domain_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("domain reputation", parameters=parameters, name="domain_reputation", assets=["cisco_talos_intelligence"], callback=domain_reputation_filter)

    return


@phantom.playbook_block()
def ip_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ip_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Use Talos to get threat data on an ip
    ################################################################################

    filtered_input_0_ip = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_3:playbook_input:ip"])

    parameters = []

    # build parameters list for 'ip_reputation' call
    for filtered_input_0_ip_item in filtered_input_0_ip:
        if filtered_input_0_ip_item[0] is not None:
            parameters.append({
                "ip": filtered_input_0_ip_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip reputation", parameters=parameters, name="ip_reputation", assets=["cisco_talos_intelligence"], callback=ip_reputation_filter)

    return


@phantom.playbook_block()
def url_reputation_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_reputation_filter() called")

    ################################################################################
    # Exclude failing url reputations
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["url_reputation:action_result.status", "==", "success"]
        ],
        name="url_reputation_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def domain_reputation_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("domain_reputation_filter() called")

    ################################################################################
    # Exclude failing domain reputations
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["domain_reputation:action_result.status", "==", "success"]
        ],
        name="domain_reputation_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def ip_reputation_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ip_reputation_filter() called")

    ################################################################################
    # Exclude failing ip reputations
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["ip_reputation:action_result.status", "==", "success"]
        ],
        name="ip_reputation_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_2() called")

    ################################################################################
    # Format output of domain threat data into an appropriate format for build_domain_output 
    # that generates observable objects.
    ################################################################################

    template = """SOAR analyzed Domain using Talos Intelligence.  The table below shows a summary of the information gathered.\n\n| Domain | Threat Level | Threat Categories | AUP Categories |\n| --- | --- | --- | --- |\n%%\n| {0} | {1} | {2} | {3}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:domain_reputation_filter:condition_1:domain_reputation:action_result.data.*.Observable",
        "filtered-data:domain_reputation_filter:condition_1:domain_reputation:action_result.data.*.Threat_Level",
        "filtered-data:domain_reputation_filter:condition_1:domain_reputation:action_result.data.*.Threat_Categories",
        "filtered-data:domain_reputation_filter:condition_1:domain_reputation:action_result.data.*.AUP"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    build_domain_output(container=container)

    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_1() called")

    ################################################################################
    # Format output of url threat data into an appropriate format for build_url_output 
    # that generates observable objects.
    ################################################################################

    template = """SOAR analyzed URL using Talos Intelligence.  The table below shows a summary of the information gathered.\n\n| URL | Threat Level | Threat Categories | AUP Categories |\n| --- | --- | --- | --- |\n%%\n| {0} | {1} | {2} | {3}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:url_reputation_filter:condition_1:url_reputation:action_result.data.*.Observable",
        "filtered-data:url_reputation_filter:condition_1:url_reputation:action_result.data.*.Threat_Level",
        "filtered-data:url_reputation_filter:condition_1:url_reputation:action_result.data.*.Threat_Categories",
        "filtered-data:url_reputation_filter:condition_1:url_reputation:action_result.data.*.AUP"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    build_url_output(container=container)

    return


@phantom.playbook_block()
def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_3() called")

    ################################################################################
    # Format output of ip threat data into an appropriate format for build_ip_output 
    # that generates observable objects. 
    ################################################################################

    template = """SOAR analyzed IP using Talos Intelligence.  The table below shows a summary of the information gathered.\n\n| IP | Threat Level | Threat Categories | AUP Categories |\n| --- | --- | --- | --- |\n%%\n| {0} | {1} | {2} | {3}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:ip_reputation_filter:condition_1:ip_reputation:action_result.data.*.Observable",
        "filtered-data:ip_reputation_filter:condition_1:ip_reputation:action_result.data.*.Threat_Level",
        "filtered-data:ip_reputation_filter:condition_1:ip_reputation:action_result.data.*.Threat_Categories",
        "filtered-data:ip_reputation_filter:condition_1:ip_reputation:action_result.data.*.AUP"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    build_ip_output(container=container)

    return


@phantom.playbook_block()
def build_url_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_url_output() called")

    ################################################################################
    # Generate an observable dictionary to output into the observables data path.
    ################################################################################

    filtered_result_0_data_url_reputation_filter = phantom.collect2(container=container, datapath=["filtered-data:url_reputation_filter:condition_1:url_reputation:action_result.data.*.Observable","filtered-data:url_reputation_filter:condition_1:url_reputation:action_result.data.*.Threat_Level","filtered-data:url_reputation_filter:condition_1:url_reputation:action_result.data.*.Threat_Categories","filtered-data:url_reputation_filter:condition_1:url_reputation:action_result.data.*.AUP"])

    filtered_result_0_data___observable = [item[0] for item in filtered_result_0_data_url_reputation_filter]
    filtered_result_0_data___threat_level = [item[1] for item in filtered_result_0_data_url_reputation_filter]
    filtered_result_0_data___threat_categories = [item[2] for item in filtered_result_0_data_url_reputation_filter]
    filtered_result_0_data___aup = [item[3] for item in filtered_result_0_data_url_reputation_filter]

    build_url_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    from urllib.parse import urlparse
    build_url_output__observable_array = []
    
    talos_to_score_mapping = {"unknown": "Unknown", "trusted": "Safe", "favorable": "Probably_Safe", "neutral": "May_not_be_Safe", "questionable": "Suspicious_or_Risky", "unstrusted": "Malicious"}
    score_table = {
        "Unkown": "0",
        "Very_Safe": "1",
        "Safe": "2",
        "Probably_Safe": "3",
        "Leans_Safe": "4",
        "May_not_be_Safe": "5",
        "Exercise_Caution": "6",
        "Suspicious_or_Risky": "7",
        "Possibly_Malicious": "8",
        "Probably_Malicious": "9",
        "Malicious": "10"
    }
    
    for url, threat_level, threat_categories, aup in zip(filtered_result_0_data___observable, filtered_result_0_data___threat_level, filtered_result_0_data___threat_categories, filtered_result_0_data___aup):
        parsed_url = urlparse(url)
        score = talos_to_score_mapping.get(threat_level.lower(), "")
        observable_object = {
            "value": url,
            "type": "url",
            "reputation": {
                "threat_level": threat_level,
                "threat_categories": threat_categories,
                "aup_categories": aup,
                "score": score,
                "score_id": score_table.get(score, "")
            },
            "attributes": {
                "hostname": parsed_url.hostname,
                "scheme": parsed_url.scheme
            },
            "source": "Cisco Talos Intelligence",
        }
        if parsed_url.path:
            observable_object['attributes']['path'] = parsed_url.path
        if parsed_url.query:
            observable_object['attributes']['query'] = parsed_url.query
        if parsed_url.port:
            observable_object['attributes']['port'] = parsed_url.port
        
        build_url_output__observable_array.append(observable_object)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_url_output:observable_array", value=json.dumps(build_url_output__observable_array))

    return


@phantom.playbook_block()
def build_domain_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_domain_output() called")

    ################################################################################
    # Generate an observable dictionary to output into the observables data path.
    ################################################################################

    filtered_result_0_data_domain_reputation_filter = phantom.collect2(container=container, datapath=["filtered-data:domain_reputation_filter:condition_1:domain_reputation:action_result.data.*.Observable","filtered-data:domain_reputation_filter:condition_1:domain_reputation:action_result.data.*.Threat_Level","filtered-data:domain_reputation_filter:condition_1:domain_reputation:action_result.data.*.Threat_Categories","filtered-data:domain_reputation_filter:condition_1:domain_reputation:action_result.data.*.AUP"])

    filtered_result_0_data___observable = [item[0] for item in filtered_result_0_data_domain_reputation_filter]
    filtered_result_0_data___threat_level = [item[1] for item in filtered_result_0_data_domain_reputation_filter]
    filtered_result_0_data___threat_categories = [item[2] for item in filtered_result_0_data_domain_reputation_filter]
    filtered_result_0_data___aup = [item[3] for item in filtered_result_0_data_domain_reputation_filter]

    build_domain_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    build_domain_output__observable_array = []
    
    talos_to_score_mapping = {"unknown": "Unknown", "trusted": "Safe", "favorable": "Probably_Safe", "neutral": "May_not_be_Safe", "questionable": "Suspicious_or_Risky", "unstrusted": "Malicious"}
    score_table = {
        "Unkown": "0",
        "Very_Safe": "1",
        "Safe": "2",
        "Probably_Safe": "3",
        "Leans_Safe": "4",
        "May_not_be_Safe": "5",
        "Exercise_Caution": "6",
        "Suspicious_or_Risky": "7",
        "Possibly_Malicious": "8",
        "Probably_Malicious": "9",
        "Malicious": "10"
    }
    
    for domain, threat_level, threat_categories, aup in zip(filtered_result_0_data___observable, filtered_result_0_data___threat_level, filtered_result_0_data___threat_categories, filtered_result_0_data___aup):
        score = talos_to_score_mapping.get(threat_level.lower(), "")
        observable_object = {
            "value": domain,
            "type": "domain",
            "reputation": {
                "threat_level": threat_level,
                "threat_categories": threat_categories,
                "aup_categories": aup,
                "score": score,
                "score_id": score_table.get(score, "")
            },
            "source": "Cisco Talos Intelligence"
        }
        build_domain_output__observable_array.append(observable_object)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_domain_output:observable_array", value=json.dumps(build_domain_output__observable_array))

    return


@phantom.playbook_block()
def build_ip_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_ip_output() called")

    ################################################################################
    # Generate an observable dictionary to output into the observables data path.
    ################################################################################

    filtered_result_0_data_ip_reputation_filter = phantom.collect2(container=container, datapath=["filtered-data:ip_reputation_filter:condition_1:ip_reputation:action_result.data.*.Observable","filtered-data:ip_reputation_filter:condition_1:ip_reputation:action_result.data.*.Threat_Level","filtered-data:ip_reputation_filter:condition_1:ip_reputation:action_result.data.*.Threat_Categories","filtered-data:ip_reputation_filter:condition_1:ip_reputation:action_result.data.*.AUP"])

    filtered_result_0_data___observable = [item[0] for item in filtered_result_0_data_ip_reputation_filter]
    filtered_result_0_data___threat_level = [item[1] for item in filtered_result_0_data_ip_reputation_filter]
    filtered_result_0_data___threat_categories = [item[2] for item in filtered_result_0_data_ip_reputation_filter]
    filtered_result_0_data___aup = [item[3] for item in filtered_result_0_data_ip_reputation_filter]

    build_ip_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    import ipaddress
    build_ip_output__observable_array = []
    
    talos_to_score_mapping = {"unknown": "Unknown", "trusted": "Safe", "favorable": "Probably_Safe", "neutral": "May_not_be_Safe", "questionable": "Suspicious_or_Risky", "unstrusted": "Malicious"}
    score_table = {
        "Unkown": "0",
        "Very_Safe": "1",
        "Safe": "2",
        "Probably_Safe": "3",
        "Leans_Safe": "4",
        "May_not_be_Safe": "5",
        "Exercise_Caution": "6",
        "Suspicious_or_Risky": "7",
        "Possibly_Malicious": "8",
        "Probably_Malicious": "9",
        "Malicious": "10"
    }
    
    for ip, threat_level, threat_categories, aup in zip(filtered_result_0_data___observable, filtered_result_0_data___threat_level, filtered_result_0_data___threat_categories, filtered_result_0_data___aup):
        score = talos_to_score_mapping.get(threat_level.lower(), "")
        observable_object = {
            "value": ip,
            "type": "ipv4",
            "reputation": {
                "threat_level": threat_level,
                "threat_categories": threat_categories,
                "aup_categories": aup,
                "score": score,
                "score_id": score_table.get(score, "")
            },
            "source": "Cisco Talos Intelligence"
        }
        ip_addr = ipaddress.ip_address(ip)
        if isinstance(ip_addr, ipaddress.IPv6Address):
            observable_object["type"] = "ipv6"

        build_ip_output__observable_array.append(observable_object)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_ip_output:observable_array", value=json.dumps(build_ip_output__observable_array))

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_1 = phantom.get_format_data(name="format_1")
    format_2 = phantom.get_format_data(name="format_2")
    format_3 = phantom.get_format_data(name="format_3")
    build_url_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_url_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    build_domain_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_domain_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    build_ip_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_ip_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    observable_combined_value = phantom.concatenate(build_url_output__observable_array, build_domain_output__observable_array, build_ip_output__observable_array)
    markdown_report_combined_value = phantom.concatenate(format_1, format_2, format_3)

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