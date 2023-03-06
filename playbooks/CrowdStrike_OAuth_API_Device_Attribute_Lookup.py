"""
Accepts device and looks up the most recent attributes for that hostname or IP. This playbook produces a normalized output for each device.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'device_id_input_filter' block
    device_id_input_filter(container=container)

    return

@phantom.playbook_block()
def device_id_input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("device_id_input_filter() called")

    ################################################################################
    # Ensure that device input exists
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:device", "!=", None]
        ],
        name="device_id_input_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        extract_ipv4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def query_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("query_hostname() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Search for devices that have the hostname given to playbook input.
    ################################################################################

    format_hostname_filter__as_list = phantom.get_format_data(name="format_hostname_filter__as_list")

    parameters = []

    # build parameters list for 'query_hostname' call
    for format_hostname_filter__item in format_hostname_filter__as_list:
        parameters.append({
            "limit": 10,
            "filter": format_hostname_filter__item,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("query device", parameters=parameters, name="query_hostname", assets=["crowdstrike"], callback=filter_hostname_results)

    return


@phantom.playbook_block()
def build_hostname_observables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_hostname_observables() called")

    ################################################################################
    # Generate an observable dictionary to output into the observables data path.
    ################################################################################

    filtered_result_0_data_filter_hostname_results = phantom.collect2(container=container, datapath=["filtered-data:filter_hostname_results:condition_1:query_hostname:action_result.data","filtered-data:filter_hostname_results:condition_1:query_hostname:action_result.parameter.filter"])

    filtered_result_0_data = [item[0] for item in filtered_result_0_data_filter_hostname_results]
    filtered_result_0_parameter_filter = [item[1] for item in filtered_result_0_data_filter_hostname_results]

    build_hostname_observables__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    build_hostname_observables__observable_array = []
    device_type_dict = {
        'server': 1,
        'desktop': 2,
        'laptop': 3,
        'tablet': 4,
        'mobile': 5,
        'virtual': 6,
        'iot': 7,
        'browser': 8
    }
    for item, input_string in zip(filtered_result_0_data, filtered_result_0_parameter_filter):
        device = item[0]
        device_dict = {
            "type": "host name",
            "value": input_string.replace("hostname:", "").replace('"', ""),
            "source": "Crowdstrike OAuth API",
            "attributes": {
                "desc": f"{device.get('system_product_name', 'No product name')} - {device.get('os_product_name', 'No os name')}",
                "groups": device.get('groups'),
                "hostname": device.get('hostname'),
                "ip": device.get('connection_ip'),
                "mac": device.get('mac_address'),
                "name": device.get('hostname'),
                "os": device.get('os_version'),
                "hw_info": {
                    "bios_manufacturer": device.get('bios_manufacturer'),
                    "bios_ver": device.get('bios_version'),
                    "serial_number": device.get('serial_number')
                },
                "type": "Unknown",
                "type_id": 0,
                "uid": device.get('device_id')        
            }
        }
        if device.get('product_type_desc'):
            if device_type_dict.get(device['product_type_desc'].lower()):
                device_dict['attributes']['type'] = device['product_type_desc']
                device_dict['attributes']['type_id'] = device_type_dict[device['product_type_desc'].lower()]
            else:
                device_dict['attributes']['type'] = device['product_type_desc']
                device_dict['attributes']['type_id'] = 99

        build_hostname_observables__observable_array.append(device_dict)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_hostname_observables:observable_array", value=json.dumps(build_hostname_observables__observable_array))

    return


@phantom.playbook_block()
def format_hostname_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_hostname_filter() called")

    ################################################################################
    # Format a filter for the query device, while looping through playbook inputs.
    ################################################################################

    template = """%%\nhostname:\"{0}\"\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:ip_filter:condition_2:extract_ipv4:custom_function_result.data.input_value"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_hostname_filter")

    query_hostname(container=container)

    return


@phantom.playbook_block()
def extract_ipv4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("extract_ipv4() called")

    ################################################################################
    # Extract IP address from input device
    ################################################################################

    filtered_input_0_device = phantom.collect2(container=container, datapath=["filtered-data:device_id_input_filter:condition_1:playbook_input:device"])

    parameters = []

    # build parameters list for 'extract_ipv4' call
    for filtered_input_0_device_item in filtered_input_0_device:
        parameters.append({
            "input_string": filtered_input_0_device_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/regex_extract_ipv4", parameters=parameters, name="extract_ipv4", callback=ip_filter)

    return


@phantom.playbook_block()
def ip_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ip_filter() called")

    ################################################################################
    # Determine which of the playbook inputs are devices or hostnames
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["extract_ipv4:custom_function_result.data.extracted_ipv4", "!=", None]
        ],
        name="ip_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_ip_filter(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["extract_ipv4:custom_function_result.data.extracted_ipv4", "==", None]
        ],
        name="ip_filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        format_hostname_filter(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def format_ip_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_ip_filter() called")

    ################################################################################
    # Format a filter for the query device, while looping through playbook inputs.
    ################################################################################

    template = """%%\nlocal_ip:\"{0}\",external_ip:\"{0}\"\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:ip_filter:condition_1:extract_ipv4:custom_function_result.data.extracted_ipv4"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_filter")

    query_ip(container=container)

    return


@phantom.playbook_block()
def query_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("query_ip() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Search for devices that have the IP given to playbook input.
    ################################################################################

    format_ip_filter__as_list = phantom.get_format_data(name="format_ip_filter__as_list")

    parameters = []

    # build parameters list for 'query_ip' call
    for format_ip_filter__item in format_ip_filter__as_list:
        parameters.append({
            "limit": 10,
            "filter": format_ip_filter__item,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("query device", parameters=parameters, name="query_ip", assets=["crowdstrike"], callback=filter_ip_results)

    return


@phantom.playbook_block()
def build_ip_observables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_ip_observables() called")

    ################################################################################
    # Generate an observable dictionary to output into the observables data path.
    ################################################################################

    filtered_result_0_data_filter_ip_results = phantom.collect2(container=container, datapath=["filtered-data:filter_ip_results:condition_1:query_ip:action_result.data","filtered-data:filter_ip_results:condition_1:query_ip:action_result.parameter.filter"])

    filtered_result_0_data = [item[0] for item in filtered_result_0_data_filter_ip_results]
    filtered_result_0_parameter_filter = [item[1] for item in filtered_result_0_data_filter_ip_results]

    build_ip_observables__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    build_ip_observables__observable_array = []
    device_type_dict = {
        'server': 1,
        'desktop': 2,
        'laptop': 3,
        'tablet': 4,
        'mobile': 5,
        'virtual': 6,
        'iot': 7,
        'browser': 8
    }
    for item, input_string in zip(filtered_result_0_data, filtered_result_0_parameter_filter):
        device = item[0]
        value = input_string.replace("local_ip:", "").replace('external_ip', "").replace('"',"")
        value = value.split(',')[0]
        device_dict = {
            "type": "ip",
            "value": value,
            "source": "Crowdstrike OAuth API",
            "attributes": {
                "desc": f"{device.get('system_product_name', 'No product name')} - {device.get('os_product_name', 'No os name')}",
                "groups": device.get('groups'),
                "hostname": device.get('hostname'),
                "ip": device.get('connection_ip'),
                "mac": device.get('mac_address'),
                "name": device.get('hostname'),
                "os": device.get('os_version'),
                "hw_info": {
                    "bios_manufacturer": device.get('bios_manufacturer'),
                    "bios_ver": device.get('bios_version'),
                    "serial_number": device.get('serial_number')
                },
                "type": "Unknown",
                "type_id": 0,
                "uid": device.get('device_id')        
            }
        }
        if device.get('product_type_desc'):
            if device_type_dict.get(device['product_type_desc'].lower()):
                device_dict['attributes']['type'] = device['product_type_desc']
                device_dict['attributes']['type_id'] = device_type_dict[device['product_type_desc'].lower()]
            else:
                device_dict['attributes']['type'] = device['product_type_desc']
                device_dict['attributes']['type_id'] = 99

        build_ip_observables__observable_array.append(device_dict)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_ip_observables:observable_array", value=json.dumps(build_ip_observables__observable_array))

    return


@phantom.playbook_block()
def filter_hostname_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_hostname_results() called")

    ################################################################################
    # Filter on hostnames that returned results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["query_hostname:action_result.summary.total_devices", ">", 0]
        ],
        name="filter_hostname_results:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        build_hostname_observables(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_ip_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_ip_results() called")

    ################################################################################
    # Filter on IPs that returned results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["query_ip:action_result.summary.total_devices", ">", 0]
        ],
        name="filter_ip_results:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        build_ip_observables(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    build_ip_observables__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_ip_observables:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    build_hostname_observables__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_hostname_observables:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    observable_combined_value = phantom.concatenate(build_ip_observables__observable_array, build_hostname_observables__observable_array)

    output = {
        "observable": observable_combined_value,
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