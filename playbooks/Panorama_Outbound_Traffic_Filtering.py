"""
Accepts a URL or list of URLs as input. Uses Panorama to block the given URLs in Palo Alto Firewall.\n\nhttps://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering/
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'url_input_filter' block
    url_input_filter(container=container)

    return

@phantom.playbook_block()
def url_input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("url_input_filter() called")

    ################################################################################
    # Check if input url contains a value
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:input_url", "!=", None]
        ],
        name="url_input_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_url(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def block_url_success_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("block_url_success_filter() called")

    ################################################################################
    # Determine if the block url action was successful or not.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["block_url:action_result.status", "==", "success"]
        ],
        name="block_url_success_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        build_observable(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def build_observable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_observable() called")

    ################################################################################
    # This block uses custom code to generate a normalized observable dictionary.
    ################################################################################

    filtered_input_0_input_url = phantom.collect2(container=container, datapath=["filtered-data:url_input_filter:condition_1:playbook_input:input_url"])
    block_url_result_data = phantom.collect2(container=container, datapath=["block_url:action_result.status"], action_results=results)

    filtered_input_0_input_url_values = [item[0] for item in filtered_input_0_input_url]
    block_url_result_item_0 = [item[0] for item in block_url_result_data]

    build_observable__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    build_observable__observable_array = list()
    for status, url in zip(block_url_result_item_0, filtered_input_0_input_url_values):
        observable = {
            "type": "url",
            "value": url,
            "source": "Panorama",
            "status": status
        }
            
        build_observable__observable_array.append(observable)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_observable:observable_array", value=json.dumps(build_observable__observable_array))

    return


@phantom.playbook_block()
def block_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("block_url() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Block urls in Panorama
    ################################################################################

    filtered_input_0_input_url = phantom.collect2(container=container, datapath=["filtered-data:url_input_filter:condition_1:playbook_input:input_url"])

    parameters = []

    # build parameters list for 'block_url' call
    for filtered_input_0_input_url_item in filtered_input_0_input_url:
        if filtered_input_0_input_url_item[0] is not None:
            parameters.append({
                "url": filtered_input_0_input_url_item[0],
                "device_group": "shared",
                "should_commit_changes": True,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("block url", parameters=parameters, name="block_url", assets=["panorama"], callback=block_url_success_filter)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    build_observable__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_observable:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "observable": build_observable__observable_array,
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