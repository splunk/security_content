"""
Accepts a domain or list of domains as input. Blocks the given domains in Cisco Umbrella.\n\nhttps://d3fend.mitre.org/technique/d3f:DNSDenylisting/
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'domain_input_filter' block
    domain_input_filter(container=container)

    return

@phantom.playbook_block()
def domain_input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("domain_input_filter() called")

    ################################################################################
    # Determine branches based on provided inputs.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:domain", "!=", None]
        ],
        name="domain_input_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_domain(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def block_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("block_domain() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Block domains in Cisco Umbrella based on given domains. 
    ################################################################################

    playbook_input_domain = phantom.collect2(container=container, datapath=["playbook_input:domain"])

    parameters = []

    # build parameters list for 'block_domain' call
    for playbook_input_domain_item in playbook_input_domain:
        if playbook_input_domain_item[0] is not None:
            parameters.append({
                "domain": playbook_input_domain_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("block domain", parameters=parameters, name="block_domain", assets=["cisco_umbrella"], callback=success_filter)

    return


@phantom.playbook_block()
def build_observable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_observable() called")

    ################################################################################
    # This block uses custom code to generate an observable dictionary to output into 
    # the observables data path.
    ################################################################################

    filtered_result_0_data_success_filter = phantom.collect2(container=container, datapath=["filtered-data:success_filter:condition_1:block_domain:action_result.parameter.domain","filtered-data:success_filter:condition_1:block_domain:action_result.status"])

    filtered_result_0_parameter_domain = [item[0] for item in filtered_result_0_data_success_filter]
    filtered_result_0_status = [item[1] for item in filtered_result_0_data_success_filter]

    build_observable__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    build_observable__observable_array = list()
    for status, domain in zip(filtered_result_0_status, filtered_result_0_parameter_domain):
        if status == "success":
            observable = {
                "type": "domain",
                "value": domain,
                "source": "Cisco Umbrella",
                "status": "blocked"
            }
            
            build_observable__observable_array.append(observable)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_observable:observable_array", value=json.dumps(build_observable__observable_array))

    return


@phantom.playbook_block()
def success_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("success_filter() called")

    ################################################################################
    # Determine if the block domain was successful.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["block_domain:action_result.status", "==", "success"]
        ],
        name="success_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        build_observable(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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