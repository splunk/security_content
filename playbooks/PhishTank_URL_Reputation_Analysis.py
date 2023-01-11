"""
Accepts a URL and does reputation analysis on the objects. Generates a global report and a per observable sub-report and normalized score. The score can be customized as desired.\n\nRef: https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'url_reputation' block
    url_reputation(container=container)

    return

@phantom.playbook_block()
def url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("url_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries PhishTank for information about the provided URL(s)
    ################################################################################

    playbook_input_url = phantom.collect2(container=container, datapath=["playbook_input:url"])

    parameters = []

    # build parameters list for 'url_reputation' call
    for playbook_input_url_item in playbook_input_url:
        if playbook_input_url_item[0] is not None:
            parameters.append({
                "url": playbook_input_url_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url reputation", parameters=parameters, name="url_reputation", assets=["phishtank"], callback=url_result_filter)

    return


@phantom.playbook_block()
def normalize_score_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalize_score_url() called")

    ################################################################################
    # Contains custom code for normalizing score. Adjust the logic as desired in the 
    # documented sections.
    ################################################################################

    filtered_result_0_data_url_result_filter = phantom.collect2(container=container, datapath=["filtered-data:url_result_filter:condition_1:url_reputation:action_result.summary.In_Database","filtered-data:url_result_filter:condition_1:url_reputation:action_result.summary.Valid","filtered-data:url_result_filter:condition_1:url_reputation:action_result.summary.Verified"])

    filtered_result_0_summary_in_database = [item[0] for item in filtered_result_0_data_url_result_filter]
    filtered_result_0_summary_valid = [item[1] for item in filtered_result_0_data_url_result_filter]
    filtered_result_0_summary_verified = [item[2] for item in filtered_result_0_data_url_result_filter]

    normalize_score_url__url_score_object = None
    normalize_score_url__scores = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    # Assign variables
    normalize_score_url__url_score_object = []
    normalize_score_url__scores = []
    in_database_list = filtered_result_0_summary_in_database
    valid_list = filtered_result_0_summary_valid
    verified_list = filtered_result_0_summary_verified
    
    
    # Reference for scores: https://schema.ocsf.io/objects/reputation
    score_table = {
        "-1": "Other",
        "0":"Unknown",
        "1":"Very_Safe",
        "2":"Safe",
        "3":"Probably_Safe",
        "4":"Leans_Safe",
        "5":"May_not_be_Safe",
        "6":"Exercise_Caution",
        "7":"Suspicious_or_Risky",
        "8":"Possibly_Malicious",
        "9":"Probably_Malicious",
        "10":"Malicious"
    }
    
    # PhishTank URL Data
    # Adjust logic as desired
    for in_database, valid, verified in zip(in_database_list, valid_list, verified_list):
        
        # Condition 1 - In database but verified not valid phish
        if in_database and verified and not valid:
            score_id = "2"

        # Condition 2 - In database and valid phish
        elif in_database and valid:
            score_id = "10"
            
        # Condition 3 - In database but not verified
        elif in_database and not verified:
            score_id = "5"
            
        # Condition 4 - Not in database
        elif not in_database:
            score_id = "0"
            
        # Condition 5 - Catch all
        else:
            score_id = "-1"
        
        score = score_table[score_id]
        normalize_score_url__url_score_object.append(
            {
                'score': score, 
                'score_id': score_id
            }
        )
        normalize_score_url__scores.append(score)
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalize_score_url:url_score_object", value=json.dumps(normalize_score_url__url_score_object))
    phantom.save_run_data(key="normalize_score_url:scores", value=json.dumps(normalize_score_url__scores))

    format_report_url(container=container)

    return


@phantom.playbook_block()
def url_result_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("url_result_filter() called")

    ################################################################################
    # Filters successful url reputation results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["url_reputation:action_result.status", "==", "success"]
        ],
        name="url_result_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        normalize_score_url(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_report_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_report_url() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed URL(s) using PhishTank.  The table below shows a summary of the information gathered.\n\n| URL | Normalized Score | Report Link | Source |\n| --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | PhishTank |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:url_result_filter:condition_1:url_reputation:action_result.parameter.url",
        "normalize_score_url:custom_function:scores",
        "filtered-data:url_result_filter:condition_1:url_reputation:action_result.data.*.phish_detail_page"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_report_url")

    parse_url(container=container)

    return


@phantom.playbook_block()
def build_url_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_url_output() called")

    ################################################################################
    # Generate an observable dictionary to output into the observables data path.
    ################################################################################

    filtered_result_0_data_url_result_filter = phantom.collect2(container=container, datapath=["filtered-data:url_result_filter:condition_1:url_reputation:action_result.parameter.url","filtered-data:url_result_filter:condition_1:url_reputation:action_result.data.*.phish_detail_page"])
    parse_url__result = phantom.collect2(container=container, datapath=["parse_url:custom_function_result.data"])
    normalize_score_url__url_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalize_score_url:url_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    filtered_result_0_parameter_url = [item[0] for item in filtered_result_0_data_url_result_filter]
    filtered_result_0_data___phish_detail_page = [item[1] for item in filtered_result_0_data_url_result_filter]
    parse_url_data = [item[0] for item in parse_url__result]

    build_url_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Assign variables
    build_url_output__observable_array = []
    url_list = filtered_result_0_parameter_url
    parsed_url_list = parse_url_data
    detail_page_list = filtered_result_0_data___phish_detail_page
    url_reputation_list = normalize_score_url__url_score_object
    
    for url, detail_page, parsed_url, url_rep in zip(url_list, detail_page_list, parsed_url_list, url_reputation_list):
        observable_object = {
            "value": url,
            "type": "url",
            "reputation": {
                "score_id": url_rep['score_id'],
                "score": url_rep['score'],
            },
            "attributes": {
                "hostname": parsed_url['hostname'],
                "scheme": parsed_url['scheme']
            },
            "source": "PhishTank",
            "source_link": detail_page
        }
        if parsed_url['path']:
            observable_object['attributes']['path'] = parsed_url['path']
        if parsed_url['query']:
            observable_object['attributes']['query'] = parsed_url['query']
        if parsed_url['port']:
            observable_object['attributes']['query'] = parsed_url['query']
            
        build_url_output__observable_array.append(observable_object)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_url_output:observable_array", value=json.dumps(build_url_output__observable_array))

    return


@phantom.playbook_block()
def parse_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("parse_url() called")

    filtered_result_0_data_url_result_filter = phantom.collect2(container=container, datapath=["filtered-data:url_result_filter:condition_1:url_reputation:action_result.parameter.url"])

    parameters = []

    # build parameters list for 'parse_url' call
    for filtered_result_0_item_url_result_filter in filtered_result_0_data_url_result_filter:
        parameters.append({
            "input_url": filtered_result_0_item_url_result_filter[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/url_parse", parameters=parameters, name="parse_url", callback=build_url_output)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_report_url = phantom.get_format_data(name="format_report_url")
    build_url_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_url_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "observable": build_url_output__observable_array,
        "markdown_report": format_report_url,
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