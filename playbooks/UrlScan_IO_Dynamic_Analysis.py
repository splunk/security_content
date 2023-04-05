"""
Accepts a URL for detonation analysis on the objects. Generates a global report and a per observable sub-report and normalized score. The score can be customized based on a variety of factors.\n\n
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
    # Determine branches based on provided inputs.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:url", "!=", ""]
        ],
        name="url_input_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        url_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("url_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries urlscan.io for information about the provided URL(s)
    ################################################################################

    playbook_input_url = phantom.collect2(container=container, datapath=["playbook_input:url"])

    parameters = []

    # build parameters list for 'url_reputation' call
    for playbook_input_url_item in playbook_input_url:
        if playbook_input_url_item[0] is not None:
            parameters.append({
                "url": playbook_input_url_item[0],
                "private": True,
                "get_result": True,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate url", parameters=parameters, name="url_reputation", assets=["urlscan.io"], callback=urlscanio_summary_filter)

    return


@phantom.playbook_block()
def urlscanio_summary_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("urlscanio_summary_filter() called")

    ################################################################################
    # Filters successful url reputation results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["url_reputation:action_result.status", "==", "success"]
        ],
        name="urlscanio_summary_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        urlscanio_error_code_filter(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def normalize_score_url_with_error_code(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalize_score_url_with_error_code() called")

    ################################################################################
    # This block uses custom code for normalizing score. Adjust the logic as desired 
    # in the documented sections.
    ################################################################################

    url_reputation_result_data = phantom.collect2(container=container, datapath=["url_reputation:action_result.parameter.url","url_reputation:action_result.data.*.message","url_reputation:action_result.data.*.status","url_reputation:action_result.data.*.description"], action_results=results)

    url_reputation_parameter_url = [item[0] for item in url_reputation_result_data]
    url_reputation_result_item_1 = [item[1] for item in url_reputation_result_data]
    url_reputation_result_item_2 = [item[2] for item in url_reputation_result_data]
    url_reputation_result_item_3 = [item[3] for item in url_reputation_result_data]

    normalize_score_url_with_error_code__url_score_object = None
    normalize_score_url_with_error_code__scores = None
    normalize_score_url_with_error_code__categories = None
    normalize_score_url_with_error_code__confidence = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    url_reputation_data_message = [str(i or '') for i in url_reputation_result_item_1] 
    url_reputation_data_status = [str(i or '') for i in url_reputation_result_item_2] 
    url_reputation_data_description =  [str(i or '') for i in url_reputation_result_item_3] 

    
    normalize_score_url_with_error_code__url_score_object = []
    normalize_score_url_with_error_code__scores = []
    normalize_score_url_with_error_code__categories = []

 
    #phantom.debug("url_reputation_parameter_url: {}".format(url_reputation_parameter_url))
    #phantom.debug("url_reputation_data_message: {}".format(url_reputation_data_message))
    #phantom.debug("url_reputation_data_status: {}".format(url_reputation_data_status))
    #phantom.debug("url_reputation_data_description: {}".format(url_reputation_data_description))

    

    
    urlscan_score_table = {
        "0":"Legitimate",
        "1":"Very_Safe",
        "2":"Safe",
        "3":"Probably_Safe",
        "4":"Leans_Safe",
        "5":"May_not_be_Safe",
        "6":"Exercise_Caution",
        "7":"Suspicious_or_Risky",
        "8":"Possibly_Malicious",
        "9":"Probably_Malicious",
        "10":"Malicious",
        "error_code_query" : "error code return, check the error code descriptions"

    }
    
    url_scan_io_error_code ={
        "blacklist"            : "Blacklisted URL or Domain",
        "spam"                 : "Spammy URL or Domain",
        "invalid_hostname"     : "Invalid Hostname URL or Domain",
        "missing_url"          : "Missing URL OR Domain Property",
        "auth"                 : "HTTP basic auth information",
        "not_be_resolved"      : "Non-resolvable hostname (A, AAAA, CNAME)"
    }
    ## URLSCAN.io return error code especially if the url or domain was already in their blacklist database. 
    ## below are the common error code message base on their
    ## - "Blacklisted domains and URLs"              : requested to be blacklisted by their respective owners.
    ## - "Spammy submissions"                        : of URLs known to be used only for spamming this service.
    ## - "Invalid hostnames"                         : or invalid protocol schemes (FTP etc).
    ## - "Missing URL property"                      : ... yes, it does happen.
    ## - "Contains HTTP basic auth information"      : ... yes, that happens as well.
    ## - "Non-resolvable hostnames (A, AAAA, CNAME)" :  which we will not even try to scan.
    
    blank_result = "--"
    category = ""
    score = ""
    error_message = ""
   
    ## check if there is error code return upon URL reputation query
    
    for url_descp in url_reputation_data_description:
        
        for key, value in url_scan_io_error_code.items():
            if key.replace("_"," ").lower() in url_descp.lower():
                error_message = url_scan_io_error_code[key]
                
                # Attach final object
                normalize_score_url_with_error_code__categories.append(error_message)            
                normalize_score_url_with_error_code__url_score_object.append({'score': urlscan_score_table['error_code_query'], 'confidence':"", 'score_id': "", "malicious_tag_verdicts": "", 'categories': error_message, "description": url_descp})
                normalize_score_url_with_error_code__scores.append(urlscan_score_table['error_code_query'])
        
    #phantom.debug("normalize_score_url_with_error_code__url_score_object: {}".format(normalize_score_url_with_error_code__url_score_object))
    #phantom.debug("normalize_score_url_with_error_code__scores: {}".format(normalize_score_url_with_error_code__scores))
    #phantom.debug("normalize_score_url_with_error_code__categories: {}".format(normalize_score_url_with_error_code__categories))
    
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalize_score_url_with_error_code:url_score_object", value=json.dumps(normalize_score_url_with_error_code__url_score_object))
    phantom.save_run_data(key="normalize_score_url_with_error_code:scores", value=json.dumps(normalize_score_url_with_error_code__scores))
    phantom.save_run_data(key="normalize_score_url_with_error_code:categories", value=json.dumps(normalize_score_url_with_error_code__categories))
    phantom.save_run_data(key="normalize_score_url_with_error_code:confidence", value=json.dumps(normalize_score_url_with_error_code__confidence))

    error_code_format_report_url(container=container)

    return


@phantom.playbook_block()
def error_code_format_report_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("error_code_format_report_url() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed URL(s) using urlscan.io.  The table below shows a summary of the information gathered.\n\n| URL | Normalized Score | Confidence |Categories | Report Link | Source |\n| --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} | {4} | urlscan.io |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation:action_result.parameter.url",
        "normalize_score_url_with_error_code:custom_function:confidence",
        "normalize_score_url_with_error_code:custom_function:scores",
        "normalize_score_url_with_error_code:custom_function:categories",
        "url_reputation:action_result.data.*.task.reportURL"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug(phantom.format(container=container, template=template, parameters=parameters, name="error_code_format_report_url"))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="error_code_format_report_url")

    build_url_output_with_error_code(container=container)

    return


@phantom.playbook_block()
def urlscanio_error_code_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("urlscanio_error_code_filter() called")

    ################################################################################
    # This filter is designed to avoid nonetype value in some list and dictionary 
    # object due to error code return value of urlscan.io especially if the URL or 
    # domain is in their blacklist database
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:urlscanio_summary_filter:condition_1:url_reputation:action_result.data.*.status", "==", 400]
        ],
        name="urlscanio_error_code_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        normalize_score_url_with_error_code(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:urlscanio_summary_filter:condition_1:url_reputation:action_result.data.*.status", "!=", 400]
        ],
        name="urlscanio_error_code_filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        normalize_score_url_with_no_error_code(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def normalize_score_url_with_no_error_code(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalize_score_url_with_no_error_code() called")

    ################################################################################
    # This block uses custom code for normalizing score. Adjust the logic as desired 
    # in the documented sections.
    ################################################################################

    url_reputation_result_data = phantom.collect2(container=container, datapath=["url_reputation:action_result.data.*.verdicts.overall","url_reputation:action_result.data.*.verdicts.urlscan","url_reputation:action_result.data.*.verdicts.engines","url_reputation:action_result.data.*.verdicts.community"], action_results=results)

    url_reputation_result_item_0 = [item[0] for item in url_reputation_result_data]
    url_reputation_result_item_1 = [item[1] for item in url_reputation_result_data]
    url_reputation_result_item_2 = [item[2] for item in url_reputation_result_data]
    url_reputation_result_item_3 = [item[3] for item in url_reputation_result_data]

    normalize_score_url_with_no_error_code__url_score_object = None
    normalize_score_url_with_no_error_code__scores = None
    normalize_score_url_with_no_error_code__categories = None
    normalize_score_url_with_no_error_code__confidence = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    normalize_score_url_with_no_error_code__url_score_object = []
    normalize_score_url_with_no_error_code__scores = []
    normalize_score_url_with_no_error_code__categories = []
    
    url_reputation_verdicts_overall_dict = [(i or {}) for i in url_reputation_result_item_0] 
    url_reputation_verdicts_urlscan_dict = [(i or {}) for i in url_reputation_result_item_1] 
    url_reputation_verdicts_engine_dict = [(i or {}) for i in url_reputation_result_item_2] 
    url_reputation_verdicts_community_dict = [(i or {}) for i in url_reputation_result_item_3] 
    
    #phantom.debug("url_reputation_verdicts_overall_dict: {}".format(url_reputation_verdicts_overall_dict))
    #phantom.debug("url_reputation_verdicts_urlscan_dict: {}".format(url_reputation_verdicts_urlscan_dict))
    #phantom.debug("url_reputation_verdicts_engine_dict: {}".format(url_reputation_verdicts_engine_dict))
    #phantom.debug("url_reputation_verdicts_community_dict: {}".format(url_reputation_verdicts_community_dict))
    
    
    urlscan_score_table = {
        "0":"Legitimate",
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
    
    ## if there is no error code, urlscan.io will continue to detonate the URL and query scores in several verdicts object
            
    ## Normalize reputation on a -100 (legitimate) to 100 point scale based on number of malicious and suspicious divided by different urlscan.io verdict objects.
    ## This can be adjusted to include whatever logic is desired.
    
    for i in range(0,len(url_reputation_verdicts_overall_dict)):
        if url_reputation_verdicts_overall_dict[i] != {} or url_reputation_verdicts_urlscan_dict[i] != {} or url_reputation_verdicts_engine_dict[i] != {} or url_reputation_verdicts_community_dict[i] != {}:
            summary_score   = url_reputation_verdicts_overall_dict[i]['score'] + url_reputation_verdicts_urlscan_dict[i]['score'] + url_reputation_verdicts_engine_dict[i]['score'] + url_reputation_verdicts_community_dict[i]['score']
            summary_malicious_verdicts = url_reputation_verdicts_overall_dict[i]['malicious'] or url_reputation_verdicts_urlscan_dict[i]['malicious'] or url_reputation_verdicts_engine_dict[i]['malicious'] or url_reputation_verdicts_community_dict[i]['malicious']
            summary_of_malicious_tag = int(url_reputation_verdicts_overall_dict[i]['malicious']) + int(url_reputation_verdicts_urlscan_dict[i]['malicious']) + int(url_reputation_verdicts_engine_dict[i]['malicious']) + int(url_reputation_verdicts_community_dict[i]['malicious'])
            summary_categories = url_reputation_verdicts_overall_dict[i]['categories'] + url_reputation_verdicts_urlscan_dict[i]['categories'] + url_reputation_verdicts_engine_dict[i]['categories'] + url_reputation_verdicts_community_dict[i]['categories']
            
                        
            ## customized score id calculation
            
            log_result = (summary_score/4)  # avg score from different urlscan.io score object (engine_score, overall_verdict_score, urlscan_verdicts_score and community score)
            score_id = int(log_result) 
        

            if score_id < -50:
                score_id = "0"
            elif score_id < 0 and score_id >= -50:
                score_id = "1"
            elif score_id >= 0 and score_id <= 10:
                score_id = "2"
            elif score_id > 10 and score_id <= 20:
                score_id = "3"
            elif score_id > 20 and score_id <= 30:
                score_id = "4"
            elif score_id > 30 and score_id <= 40:
                score_id = "5"
            elif score_id > 40 and score_id <= 50:
                score_id = "6"
            elif score_id > 50 and score_id <= 60:
                score_id = "7"
            elif score_id > 70 and score_id <= 80:
                score_id = "8"
            elif score_id > 80 and score_id <= 90:
                score_id = "9"
            elif score_id > 90 and score_id <= 100:
                score_id = "10"

            score = urlscan_score_table[str(score_id)]

            malicious_tag_stats = (summary_of_malicious_tag, 4)

            # Attach final object
            normalize_score_url_with_no_error_code__categories.append(summary_categories)            
            normalize_score_url_with_no_error_code__url_score_object.append({'score': score, 'confidence':log_result, 'score_id': score_id, "malicious_tag_verdicts": summary_malicious_verdicts, "malicious_tag_stats": malicious_tag_stats , 'categories': summary_categories, "description": ""})
            normalize_score_url_with_no_error_code__scores.append(score)
        
    #phantom.debug("normalize_score_url_with_no_error_code__categories: {}".format(normalize_score_url_with_no_error_code__categories))
    #phantom.debug("normalize_score_url_with_no_error_code__url_score_object: {}".format(normalize_score_url_with_no_error_code__url_score_object))
    #phantom.debug("normalize_score_url_with_no_error_code__scores: {}".format(normalize_score_url_with_no_error_code__scores))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalize_score_url_with_no_error_code:url_score_object", value=json.dumps(normalize_score_url_with_no_error_code__url_score_object))
    phantom.save_run_data(key="normalize_score_url_with_no_error_code:scores", value=json.dumps(normalize_score_url_with_no_error_code__scores))
    phantom.save_run_data(key="normalize_score_url_with_no_error_code:categories", value=json.dumps(normalize_score_url_with_no_error_code__categories))
    phantom.save_run_data(key="normalize_score_url_with_no_error_code:confidence", value=json.dumps(normalize_score_url_with_no_error_code__confidence))

    no_error_code_format_report_url_1(container=container)

    return


@phantom.playbook_block()
def no_error_code_format_report_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("no_error_code_format_report_url_1() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed URL(s) using urlscan.io.  The table below shows a summary of the information gathered.\n\n| URL | Normalized Score |Confidence |  Categories | Report Link | Source |\n| --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} |{4} | urlscan.io |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation:action_result.parameter.url",
        "normalize_score_url_with_no_error_code:custom_function:scores",
        "normalize_score_url_with_no_error_code:custom_function:confidence",
        "normalize_score_url_with_no_error_code:custom_function:categories",
        "url_reputation:action_result.data.*.task.reportURL"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug(phantom.format(container=container, template=template, parameters=parameters, name="no_error_code_format_report_url"))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="no_error_code_format_report_url_1")

    build_url_output_with_no_error_code(container=container)

    return


@phantom.playbook_block()
def build_url_output_with_error_code(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_url_output_with_error_code() called")

    ################################################################################
    # This block uses custom code to generate an observable dictionary to output into 
    # the observables data path.
    ################################################################################

    url_reputation_result_data = phantom.collect2(container=container, datapath=["url_reputation:action_result.parameter.url","url_reputation:action_result.data.*.task.reportURL"], action_results=results)
    normalize_score_url_with_error_code__url_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalize_score_url_with_error_code:url_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    url_reputation_parameter_url = [item[0] for item in url_reputation_result_data]
    url_reputation_result_item_1 = [item[1] for item in url_reputation_result_data]

    build_url_output_with_error_code__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    # Write your custom code here...
    from urllib.parse import urlparse
    build_url_output_with_error_code__observable_array = []

    # Build URL
    url_scan_io_task_reporturl = [str(i or 'no report url') for i in url_reputation_result_item_1]
    url_scan_io_parameter_url = [str(i or '') for i in url_reputation_parameter_url]
    url_scan_io_url_score_object = normalize_score_url_with_error_code__url_score_object
    
    #phantom.debug("url_reputation_parameter_url: {}".format(url_reputation_parameter_url))
    #phantom.debug("url_reputation_result_item_1: {}".format(url_reputation_result_item_1))
    #phantom.debug("normalize_score_url_with_error_code__url_score_object: {}".format(normalize_score_url_with_error_code__url_score_object))
    for url, external_id, url_object in zip(url_scan_io_parameter_url, url_scan_io_task_reporturl, url_scan_io_url_score_object):
        parsed_url = urlparse(url)
        #phantom.debug("{} {} {} parsed_url: {}".format(url, external_id, url_object, parsed_url))
        observable_object = {
            "value": url,
            "type": "url",
            "reputation": {
                "score_id": url_object['score_id'],
                "score": url_object['score'],
                "confidence": url_object['confidence']
            }, 
            "attributes": {
                "hostname": parsed_url.hostname,
                "scheme": parsed_url.scheme
            },
            "categories": url_object['categories'],
            "description" :url_object['description'],
            "source": "urlscan.io",
            "source_link": f"{external_id}"
        }
        if parsed_url.hostname == None:
            observable_object['attributes']['hostname'] = url.split("\\",1)[0]
        if parsed_url.path:
            observable_object['attributes']['path'] = parsed_url.path
        if parsed_url.query:
            observable_object['attributes']['query'] = parsed_url.query
        if parsed_url.port:
            observable_object['attributes']['port'] = parsed_url.port

        
        build_url_output_with_error_code__observable_array.append(observable_object)
    #phantom.debug("build_url_output_with_error_code__observable_array: {}".format(build_url_output_with_error_code__observable_array))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_url_output_with_error_code:observable_array", value=json.dumps(build_url_output_with_error_code__observable_array))

    return


@phantom.playbook_block()
def build_url_output_with_no_error_code(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_url_output_with_no_error_code() called")

    ################################################################################
    # This block uses custom code to generate an observable dictionary to output into 
    # the observables data path.
    ################################################################################

    url_reputation_result_data = phantom.collect2(container=container, datapath=["url_reputation:action_result.parameter.url","url_reputation:action_result.data.*.task.reportURL"], action_results=results)
    normalize_score_url_with_no_error_code__url_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalize_score_url_with_no_error_code:url_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    url_reputation_parameter_url = [item[0] for item in url_reputation_result_data]
    url_reputation_result_item_1 = [item[1] for item in url_reputation_result_data]

    build_url_output_with_no_error_code__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    from urllib.parse import urlparse
    build_url_output_with_no_error_code__observable_array = []

    # Build URL
    #phantom.debug(url_reputation_parameter_url)
    for url, external_id, url_object in zip(url_reputation_parameter_url, url_reputation_result_item_1, normalize_score_url_with_no_error_code__url_score_object):
        parsed_url = urlparse(url)
        #phantom.debug("{} {} {} parsed_url: {}".format(url, external_id, url_object, parsed_url))
        observable_object = {
            "value": url,
            "type": "url",
            "reputation": {
                "score_id": url_object['score_id'],
                "score": url_object['score'],
                "confidence": url_object['confidence']
            },
            "attributes": {
                "hostname": parsed_url.hostname,
                "scheme": parsed_url.scheme
            },
            "categories": url_object['categories'],
            "description" :url_object['description'],
            "source": "urlscan.io",
            "source_link": f"{external_id}"
        }
        if parsed_url.hostname == None:
            observable_object['attributes']['hostname'] = url.split("\\",1)[0]
        if parsed_url.path:
            observable_object['attributes']['path'] = parsed_url.path
        if parsed_url.query:
            observable_object['attributes']['query'] = parsed_url.query
        if parsed_url.port:
            observable_object['attributes']['port'] = parsed_url.port
        
        build_url_output_with_no_error_code__observable_array.append(observable_object)
    #phantom.debug("build_url_output_with_no_error_code__observable_array: {}".format(build_url_output_with_no_error_code__observable_array))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_url_output_with_no_error_code:observable_array", value=json.dumps(build_url_output_with_no_error_code__observable_array))

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    error_code_format_report_url = phantom.get_format_data(name="error_code_format_report_url")
    no_error_code_format_report_url_1 = phantom.get_format_data(name="no_error_code_format_report_url_1")
    build_url_output_with_error_code__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_url_output_with_error_code:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    build_url_output_with_no_error_code__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_url_output_with_no_error_code:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    observable_combined_value = phantom.concatenate(build_url_output_with_error_code__observable_array, build_url_output_with_no_error_code__observable_array)
    report_combined_value = phantom.concatenate(error_code_format_report_url, no_error_code_format_report_url_1)

    output = {
        "observable": observable_combined_value,
        "report": report_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug(output)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return