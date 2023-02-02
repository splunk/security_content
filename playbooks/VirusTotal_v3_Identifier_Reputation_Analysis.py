"""
Accepts a URL, IP, Domain, or File_Hash and does reputation analysis on the objects. Generates a global report and a per observable sub-report and normalized score. The score can be customized based on a variety of factors.\n\nRef: https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################
from math import log
################################################################################
## Global Custom Code End
################################################################################

@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'inputs_filter' block
    inputs_filter(container=container)

    return

@phantom.playbook_block()
def url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("url_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries VirusTotal for information about the provided URL(s)
    ################################################################################

    filtered_input_0_url = phantom.collect2(container=container, datapath=["filtered-data:inputs_filter:condition_1:playbook_input:url"])

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

    phantom.act("url reputation", parameters=parameters, name="url_reputation", assets=["virustotal_v3"], callback=url_result_filter)

    return


@phantom.playbook_block()
def format_report_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_report_url() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed URL(s) using VirusTotal.  The table below shows a summary of the information gathered.\n\n| URL | Normalized Score | Categories | Report Link | Source |\n| --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | https://www.virustotal.com/gui/url/{3} | VirusTotal v3 |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:url_result_filter:condition_1:url_reputation:action_result.parameter.url",
        "normalize_score_url:custom_function:score",
        "normalize_score_url:custom_function:categories",
        "filtered-data:url_result_filter:condition_1:url_reputation:action_result.data.*.id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_report_url")

    build_url_output(container=container)

    return


@phantom.playbook_block()
def build_url_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_url_output() called")

    ################################################################################
    # Generate an observable dictionary to output into the observables data path.
    ################################################################################

    filtered_result_0_data_url_result_filter = phantom.collect2(container=container, datapath=["filtered-data:url_result_filter:condition_1:url_reputation:action_result.parameter.url","filtered-data:url_result_filter:condition_1:url_reputation:action_result.data.*.id"])
    normalize_score_url__url_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalize_score_url:url_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    filtered_result_0_parameter_url = [item[0] for item in filtered_result_0_data_url_result_filter]
    filtered_result_0_data___id = [item[1] for item in filtered_result_0_data_url_result_filter]

    build_url_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    from urllib.parse import urlparse
    build_url_output__observable_array = []

    # Build URL
    for url, external_id, url_object in zip(filtered_result_0_parameter_url, filtered_result_0_data___id, normalize_score_url__url_score_object):
        parsed_url = urlparse(url)
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
            "source": "VirusTotal v3",
            "source_link": f"https://www.virustotal.com/gui/url/{external_id}"
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
def normalize_score_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalize_score_url() called")

    ################################################################################
    # Contains custom code for normalizing score. Adjust the logic as desired in the 
    # documented sections.
    ################################################################################

    filtered_result_0_data_url_result_filter = phantom.collect2(container=container, datapath=["filtered-data:url_result_filter:condition_1:url_reputation:action_result.data.*.attributes.categories","filtered-data:url_result_filter:condition_1:url_reputation:action_result.summary"])

    filtered_result_0_data___attributes_categories = [item[0] for item in filtered_result_0_data_url_result_filter]
    filtered_result_0_summary = [item[1] for item in filtered_result_0_data_url_result_filter]

    normalize_score_url__url_score_object = None
    normalize_score_url__score = None
    normalize_score_url__categories = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    # Reference for scores: https://schema.ocsf.io/objects/reputation
    score_table = {
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
    
    # Assign Variables
    url_categories_list = filtered_result_0_data___attributes_categories
    url_summary_list = filtered_result_0_summary
    normalize_score_url__url_score_object = []
    normalize_score_url__score = []
    normalize_score_url__categories = []
    
    # VirusTotal v3 URL Data
    # Adjust logic as desired
    for category, summary_data in zip(url_categories_list, url_summary_list):

        # Set confidence based on percentage of vendors undetected
        # Reduce the confidence by percentage of vendors undetected.
        vendors = summary_data['harmless'] + summary_data['undetected'] + summary_data['malicious'] + summary_data['suspicious']
        confidence = 100 - int((summary_data['undetected']/vendors) * 100)
        
        # Normalize reputation on a 10 point scale based on number of malicious and suspicious divided by harmless vendors
        # This can be adjusted to include whatever logic is desired.
        suspect = summary_data['malicious'] + summary_data['suspicious']
        # If there are only harmless verdicts and no suspicious entries, set score_id to 1.
        if summary_data['harmless'] and not suspect:
            score_id = 1
        else:
            # customize score calculation as desired
            log_result = log((suspect/vendors) * 100, 100) # log imported from math in global code block
            score_id = int(log_result * 10) + 3
            if score_id > 10:
                score_id = 10
        
        categories = [cat.lower() for cat in category.values()]
        categories = list(set(categories))
        
        score = score_table[str(score_id)]
        
        # Attach final object
        normalize_score_url__url_score_object.append({'score': score, 'score_id': score_id, 'confidence': confidence, 'categories': categories})
        normalize_score_url__score.append(score)
        normalize_score_url__categories.append(categories)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalize_score_url:url_score_object", value=json.dumps(normalize_score_url__url_score_object))
    phantom.save_run_data(key="normalize_score_url:score", value=json.dumps(normalize_score_url__score))
    phantom.save_run_data(key="normalize_score_url:categories", value=json.dumps(normalize_score_url__categories))

    format_report_url(container=container)

    return


@phantom.playbook_block()
def domain_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("domain_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries VirusTotal for information about the provided Domain(s)
    ################################################################################

    filtered_input_0_domain = phantom.collect2(container=container, datapath=["filtered-data:inputs_filter:condition_2:playbook_input:domain"])

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

    phantom.act("domain reputation", parameters=parameters, name="domain_reputation", assets=["virustotal_v3"], callback=domain_result_filter)

    return


@phantom.playbook_block()
def ip_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ip_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries VirusTotal for information about the provided IP(s)
    ################################################################################

    filtered_input_0_ip = phantom.collect2(container=container, datapath=["filtered-data:inputs_filter:condition_3:playbook_input:ip"])

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

    phantom.act("ip reputation", parameters=parameters, name="ip_reputation", assets=["virustotal_v3"], callback=ip_result_filter)

    return


@phantom.playbook_block()
def file_hash_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("file_hash_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries VirusTotal for information about the provided File Hash(es)
    ################################################################################

    filtered_input_0_file_hash = phantom.collect2(container=container, datapath=["filtered-data:inputs_filter:condition_4:playbook_input:file_hash"])

    parameters = []

    # build parameters list for 'file_hash_reputation' call
    for filtered_input_0_file_hash_item in filtered_input_0_file_hash:
        if filtered_input_0_file_hash_item[0] is not None:
            parameters.append({
                "hash": filtered_input_0_file_hash_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("file reputation", parameters=parameters, name="file_hash_reputation", assets=["virustotal_v3"], callback=file_result_filter)

    return


@phantom.playbook_block()
def normalize_score_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalize_score_domain() called")

    ################################################################################
    # Contains custom code for normalizing score. Adjust the logic as desired in the 
    # documented sections.
    ################################################################################

    filtered_result_0_data_domain_result_filter = phantom.collect2(container=container, datapath=["filtered-data:domain_result_filter:condition_1:domain_reputation:action_result.data.*.attributes.categories","filtered-data:domain_result_filter:condition_1:domain_reputation:action_result.summary"])

    filtered_result_0_data___attributes_categories = [item[0] for item in filtered_result_0_data_domain_result_filter]
    filtered_result_0_summary = [item[1] for item in filtered_result_0_data_domain_result_filter]

    normalize_score_domain__domain_score_object = None
    normalize_score_domain__score = None
    normalize_score_domain__categories = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Reference for scores: https://schema.ocsf.io/objects/reputation
    score_table = {
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
    
    # Assign Variables
    domain_categories_list = filtered_result_0_data___attributes_categories
    domain_summary_list = filtered_result_0_summary
    normalize_score_domain__domain_score_object = []
    normalize_score_domain__score = []
    normalize_score_domain__categories = []
    
    # VirusTotal v3 URL Data
    # Adjust logic as desired
    for category, summary_data in zip(domain_categories_list, domain_summary_list):
        
        # Set confidence based on percentage of vendors undetected
        # Reduce the confidence by percentage of vendors undetected.
        vendors = summary_data['harmless'] + summary_data['undetected'] + summary_data['malicious'] + summary_data['suspicious']
        confidence = 100 - int((summary_data['undetected']/vendors) * 100)
        
        # Normalize reputation on a 10 point scale based on number of malicious and suspicious divided by harmless vendors
        # This can be adjusted to include whatever logic is desired.
        suspect = summary_data['malicious'] + summary_data['suspicious']
        # If there are only harmless verdicts and no suspicious entries, set score_id to 1.
        if summary_data['harmless'] and not suspect:
            score_id = 1
        else:
            # customize score calculation as desired
            log_result = log((suspect/vendors) * 100, 100) # log imported from math in global code block
            score_id = int(log_result * 10) + 3
            if score_id > 10:
                score_id = 10
        
        categories = [cat.lower() for cat in category.values()]
        categories = list(set(categories))
        score = score_table[str(score_id)]
        
        # Attach final object
        normalize_score_domain__domain_score_object.append({'score': score, 'score_id': score_id, 'confidence': confidence, 'categories': categories})
        normalize_score_domain__score.append(score)
        normalize_score_domain__categories.append(categories)


    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalize_score_domain:domain_score_object", value=json.dumps(normalize_score_domain__domain_score_object))
    phantom.save_run_data(key="normalize_score_domain:score", value=json.dumps(normalize_score_domain__score))
    phantom.save_run_data(key="normalize_score_domain:categories", value=json.dumps(normalize_score_domain__categories))

    format_report_domain(container=container)

    return


@phantom.playbook_block()
def normalize_score_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalize_score_ip() called")

    ################################################################################
    # Contains custom code for normalizing score. Adjust the logic as desired in the 
    # documented sections.
    ################################################################################

    filtered_result_0_data_ip_result_filter = phantom.collect2(container=container, datapath=["filtered-data:ip_result_filter:condition_1:ip_reputation:action_result.summary"])

    filtered_result_0_summary = [item[0] for item in filtered_result_0_data_ip_result_filter]

    normalize_score_ip__ip_score_object = None
    normalize_score_ip__scores = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Reference for scores: https://schema.ocsf.io/objects/reputation
    score_table = {
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
    
    ip_summary_list = filtered_result_0_summary
    normalize_score_ip__ip_score_object = []
    normalize_score_ip__scores = []
    
    for summary_data in ip_summary_list:
        # Set confidence based on percentage of vendors undetected
        # Reduce the confidence by percentage of vendors undetected.
        vendors = summary_data['harmless'] + summary_data['undetected'] + summary_data['malicious'] + summary_data['suspicious']
        confidence = 100 - int((summary_data['undetected']/vendors) * 100)
        
        # Normalize reputation on a 10 point scale based on number of malicious and suspicious divided by harmless vendors
        # This can be adjusted to include whatever logic is desired.
        suspect = summary_data['malicious'] + summary_data['suspicious']
        # If there are only harmless verdicts and no suspicious entries, set score_id to 1.
        if summary_data['harmless'] and not suspect:
            score_id = 1
        else:
            # customize score calculation as desired
            log_result = log((suspect/vendors) * 100, 100) # log imported from math in global code block
            score_id = int(log_result * 10) + 3
            if score_id > 10:
                score_id = 10
            
        score = score_table[str(score_id)]

        normalize_score_ip__ip_score_object.append({'score': score, 'score_id': score_id, 'confidence': confidence})
        normalize_score_ip__scores.append(score)
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalize_score_ip:ip_score_object", value=json.dumps(normalize_score_ip__ip_score_object))
    phantom.save_run_data(key="normalize_score_ip:scores", value=json.dumps(normalize_score_ip__scores))

    format_report_ip(container=container)

    return


@phantom.playbook_block()
def normalize_score_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalize_score_file() called")

    ################################################################################
    # Contains custom code for normalizing score. Adjust the logic as desired in the 
    # documented sections.
    ################################################################################

    filtered_result_0_data_file_result_filter = phantom.collect2(container=container, datapath=["filtered-data:file_result_filter:condition_1:file_hash_reputation:action_result.summary"])

    filtered_result_0_summary = [item[0] for item in filtered_result_0_data_file_result_filter]

    normalize_score_file__file_score_object = None
    normalize_score_file__scores = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Reference for scores: https://schema.ocsf.io/objects/reputation
    score_table = {
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
    
    file_summary_list = filtered_result_0_summary
    normalize_score_file__file_score_object = []
    normalize_score_file__scores = []
    
    for summary_data in file_summary_list:
        # Set confidence based on percentage of vendors undetected
        # Reduce the confidence by percentage of vendors undetected.
        vendors = summary_data['harmless'] + summary_data['undetected'] + summary_data['malicious'] + summary_data['suspicious']
        confidence = 100 - int((summary_data['undetected']/vendors) * 100)
        
        # Normalize reputation on a 10 point scale based on number of malicious and suspicious divided by harmless vendors
        # This can be adjusted to include whatever logic is desired.
        suspect = summary_data['malicious'] + summary_data['suspicious']
        # If there are only harmless verdicts and no suspicious entries, set score_id to 1.
        if summary_data['harmless'] and not suspect:
            score_id = 1
        else:
            # customize score calculation as desired
            log_result = log((suspect/vendors) * 100, 100) # log imported from math in global code block
            score_id = int(log_result * 10) + 3
            if score_id > 10:
                score_id = 10
            
        score = score_table[str(score_id)]

        normalize_score_file__file_score_object.append({'score': score, 'score_id': score_id, 'confidence': confidence})
        normalize_score_file__scores.append(score)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalize_score_file:file_score_object", value=json.dumps(normalize_score_file__file_score_object))
    phantom.save_run_data(key="normalize_score_file:scores", value=json.dumps(normalize_score_file__scores))

    format_report_file(container=container)

    return


@phantom.playbook_block()
def format_report_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_report_domain() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed Domain(s) using VirusTotal.  The table below shows a summary of the information gathered.\n\n| Domain | Normalized Data | Categories | Report Link | Source |\n| --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | https://www.virustotal.com/gui/domain/{0} | VirusTotal v3 |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:domain_result_filter:condition_1:domain_reputation:action_result.parameter.domain",
        "normalize_score_domain:custom_function:score",
        "normalize_score_domain:custom_function:categories"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_report_domain")

    build_domain_output(container=container)

    return


@phantom.playbook_block()
def format_report_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_report_ip() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed IP(s) using VirusTotal.  The table below shows a summary of the information gathered.\n\n| IP Address | Normalized Data | Report Link | Source |\n| --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} |  | https://www.virustotal.com/gui/ip-address/{0} | VirusTotal v3 |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:ip_result_filter:condition_1:ip_reputation:action_result.parameter.ip",
        "normalize_score_ip:custom_function:scores"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_report_ip")

    build_ip_output(container=container)

    return


@phantom.playbook_block()
def format_report_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_report_file() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed file(s) using VirusTotal.  The table below shows a summary of the information gathered.\n\n| File | VT Name | VT Decription | Normalized Score  | Report Link | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {2} | {3} | {1} | https://www.virustotal.com/gui/file/{0} | VirusTotal v3 |\n%%\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:file_result_filter:condition_1:file_hash_reputation:action_result.parameter.hash",
        "normalize_score_file:custom_function:scores",
        "filtered-data:file_result_filter:condition_1:file_hash_reputation:action_result.data.*.attributes.meaningful_name",
        "filtered-data:file_result_filter:condition_1:file_hash_reputation:action_result.data.*.attributes.magic"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_report_file")

    build_file_hash_output(container=container)

    return


@phantom.playbook_block()
def inputs_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("inputs_filter() called")

    ################################################################################
    # Determine branches based on provided inputs.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:url", "!=", ""]
        ],
        name="inputs_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        url_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:domain", "!=", ""]
        ],
        name="inputs_filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        domain_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:ip", "!=", ""]
        ],
        name="inputs_filter:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        ip_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids and results for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:file_hash", "!=", ""]
        ],
        name="inputs_filter:condition_4")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        file_hash_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    return


@phantom.playbook_block()
def build_domain_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_domain_output() called")

    ################################################################################
    # Generate an observable dictionary to output into the observables data path.
    ################################################################################

    filtered_result_0_data_domain_result_filter = phantom.collect2(container=container, datapath=["filtered-data:domain_result_filter:condition_1:domain_reputation:action_result.parameter.domain"])
    normalize_score_domain__domain_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalize_score_domain:domain_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    filtered_result_0_parameter_domain = [item[0] for item in filtered_result_0_data_domain_result_filter]

    build_domain_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    build_domain_output__observable_array = []

    # Build URL
    for domain, domain_object in zip(filtered_result_0_parameter_domain, normalize_score_domain__domain_score_object):
        observable_object = {
            "value": domain,
            "type": "domain",
            "reputation": {
                "score_id": domain_object['score_id'],
                "score": domain_object['score'],
                "confidence": domain_object['confidence']
            },
            "categories": domain_object['categories'],
            "source": "VirusTotal v3",
            "source_link": f"https://www.virustotal.com/gui/domain/{domain}"
        }
        build_domain_output__observable_array.append(observable_object)
            

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_domain_output:observable_array", value=json.dumps(build_domain_output__observable_array))

    return


@phantom.playbook_block()
def build_ip_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_ip_output() called")

    ################################################################################
    # Generate an observable dictionary to output into the observables data path.
    ################################################################################

    filtered_result_0_data_ip_result_filter = phantom.collect2(container=container, datapath=["filtered-data:ip_result_filter:condition_1:ip_reputation:action_result.parameter.ip","filtered-data:ip_result_filter:condition_1:ip_reputation:action_result.data.*.attributes.country","filtered-data:ip_result_filter:condition_1:ip_reputation:action_result.data.*.attributes.network","filtered-data:ip_result_filter:condition_1:ip_reputation:action_result.data.*.attributes.as_owner","filtered-data:ip_result_filter:condition_1:ip_reputation:action_result.data.*.attributes.continent"])
    normalize_score_ip__ip_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalize_score_ip:ip_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    filtered_result_0_parameter_ip = [item[0] for item in filtered_result_0_data_ip_result_filter]
    filtered_result_0_data___attributes_country = [item[1] for item in filtered_result_0_data_ip_result_filter]
    filtered_result_0_data___attributes_network = [item[2] for item in filtered_result_0_data_ip_result_filter]
    filtered_result_0_data___attributes_as_owner = [item[3] for item in filtered_result_0_data_ip_result_filter]
    filtered_result_0_data___attributes_continent = [item[4] for item in filtered_result_0_data_ip_result_filter]

    build_ip_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    build_ip_output__observable_array = []
    
    # Build IP
    for ip, country, network, as_owner, continent, ip_object in zip(
        filtered_result_0_parameter_ip, 
        filtered_result_0_data___attributes_country,
        filtered_result_0_data___attributes_network,
        filtered_result_0_data___attributes_as_owner,
        filtered_result_0_data___attributes_continent,
        normalize_score_ip__ip_score_object
    ):
        observable_object = {
            "value": ip,
            "type": "ip",
            "reputation": {
                "score_id": ip_object['score_id'],
                "score": ip_object['score'],
                "confidence": ip_object['confidence']
            },
            "enrichment": {
                "provider": "VirusTotal v3",
                "type": "whois",
                "data": {
                    "country": country,
                    "network": network,
                    "as_owner": as_owner,
                    "continent": continent
                }
            },
            "source": "VirusTotal v3",
            "source_link": f"https://www.virustotal.com/gui/ip-address/{ip}"
        }
        build_ip_output__observable_array.append(observable_object)
        
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_ip_output:observable_array", value=json.dumps(build_ip_output__observable_array))

    return


@phantom.playbook_block()
def build_file_hash_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_file_hash_output() called")

    ################################################################################
    # Generate an observable dictionary to output into the observables data path.
    ################################################################################

    filtered_result_0_data_file_result_filter = phantom.collect2(container=container, datapath=["filtered-data:file_result_filter:condition_1:file_hash_reputation:action_result.parameter.hash","filtered-data:file_result_filter:condition_1:file_hash_reputation:action_result.data.*.attributes.meaningful_name","filtered-data:file_result_filter:condition_1:file_hash_reputation:action_result.data.*.attributes.type_description"])
    normalize_score_file__file_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalize_score_file:file_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    filtered_result_0_parameter_hash = [item[0] for item in filtered_result_0_data_file_result_filter]
    filtered_result_0_data___attributes_meaningful_name = [item[1] for item in filtered_result_0_data_file_result_filter]
    filtered_result_0_data___attributes_type_description = [item[2] for item in filtered_result_0_data_file_result_filter]

    build_file_hash_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    build_file_hash_output__observable_array = []
    # Build file_hash
    for file_hash, file_name, file_type, file_object in zip(filtered_result_0_parameter_hash, filtered_result_0_data___attributes_meaningful_name, filtered_result_0_data___attributes_type_description, normalize_score_file__file_score_object):
        observable_object = {
            "value": file_hash,
            "type": "hash",
            "reputation": {
                "score_id": file_object['score_id'],
                "score": file_object['score'],
                "confidence": file_object['confidence']
            },
            "enrichment": {
                "provider": "VirusTotal v3",
                "type": "file",
                "data": {
                    "meaningful_name": file_name,
                    "magic": file_type
                }
            },
            "source": "VirusTotal v3",
            "source_link": f"https://www.virustotal.com/gui/file/{file_hash}"
        }
        
        build_file_hash_output__observable_array.append(observable_object)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_file_hash_output:observable_array", value=json.dumps(build_file_hash_output__observable_array))

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
def domain_result_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("domain_result_filter() called")

    ################################################################################
    # Filters successful domain reputation results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["domain_reputation:action_result.status", "==", "success"]
        ],
        name="domain_result_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        normalize_score_domain(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def ip_result_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ip_result_filter() called")

    ################################################################################
    # Filters successful ip reputation results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["ip_reputation:action_result.status", "==", "success"]
        ],
        name="ip_result_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        normalize_score_ip(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def file_result_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("file_result_filter() called")

    ################################################################################
    # Filters successful file reputation results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["file_hash_reputation:action_result.status", "==", "success"]
        ],
        name="file_result_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        normalize_score_file(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_report_url = phantom.get_format_data(name="format_report_url")
    format_report_domain = phantom.get_format_data(name="format_report_domain")
    format_report_ip = phantom.get_format_data(name="format_report_ip")
    format_report_file = phantom.get_format_data(name="format_report_file")
    build_url_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_url_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    build_domain_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_domain_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    build_ip_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_ip_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    build_file_hash_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_file_hash_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    observable_combined_value = phantom.concatenate(build_url_output__observable_array, build_domain_output__observable_array, build_ip_output__observable_array, build_file_hash_output__observable_array)
    markdown_report_combined_value = phantom.concatenate(format_report_url, format_report_domain, format_report_ip, format_report_file)

    output = {
        "observable": observable_combined_value,
        "markdown_report": markdown_report_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return