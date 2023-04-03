"""
Accepts a URL or vault_id and does detonation analysis on the objects. Generates a global report and a per observable sub-report and normalized score. The score can be customized based on a variety of factors.\n\n
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'saa_input_filter' block
    saa_input_filter(container=container)

    return

@phantom.playbook_block()
def saa_input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("saa_input_filter() called")

    ################################################################################
    # Determine branches based on provided inputs.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:url", "!=", ""]
        ],
        name="saa_input_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        saa_url_detonation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:vault_id", "!=", ""]
        ],
        name="saa_input_filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        saa_file_detonation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def saa_url_detonation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("saa_url_detonation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries SAA for information about the provided URL(s)
    ################################################################################

    playbook_input_url = phantom.collect2(container=container, datapath=["playbook_input:url"])

    parameters = []

    # build parameters list for 'saa_url_detonation' call
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

    phantom.act("detonate url", parameters=parameters, name="saa_url_detonation", assets=["splunk attack analyzer"], callback=url_detonation_status_filter_1)

    return


@phantom.playbook_block()
def file_detonation_status_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("file_detonation_status_filter() called")

    ################################################################################
    # Filters successful file  detonation results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["saa_file_detonation:action_result.status", "==", "success"]
        ],
        name="file_detonation_status_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_jobid_of_file_detonation_output(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def get_jobid_of_url_detonation_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_jobid_of_url_detonation_output() called")

    ################################################################################
    # This block uses custom code for fetching JobID for URL(s) or file(s) detonation.
    ################################################################################

    saa_url_detonation_result_data = phantom.collect2(container=container, datapath=["saa_url_detonation:action_result.data.*.JobID"], action_results=results)

    saa_url_detonation_result_item_0 = [item[0] for item in saa_url_detonation_result_data]

    get_jobid_of_url_detonation_output__jobid = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    get_jobid_of_url_detonation_output__jobid = []

    get_jobid_of_url_detonation_output__jobid.append(saa_url_detonation_result_item_0)
    #phantom.debug("get_jobid_of_url_detonation_output__jobid: {}".format(get_jobid_of_url_detonation_output__jobid))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="get_jobid_of_url_detonation_output:jobid", value=json.dumps(get_jobid_of_url_detonation_output__jobid))

    ssa_get_job_forensics_output(container=container)

    return


@phantom.playbook_block()
def ssa_get_job_forensics_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ssa_get_job_forensics_output() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries SAA Forensics data relative to the JobID of URL(s) or File(s) needs 
    # to be detonated.
    ################################################################################

    get_jobid_of_url_detonation_output__jobid = json.loads(_ if (_ := phantom.get_run_data(key="get_jobid_of_url_detonation_output:jobid")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if get_jobid_of_url_detonation_output__jobid is not None:
        parameters.append({
            "job_id": get_jobid_of_url_detonation_output__jobid,
            "timeout": 5,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []
    for job_ids in get_jobid_of_url_detonation_output__jobid:
        for job in job_ids:
            if job is not None:
                parameters.append({
                    "job_id": job,
                    "timeout": 5,
                })
    #phantom.debug(parameters)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get job forensics", parameters=parameters, name="ssa_get_job_forensics_output", assets=["splunk attack analyzer"], callback=get_jobid_forensic_filter)

    return


@phantom.playbook_block()
def get_jobid_forensic_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_jobid_forensic_filter() called")

    ################################################################################
    # Filters successful url or file detonation job forensic results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["ssa_get_job_forensics_output:action_result.status", "==", "success"]
        ],
        name="get_jobid_forensic_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        normalized_job_forensic_report_output(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def normalized_job_forensic_report_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalized_job_forensic_report_output() called")

    ################################################################################
    # This block uses custom code for normalizing score. Adjust the logic as desired 
    # in the documented sections.
    ################################################################################

    ssa_get_job_forensics_output_result_data = phantom.collect2(container=container, datapath=["ssa_get_job_forensics_output:action_result.data.*.URLs.*.URL","ssa_get_job_forensics_output:action_result.data.*.DisplayScore","ssa_get_job_forensics_output:action_result.data.*.Detections.*.Description","ssa_get_job_forensics_output:action_result.data.*.Verdict","ssa_get_job_forensics_output:action_result.data"], action_results=results)

    ssa_get_job_forensics_output_result_item_0 = [item[0] for item in ssa_get_job_forensics_output_result_data]
    ssa_get_job_forensics_output_result_item_1 = [item[1] for item in ssa_get_job_forensics_output_result_data]
    ssa_get_job_forensics_output_result_item_2 = [item[2] for item in ssa_get_job_forensics_output_result_data]
    ssa_get_job_forensics_output_result_item_3 = [item[3] for item in ssa_get_job_forensics_output_result_data]
    ssa_get_job_forensics_output_result_item_4 = [item[4] for item in ssa_get_job_forensics_output_result_data]

    normalized_job_forensic_report_output__url_score_object = None
    normalized_job_forensic_report_output__scores = None
    normalized_job_forensic_report_output__categories = None
    normalized_job_forensic_report_output__confidence = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    score_id =0
    score_table = {
        "0":"Unknown",
        "10":"Very_Safe",
        "20":"Safe",
        "30":"Probably_Safe",
        "40":"Leans_Safe",
        "50":"May_not_be_Safe",
        "60":"Exercise_Caution",
        "70":"Suspicious_or_Risky",
        "80":"Possibly_Malicious",
        "90":"Probably_Malicious",
        "100":"Malicious"
    }
    #phantom.debug("url: {}".format(ssa_get_job_forensics_output_result_item_0))
    #phantom.debug("DisplayScore: {}".format(ssa_get_job_forensics_output_result_item_1))
    #phantom.debug("Category: {}".format(ssa_get_job_forensics_output_result_item_2))
    #phantom.debug("verdict: {}".format(ssa_get_job_forensics_output_result_item_3))
    #phantom.debug("action_data: {}".format(ssa_get_job_forensics_output_result_item_4))

    
    normalized_job_forensic_report_output__url_score_object = []
    normalized_job_forensic_report_output__scores = []
    normalized_job_forensic_report_output__categories = []
    normalized_job_forensic_report_output__confidence = []
    
    ## normalized NoneType value to avoid enumeration failure
    url_detonation_param_list =  [(i or "") for i in ssa_get_job_forensics_output_result_item_0] 
    url_detonation_threat_score_list = [(i or 0) for i in ssa_get_job_forensics_output_result_item_1] 
    url_detonation_category_list = [(i or "") for i in ssa_get_job_forensics_output_result_item_2] 
    url_detonation_verdict_list = [(i or "") for i in ssa_get_job_forensics_output_result_item_3] 
    
    ## get the set() or unique input url parameter.
    
    index_url_dict = {}
    set_url_inputs = set(url_detonation_param_list)
    
    for url_input in set_url_inputs:
        url_list = []
        score_list = []
        display_score_list = []
        category_list = []
        
        ## getting the index of each detonation phase of the url group the result for each url detonation
        url_input_index = [indx for indx, url_val in enumerate(url_detonation_param_list) if url_val == url_input]
        index_url_dict[url_input] = url_input_index

        for idx,(_url, _score, _display_score, _category) in enumerate(zip(url_detonation_param_list, url_detonation_verdict_list, url_detonation_threat_score_list, url_detonation_category_list)):
            if _url == url_input and idx in index_url_dict[url_input]:
                url_list.append(_url)
                score_list.append(_score)
                display_score_list.append(_display_score)
                category_list.append(_category)
                
    ## if score_list is empty or it has one element but empty string, lets score it base on confidence score of its engine detonation
        #phantom.debug("score_list: {} len: {}".format(score_list, len(score_list)))
        #phantom.debug("category_list: {} len: {}".format(category_list, len(category_list)))
        confidence_ = list(set(display_score_list))[0]
        categories = list(set(category_list))

        if len(score_list) == 0 or (len(set(score_list)) == 1 and score_list[0] == ""):
            if confidence_ >= 0 and confidence_ < 10:
                          score_id = 0
            elif confidence_ >= 10 and confidence_ < 20:
                          score_id = 10
            elif confidence_ >= 20 and confidence_ < 30:
                          score_id = 20
            elif confidence_ >= 30 and confidence_ < 40:
                          score_id = 30
            elif confidence_ >= 40 and confidence_ < 50:
                          score_id = 40
            elif confidence_ >= 50 and confidence_ < 60:
                          score_id = 50
            elif confidence_ >= 60 and confidence_ < 70:
                          score_id = 60
            elif confidence_ >= 70 and confidence_ < 80:
                          score_id = 70
            elif confidence_ >= 80 and confidence_ < 90:
                          score_id = 80
            elif confidence_ >= 90 and confidence_ < 100:
                          score_id = 90
            elif confidence_ >= 100:
                          score_id = 100
            
            score = score_table[str(score_id)]
            
        else:
            score = list(set(score_list))[0]
                      
        # Attach final object
        normalized_job_forensic_report_output__url_score_object.append({'score': score, 'confidence': confidence_, 'categories': categories})
        normalized_job_forensic_report_output__scores.append(score)
        normalized_job_forensic_report_output__categories.append(categories)
        normalized_job_forensic_report_output__confidence.append(confidence_)
        #phantom.debug("normalized_job_forensic_report_output__url_score_object: {}".format(normalized_job_forensic_report_output__url_score_object))
        #phantom.debug("normalized_job_forensic_report_output__categories: {}".format(normalized_job_forensic_report_output__categories))
        #phantom.debug("normalized_job_forensic_report_output__confidence: {}".format(normalized_job_forensic_report_output__confidence))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalized_job_forensic_report_output:url_score_object", value=json.dumps(normalized_job_forensic_report_output__url_score_object))
    phantom.save_run_data(key="normalized_job_forensic_report_output:scores", value=json.dumps(normalized_job_forensic_report_output__scores))
    phantom.save_run_data(key="normalized_job_forensic_report_output:categories", value=json.dumps(normalized_job_forensic_report_output__categories))
    phantom.save_run_data(key="normalized_job_forensic_report_output:confidence", value=json.dumps(normalized_job_forensic_report_output__confidence))

    format_url_report(container=container)

    return


@phantom.playbook_block()
def format_url_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_url_report() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed URL(s) using Splunk Attack Analyzer.  The table below shows a summary of the information gathered.\n\n| URL | Score | Confidence |Categories | Report Link | Source |\n| --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} |https://app.twinwave.io/job/{4} | Splunk Attack Analyzer (SAA){1}{2}{3}{4} |\n%%\n\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:url",
        "normalized_job_forensic_report_output:custom_function:scores",
        "normalized_job_forensic_report_output:custom_function:confidence",
        "normalized_job_forensic_report_output:custom_function:categories",
        "get_jobid_of_url_detonation_output:custom_function:jobid"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug(phantom.format(container=container, template=template, parameters=parameters, name="format_report_url"))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_url_report")

    build_url_output(container=container)

    return


@phantom.playbook_block()
def build_url_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_url_output() called")

    ################################################################################
    # This block uses custom code to generate an observable dictionary to output into 
    # the observables data path.
    ################################################################################

    playbook_input_url = phantom.collect2(container=container, datapath=["playbook_input:url"])
    get_jobid_of_url_detonation_output__jobid = json.loads(_ if (_ := phantom.get_run_data(key="get_jobid_of_url_detonation_output:jobid")) != "" else "null")  # pylint: disable=used-before-assignment
    normalized_job_forensic_report_output__url_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalized_job_forensic_report_output:url_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    playbook_input_url_values = [item[0] for item in playbook_input_url]

    build_url_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    from urllib.parse import urlparse
    build_url_output__observable_array = []
    #phantom.debug(playbook_input_url_values)
    # Build URL
    for jobs_id in get_jobid_of_url_detonation_output__jobid:
        
        for url, external_id, url_object in zip(playbook_input_url_values, jobs_id, normalized_job_forensic_report_output__url_score_object):
            parsed_url = urlparse(url)
            #phantom.debug("url: {} jobs_id:{}".format(url, external_id))
            #phantom.debug("parsed_url: {}, url_object: {}".format(parsed_url, url_object))
            observable_object = {
                "value": url,
                "type": "url",
                "sandbox": {
                    "score": url_object['score'],
                    "confidence": url_object['confidence']
                },
                "attributes": {
                    "hostname": parsed_url.hostname,
                    "scheme": parsed_url.scheme
                },
                "categories": url_object['categories'],
                "source": "Splunk Attack Analyzer (SAA)",
                "source_link": f"https://app.twinwave.io/job/{external_id}"
            }

            if parsed_url.path:
                observable_object['attributes']['path'] = parsed_url.path
            if parsed_url.query:
                observable_object['attributes']['query'] = parsed_url.query
            if parsed_url.port:
                observable_object['attributes']['port'] = parsed_url.port

            build_url_output__observable_array.append(observable_object)
            #phantom.debug("build_url_output__observable_array: {}".format(build_url_output__observable_array))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_url_output:observable_array", value=json.dumps(build_url_output__observable_array))

    return


@phantom.playbook_block()
def saa_file_detonation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("saa_file_detonation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries SAA for information about the provided vault_id(s)
    ################################################################################

    playbook_input_vault_id = phantom.collect2(container=container, datapath=["playbook_input:vault_id"])

    parameters = []

    # build parameters list for 'saa_file_detonation' call
    for playbook_input_vault_id_item in playbook_input_vault_id:
        if playbook_input_vault_id_item[0] is not None:
            parameters.append({
                "file": playbook_input_vault_id_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate file", parameters=parameters, name="saa_file_detonation", assets=["splunk attack analyzer"], callback=file_detonation_status_filter)

    return


@phantom.playbook_block()
def get_jobid_of_file_detonation_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_jobid_of_file_detonation_output() called")

    ################################################################################
    # This block uses custom code for fetching JobID for URL(s) or file(s) detonation.
    ################################################################################

    saa_file_detonation_result_data = phantom.collect2(container=container, datapath=["saa_file_detonation:action_result.data.*.JobID"], action_results=results)

    saa_file_detonation_result_item_0 = [item[0] for item in saa_file_detonation_result_data]

    get_jobid_of_file_detonation_output__jobid = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    get_jobid_of_file_detonation_output__jobid = []

    get_jobid_of_file_detonation_output__jobid.append(saa_file_detonation_result_item_0)
    #phantom.debug("get_jobid_of_file_detonation_output__jobid: {}".format(get_jobid_of_file_detonation_output__jobid))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="get_jobid_of_file_detonation_output:jobid", value=json.dumps(get_jobid_of_file_detonation_output__jobid))

    saa_get_file_job_forensics_output(container=container)

    return


@phantom.playbook_block()
def saa_get_file_job_forensics_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("saa_get_file_job_forensics_output() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries SAA Forensics data relative to the JobID of URL(s) or File(s) needs 
    # to be detonated.
    ################################################################################

    get_jobid_of_file_detonation_output__jobid = json.loads(_ if (_ := phantom.get_run_data(key="get_jobid_of_file_detonation_output:jobid")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if get_jobid_of_file_detonation_output__jobid is not None:
        parameters.append({
            "job_id": get_jobid_of_file_detonation_output__jobid,
            "timeout": 5,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []
    for job_ids in get_jobid_of_file_detonation_output__jobid:
        for job in job_ids:
            if job is not None:
                parameters.append({
                    "job_id": job,
                    "timeout": 5,
                })
    #phantom.debug(parameters)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get job forensics", parameters=parameters, name="saa_get_file_job_forensics_output", assets=["splunk attack analyzer"], callback=filter_6)

    return


@phantom.playbook_block()
def normalized_job_forensic_report_output_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalized_job_forensic_report_output_1() called")

    ################################################################################
    # This block uses custom code for normalizing score. Adjust the logic as desired 
    # in the documented sections.
    ################################################################################

    playbook_input_vault_id = phantom.collect2(container=container, datapath=["playbook_input:vault_id"])
    saa_get_file_job_forensics_output_result_data = phantom.collect2(container=container, datapath=["saa_get_file_job_forensics_output:action_result.data.*.DisplayScore","saa_get_file_job_forensics_output:action_result.data.*.Detections.*.Description","saa_get_file_job_forensics_output:action_result.data.*.Verdict","saa_get_file_job_forensics_output:action_result.data"], action_results=results)

    playbook_input_vault_id_values = [item[0] for item in playbook_input_vault_id]
    saa_get_file_job_forensics_output_result_item_0 = [item[0] for item in saa_get_file_job_forensics_output_result_data]
    saa_get_file_job_forensics_output_result_item_1 = [item[1] for item in saa_get_file_job_forensics_output_result_data]
    saa_get_file_job_forensics_output_result_item_2 = [item[2] for item in saa_get_file_job_forensics_output_result_data]
    saa_get_file_job_forensics_output_result_item_3 = [item[3] for item in saa_get_file_job_forensics_output_result_data]

    normalized_job_forensic_report_output_1__file_score_object = None
    normalized_job_forensic_report_output_1__scores = None
    normalized_job_forensic_report_output_1__categories = None
    normalized_job_forensic_report_output_1__confidence = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    score_id =0
    score_table = {
        "0":"Unknown",
        "10":"Very_Safe",
        "20":"Safe",
        "30":"Probably_Safe",
        "40":"Leans_Safe",
        "50":"May_not_be_Safe",
        "60":"Exercise_Caution",
        "70":"Suspicious_or_Risky",
        "80":"Possibly_Malicious",
        "90":"Probably_Malicious",
        "100":"Malicious"
    }
    #phantom.debug("vault_id: {}".format(ssa_get_job_forensics_output_result_item_0))
    #phantom.debug("DisplayScore: {}".format(ssa_get_job_forensics_output_result_item_1))
    #phantom.debug("Category: {}".format(ssa_get_job_forensics_output_result_item_2))
    #phantom.debug("verdict: {}".format(ssa_get_job_forensics_output_result_item_3))
    #phantom.debug("action_data: {}".format(ssa_get_job_forensics_output_result_item_4))

    
    normalized_job_forensic_report_output_1__file_score_object = []
    normalized_job_forensic_report_output_1__scores = []
    normalized_job_forensic_report_output_1__categories = []
    normalized_job_forensic_report_output_1__confidence = []
    
    ## normalized NoneType value to avoid enumeration failure
    file_detonation_param_list =  [(i or "") for i in playbook_input_vault_id_values] 
    file_detonation_threat_score_list = [(i or 0) for i in saa_get_file_job_forensics_output_result_item_0] 
    file_detonation_category_list = [(i or "") for i in saa_get_file_job_forensics_output_result_item_1] 
    file_detonation_verdict_list = [(i or "") for i in saa_get_file_job_forensics_output_result_item_2] 
    
    ## get the set() or unique input url parameter.
    
    index_file_dict = {}
    set_file_inputs = set(file_detonation_param_list)
    
    for file_input in set_file_inputs:
        vaultid_list = []
        score_list = []
        display_score_list = []
        category_list = []
        
        ## getting the index of each detonation phase of the url group the result for each url detonation
        file_input_index = [indx for indx, vaultid_val in enumerate(file_detonation_param_list) if vaultid_val == file_input]
        index_file_dict[file_input] = file_input_index
        
        for idx,(_vaultid, _score, _display_score, _category) in enumerate(zip(file_detonation_param_list, file_detonation_verdict_list, file_detonation_threat_score_list, file_detonation_category_list)):
            if _vaultid == file_input and idx in index_file_dict[file_input]:
                vaultid_list.append(_vaultid)
                score_list.append(_score)
                display_score_list.append(_display_score)
                category_list.append(_category)
                
    ## if score_list is empty or it has one element but empty string, lets score it base on confidence score of its engine detonation
        #phantom.debug("score_list: {} len: {}".format(score_list, len(score_list)))
        #phantom.debug("category_list: {} len: {}".format(category_list, len(category_list)))
        confidence_ = list(set(display_score_list))[0]
        categories = list(set(category_list))
        
        if len(score_list) == 0 or (len(set(score_list)) == 1 and score_list[0] == ""):
            if confidence_ >= 0 and confidence_ < 10:
                          score_id = 0
            elif confidence_ >= 10 and confidence_ < 20:
                          score_id = 10
            elif confidence_ >= 20 and confidence_ < 30:
                          score_id = 20
            elif confidence_ >= 30 and confidence_ < 40:
                          score_id = 30
            elif confidence_ >= 40 and confidence_ < 50:
                          score_id = 40
            elif confidence_ >= 50 and confidence_ < 60:
                          score_id = 50
            elif confidence_ >= 60 and confidence_ < 70:
                          score_id = 60
            elif confidence_ >= 70 and confidence_ < 80:
                          score_id = 70
            elif confidence_ >= 80 and confidence_ < 90:
                          score_id = 80
            elif confidence_ >= 90 and confidence_ < 100:
                          score_id = 90
            elif confidence_ >= 100:
                          score_id = 100
            
            score = score_table[str(score_id)]
            
        else:
            score = list(set(score_list))[0]
                      
        # Attach final object
        normalized_job_forensic_report_output_1__file_score_object.append({'score': score, 'confidence': confidence_, 'categories': categories})
        normalized_job_forensic_report_output_1__scores.append(score)
        normalized_job_forensic_report_output_1__categories.append(categories)
        normalized_job_forensic_report_output_1__confidence.append(confidence_)
        #phantom.debug("normalized_job_forensic_report_output_1__file_score_object: {}".format(normalized_job_forensic_report_output_1__file_score_object))
        #phantom.debug("normalized_job_forensic_report_output_1__scores: {}".format(normalized_job_forensic_report_output_1__scores))
        #phantom.debug("normalized_job_forensic_report_output_1__categories: {}".format(normalized_job_forensic_report_output_1__categories))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalized_job_forensic_report_output_1:file_score_object", value=json.dumps(normalized_job_forensic_report_output_1__file_score_object))
    phantom.save_run_data(key="normalized_job_forensic_report_output_1:scores", value=json.dumps(normalized_job_forensic_report_output_1__scores))
    phantom.save_run_data(key="normalized_job_forensic_report_output_1:categories", value=json.dumps(normalized_job_forensic_report_output_1__categories))
    phantom.save_run_data(key="normalized_job_forensic_report_output_1:confidence", value=json.dumps(normalized_job_forensic_report_output_1__confidence))

    format_file_report(container=container)

    return


@phantom.playbook_block()
def format_file_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_file_report() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed File(s) using Splunk Attack Analyzer.  The table below shows a summary of the information gathered.\n\n| File hash | Score | Confidence |Categories | Report Link | Source |\n| --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} |https://app.twinwave.io/job/{4} | Splunk Attack Analyzer (SAA){1}{2}{3}{4} |\n%%\n\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:vault_id",
        "normalized_job_forensic_report_output_1:custom_function:scores",
        "normalized_job_forensic_report_output_1:custom_function:confidence",
        "normalized_job_forensic_report_output_1:custom_function:categories",
        "get_jobid_of_file_detonation_output:custom_function:jobid"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug(phantom.format(container=container, template=template, parameters=parameters, name="format_report_file"))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_file_report")

    build_file_output(container=container)

    return


@phantom.playbook_block()
def build_file_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_file_output() called")

    ################################################################################
    # This block uses custom code to generate an observable dictionary to output into 
    # the observables data path.
    ################################################################################

    playbook_input_vault_id = phantom.collect2(container=container, datapath=["playbook_input:vault_id"])
    get_jobid_of_file_detonation_output__jobid = json.loads(_ if (_ := phantom.get_run_data(key="get_jobid_of_file_detonation_output:jobid")) != "" else "null")  # pylint: disable=used-before-assignment
    normalized_job_forensic_report_output_1__file_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalized_job_forensic_report_output_1:file_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    playbook_input_vault_id_values = [item[0] for item in playbook_input_vault_id]

    build_file_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    build_file_output__observable_array = []
    for jobs_id in get_jobid_of_file_detonation_output__jobid:
        for _vault_id, external_id, file_object in zip(playbook_input_vault_id_values, jobs_id, normalized_job_forensic_report_output_1__file_score_object):
            #phantom.debug("vault: {} id: {}".format(_vault_id, external_id))
            observable_object = {

                "value": _vault_id,
                "type": "hash",
                "sandbox": {
                    "score": file_object['score'],
                    "confidence": file_object['confidence'],

                },
                "enrichment": {
                    "provider": "Splunk Attack Analyzer",
                    "type": "file",

                },
                "categories": file_object['categories'],
                "source": "Splunk Attack Analyzer (SAA)",
                "source_link":f"https://app.twinwave.io/job/{external_id}"
            }
            build_file_output__observable_array.append(observable_object)
            #phantom.debug("build_file_output__observable_array: {}".format(build_file_output__observable_array))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_file_output:observable_array", value=json.dumps(build_file_output__observable_array))

    return


@phantom.playbook_block()
def url_detonation_status_filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("url_detonation_status_filter_1() called")

    ################################################################################
    # Filters url detonation results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["saa_url_detonation:action_result.status", "==", "success"]
        ],
        name="url_detonation_status_filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_jobid_of_url_detonation_output(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_6() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["saa_get_file_job_forensics_output:action_result.status", "==", "success"]
        ],
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        normalized_job_forensic_report_output_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_url_report = phantom.get_format_data(name="format_url_report")
    format_file_report = phantom.get_format_data(name="format_file_report")
    build_url_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_url_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    build_file_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_file_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    observable_combined_value = phantom.concatenate(build_url_output__observable_array, build_file_output__observable_array)
    report_combined_value = phantom.concatenate(format_url_report, format_file_report)

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