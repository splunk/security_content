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
        url_detonation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:vault_id", "!=", ""]
        ],
        name="saa_input_filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        file_detonation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def url_detonation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("url_detonation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries SAA for information about the provided URL(s)
    ################################################################################

    playbook_input_url = phantom.collect2(container=container, datapath=["playbook_input:url"])

    parameters = []

    # build parameters list for 'url_detonation' call
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

    phantom.act("detonate url", parameters=parameters, name="url_detonation", assets=["saa"], callback=url_detonation_status_filter_1)

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
            ["file_detonation:action_result.status", "==", "success"]
        ],
        name="file_detonation_status_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_file_forensics_output(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def get_url_forensics_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_url_forensics_output() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries SAA Forensics data relative to the JobID of URL(s) or File(s) needs 
    # to be detonated.
    ################################################################################

    url_detonation_result_data = phantom.collect2(container=container, datapath=["url_detonation:action_result.data.*.JobID","url_detonation:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_url_forensics_output' call
    for url_detonation_result_item in url_detonation_result_data:
        if url_detonation_result_item[0] is not None:
            parameters.append({
                "job_id": url_detonation_result_item[0],
                "context": {'artifact_id': url_detonation_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #parameters = []
    #for job_ids in url_jobid_detonation_output__jobid:
    #    for job in job_ids:
    #        if job is not None:
    #            parameters.append({
    #                "job_id": job,
    #                "timeout": 5,
    #            })
    #phantom.debug(parameters)
    ################################################################################
    ## Custom Code End
    ################################################################################

    # calculate start time using delay of 2 minutes
    start_time = datetime.now() + timedelta(minutes=2)
    phantom.act("get job forensics", parameters=parameters, name="get_url_forensics_output", start_time=start_time, assets=["saa"], callback=get_jobid_forensic_filter)

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
            ["get_url_forensics_output:action_result.status", "==", "success"]
        ],
        name="get_jobid_forensic_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        normalized_url_forensic_output(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def normalized_url_forensic_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalized_url_forensic_output() called")

    ################################################################################
    # This block uses custom code for normalizing score. Adjust the logic as desired 
    # in the documented sections.
    ################################################################################

    get_url_forensics_output_result_data = phantom.collect2(container=container, datapath=["get_url_forensics_output:action_result.data.*.URLs.*.URL","get_url_forensics_output:action_result.data.*.DisplayScore","get_url_forensics_output:action_result.data.*.Detections.*.Description","get_url_forensics_output:action_result.data.*.Verdict"], action_results=results)

    get_url_forensics_output_result_item_0 = [item[0] for item in get_url_forensics_output_result_data]
    get_url_forensics_output_result_item_1 = [item[1] for item in get_url_forensics_output_result_data]
    get_url_forensics_output_result_item_2 = [item[2] for item in get_url_forensics_output_result_data]
    get_url_forensics_output_result_item_3 = [item[3] for item in get_url_forensics_output_result_data]

    normalized_url_forensic_output__url_score_object = None
    normalized_url_forensic_output__scores = None
    normalized_url_forensic_output__categories = None
    normalized_url_forensic_output__score_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    score_id =0
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
    #phantom.debug("url: {}".format(ssa_get_job_forensics_output_result_item_0))
    #phantom.debug("DisplayScore: {}".format(ssa_get_job_forensics_output_result_item_1))
    #phantom.debug("Category: {}".format(ssa_get_job_forensics_output_result_item_2))
    #phantom.debug("verdict: {}".format(ssa_get_job_forensics_output_result_item_3))
    #phantom.debug("action_data: {}".format(ssa_get_job_forensics_output_result_item_4))
    #phantom.debug(get_url_forensics_output_result_item_4)
    
    normalized_url_forensic_output__url_score_object = []
    normalized_url_forensic_output__scores = []
    normalized_url_forensic_output__categories = []
    normalized_url_forensic_output__score_id = []
    
    ## normalized NoneType value to avoid enumeration failure
    url_detonation_param_list =  [(i or "") for i in get_url_forensics_output_result_item_0] 
    url_detonation_threat_score_list = [(i or 0) for i in get_url_forensics_output_result_item_1] 
    url_detonation_category_list = [(i or "") for i in get_url_forensics_output_result_item_2] 
    url_detonation_verdict_list = [(i or "") for i in get_url_forensics_output_result_item_3] 
    
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
        
        score = ""
        if len(score_list) == 0 or (len(set(score_list)) == 1 and score_list[0] == ""):
            if confidence_ >= 0 and confidence_ < 10:
                          score_id = 0
            elif confidence_ >= 10 and confidence_ < 20:
                          score_id = 1
            elif confidence_ >= 20 and confidence_ < 30:
                          score_id = 2
            elif confidence_ >= 30 and confidence_ < 40:
                          score_id = 3
            elif confidence_ >= 40 and confidence_ < 50:
                          score_id = 4
            elif confidence_ >= 50 and confidence_ < 60:
                          score_id = 5
            elif confidence_ >= 60 and confidence_ < 70:
                          score_id = 6
            elif confidence_ >= 70 and confidence_ < 80:
                          score_id = 7
            elif confidence_ >= 80 and confidence_ < 90:
                          score_id = 8
            elif confidence_ >= 90 and confidence_ < 100:
                          score_id = 9
            elif confidence_ >= 100:
                          score_id = 10
            #score = score_table[str(score_id)]
        else:
            score_id = round(confidence_/ 10)
        
        score = score_table[str(score_id)]
        
        # Attach final object
        normalized_url_forensic_output__url_score_object.append({'score': score, 'score_id': score_id, 'confidence': confidence_, 'categories': categories})
        normalized_url_forensic_output__scores.append(score)
        normalized_url_forensic_output__categories.append(", ".join(categories))
        normalized_url_forensic_output__score_id.append(score_id)
        #phantom.debug("normalized_job_forensic_report_output__url_score_object: {}".format(normalized_url_forensic_output__url_score_object))
        #phantom.debug("normalized_job_forensic_report_output__categories: {}".format(normalized_job_forensic_report_output__categories))
        #phantom.debug("normalized_job_forensic_report_output__confidence: {}".format(normalized_job_forensic_report_output__confidence))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalized_url_forensic_output:url_score_object", value=json.dumps(normalized_url_forensic_output__url_score_object))
    phantom.save_run_data(key="normalized_url_forensic_output:scores", value=json.dumps(normalized_url_forensic_output__scores))
    phantom.save_run_data(key="normalized_url_forensic_output:categories", value=json.dumps(normalized_url_forensic_output__categories))
    phantom.save_run_data(key="normalized_url_forensic_output:score_id", value=json.dumps(normalized_url_forensic_output__score_id))

    format_url_report(container=container)

    return


@phantom.playbook_block()
def format_url_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_url_report() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed URL(s) using Splunk Attack Analyzer.  The table below shows a summary of the information gathered.\n\n| URL | Normalized Score | score id |Categories | Report Link | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} |https://app.twinwave.io/job/{4} | Splunk Attack Analyzer (SAA) |\n%%\n\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:url",
        "normalized_url_forensic_output:custom_function:scores",
        "normalized_url_forensic_output:custom_function:score_id",
        "normalized_url_forensic_output:custom_function:categories",
        "url_detonation:action_result.data.*.JobID"
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
    url_detonation_result_data = phantom.collect2(container=container, datapath=["url_detonation:action_result.data.*.JobID"], action_results=results)
    normalized_url_forensic_output__url_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalized_url_forensic_output:url_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    playbook_input_url_values = [item[0] for item in playbook_input_url]
    url_detonation_result_item_0 = [item[0] for item in url_detonation_result_data]

    build_url_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    from urllib.parse import urlparse
    build_url_output__observable_array = []
    #phantom.debug(playbook_input_url_values)
    # Build URL

        
    for url, external_id, url_object in zip(playbook_input_url_values, url_detonation_result_item_0, normalized_url_forensic_output__url_score_object):
        parsed_url = urlparse(url)
        #phantom.debug("url: {} jobs_id:{}".format(url, external_id))
        #phantom.debug("parsed_url: {}, url_object: {}".format(parsed_url, url_object))
        observable_object = {
                "value": url,
                "type": "url",
                "reputation": {
                    "score": url_object['score'],
                    "score_id": url_object['score_id'],
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
def file_detonation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("file_detonation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries SAA for information about the provided vault_id(s)
    ################################################################################

    playbook_input_vault_id = phantom.collect2(container=container, datapath=["playbook_input:vault_id"])

    parameters = []

    # build parameters list for 'file_detonation' call
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

    # calculate start time using delay of 2 minutes
    start_time = datetime.now() + timedelta(minutes=2)
    phantom.act("detonate file", parameters=parameters, name="file_detonation", start_time=start_time, assets=["saa"], callback=file_detonation_status_filter)

    return


@phantom.playbook_block()
def get_file_forensics_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_file_forensics_output() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries SAA Forensics data relative to the JobID of URL(s) or File(s) needs 
    # to be detonated.
    ################################################################################

    file_detonation_result_data = phantom.collect2(container=container, datapath=["file_detonation:action_result.data.*.JobID","file_detonation:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_file_forensics_output' call
    for file_detonation_result_item in file_detonation_result_data:
        if file_detonation_result_item[0] is not None:
            parameters.append({
                "job_id": file_detonation_result_item[0],
                "context": {'artifact_id': file_detonation_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #parameters = []
    #for job_ids in file_jobid_detonation_output__jobid:
    #    for job in job_ids:
    #        if job is not None:
    #            parameters.append({
    #                "job_id": job,
    #                "timeout": 5,
    #            })
    #phantom.debug(parameters)
    ################################################################################
    ## Custom Code End
    ################################################################################

    # calculate start time using delay of 2 minutes
    start_time = datetime.now() + timedelta(minutes=2)
    phantom.act("get job forensics", parameters=parameters, name="get_file_forensics_output", start_time=start_time, assets=["saa"], callback=filter_6)

    return


@phantom.playbook_block()
def normalized_file_forensic_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalized_file_forensic_output() called")

    ################################################################################
    # This block uses custom code for normalizing score. Adjust the logic as desired 
    # in the documented sections.
    ################################################################################

    playbook_input_vault_id = phantom.collect2(container=container, datapath=["playbook_input:vault_id"])
    get_file_forensics_output_result_data = phantom.collect2(container=container, datapath=["get_file_forensics_output:action_result.data.*.DisplayScore","get_file_forensics_output:action_result.data.*.Detections.*.Description","get_file_forensics_output:action_result.data.*.Verdict"], action_results=results)

    playbook_input_vault_id_values = [item[0] for item in playbook_input_vault_id]
    get_file_forensics_output_result_item_0 = [item[0] for item in get_file_forensics_output_result_data]
    get_file_forensics_output_result_item_1 = [item[1] for item in get_file_forensics_output_result_data]
    get_file_forensics_output_result_item_2 = [item[2] for item in get_file_forensics_output_result_data]

    normalized_file_forensic_output__file_score_object = None
    normalized_file_forensic_output__scores = None
    normalized_file_forensic_output__categories = None
    normalized_file_forensic_output__score_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    score_id =0
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
    #phantom.debug("vault_id: {}".format(ssa_get_job_forensics_output_result_item_0))
    #phantom.debug("DisplayScore: {}".format(ssa_get_job_forensics_output_result_item_1))
    #phantom.debug("Category: {}".format(ssa_get_job_forensics_output_result_item_2))
    #phantom.debug("verdict: {}".format(ssa_get_job_forensics_output_result_item_3))
    #phantom.debug("action_data: {}".format(ssa_get_job_forensics_output_result_item_4))
    #phantom.debug(get_file_forensics_output_result_item_3)
    
    normalized_file_forensic_output__file_score_object = []
    normalized_file_forensic_output__scores = []
    normalized_file_forensic_output__categories = []
    normalized_file_forensic_output__score_id = []
    
    ## normalized NoneType value to avoid enumeration failure
    file_detonation_param_list =  [(i or "") for i in playbook_input_vault_id_values] 
    file_detonation_threat_score_list = [(i or 0) for i in get_file_forensics_output_result_item_0] 
    file_detonation_category_list = [(i or "") for i in get_file_forensics_output_result_item_1] 
    file_detonation_verdict_list = [(i or "") for i in get_file_forensics_output_result_item_2] 
    
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
        #score_ = list(set(score_list))[0]
        
        score = ""
        if len(score_list) == 0 or (len(set(score_list)) == 1 and score_list[0] == ""):
            if confidence_ >= 0 and confidence_ < 10:
                          score_id = 0
            elif confidence_ >= 10 and confidence_ < 20:
                          score_id = 1
            elif confidence_ >= 20 and confidence_ < 30:
                          score_id = 2
            elif confidence_ >= 30 and confidence_ < 40:
                          score_id = 3
            elif confidence_ >= 40 and confidence_ < 50:
                          score_id = 4
            elif confidence_ >= 50 and confidence_ < 60:
                          score_id = 5
            elif confidence_ >= 60 and confidence_ < 70:
                          score_id = 6
            elif confidence_ >= 70 and confidence_ < 80:
                          score_id = 7
            elif confidence_ >= 80 and confidence_ < 90:
                          score_id = 8
            elif confidence_ >= 90 and confidence_ < 100:
                          score_id = 9
            elif confidence_ >= 100:
                          score_id = 10
            
        else:
            score_id = round(confidence_/ 10)
        
        score = score_table[str(score_id)]
        #phantom.debug("score: {} score_id {}".format(score, score_id))
        # Attach final object
        normalized_file_forensic_output__file_score_object.append({'score': score, 'score_id': score_id, 'confidence': confidence_, 'categories': categories})
        normalized_file_forensic_output__scores.append(score)
        normalized_file_forensic_output__categories.append(", ".join(categories))
        normalized_file_forensic_output__score_id.append(score_id)
        #phantom.debug("normalized_job_forensic_report_output_1__file_score_object: {}".format(normalized_job_forensic_report_output_1__file_score_object))
        #phantom.debug("normalized_job_forensic_report_output_1__scores: {}".format(normalized_job_forensic_report_output_1__scores))
        #phantom.debug("normalized_job_forensic_report_output_1__categories: {}".format(normalized_job_forensic_report_output_1__categories))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalized_file_forensic_output:file_score_object", value=json.dumps(normalized_file_forensic_output__file_score_object))
    phantom.save_run_data(key="normalized_file_forensic_output:scores", value=json.dumps(normalized_file_forensic_output__scores))
    phantom.save_run_data(key="normalized_file_forensic_output:categories", value=json.dumps(normalized_file_forensic_output__categories))
    phantom.save_run_data(key="normalized_file_forensic_output:score_id", value=json.dumps(normalized_file_forensic_output__score_id))

    format_file_report(container=container)

    return


@phantom.playbook_block()
def format_file_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_file_report() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed File(s) using Splunk Attack Analyzer.  The table below shows a summary of the information gathered.\n\n| vault_id | Normalized Score | score id |Categories | Report Link | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} |https://app.twinwave.io/job/{4} | Splunk Attack Analyzer (SAA) |\n%%\n\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:vault_id",
        "normalized_file_forensic_output:custom_function:scores",
        "normalized_file_forensic_output:custom_function:score_id",
        "normalized_file_forensic_output:custom_function:categories",
        "file_detonation:action_result.data.*.JobID"
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
    file_detonation_result_data = phantom.collect2(container=container, datapath=["file_detonation:action_result.data.*.JobID"], action_results=results)
    normalized_file_forensic_output__file_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalized_file_forensic_output:file_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    playbook_input_vault_id_values = [item[0] for item in playbook_input_vault_id]
    file_detonation_result_item_0 = [item[0] for item in file_detonation_result_data]

    build_file_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    build_file_output__observable_array = []

    for _vault_id, external_id, file_object in zip(playbook_input_vault_id_values, file_detonation_result_item_0, normalized_file_forensic_output__file_score_object):
        #phantom.debug("vault: {} id: {}".format(_vault_id, external_id))
        observable_object = {

                "value": _vault_id,
                "type": "hash",
                "reputation": {
                    "score": file_object['score'],
                    "score_id": file_object['score_id'],
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
            ["url_detonation:action_result.status", "==", "success"]
        ],
        name="url_detonation_status_filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_url_forensics_output(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_6() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["get_file_forensics_output:action_result.status", "==", "success"]
        ],
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        normalized_file_forensic_output(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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