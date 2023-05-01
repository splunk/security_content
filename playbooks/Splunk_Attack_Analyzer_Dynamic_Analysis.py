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

    phantom.act("detonate url", parameters=parameters, name="url_detonation", assets=["splunk_attack_analyzer"], callback=url_status_filter)

    return


@phantom.playbook_block()
def detonation_status_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("detonation_status_filter() called")

    ################################################################################
    # Filters successful file  detonation results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["file_detonation:action_result.status", "==", "success"]
        ],
        name="detonation_status_filter:condition_1")

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

    filtered_result_0_data_url_status_filter = phantom.collect2(container=container, datapath=["filtered-data:url_status_filter:condition_1:url_detonation:action_result.data.*.JobID"])

    parameters = []

    # build parameters list for 'get_url_forensics_output' call
    for filtered_result_0_item_url_status_filter in filtered_result_0_data_url_status_filter:
        if filtered_result_0_item_url_status_filter[0] is not None:
            parameters.append({
                "job_id": filtered_result_0_item_url_status_filter[0],
                "timeout": 5,
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

    phantom.act("get job forensics", parameters=parameters, name="get_url_forensics_output", assets=["splunk_attack_analyzer"], callback=get_jobid_forensic_filter)

    return


@phantom.playbook_block()
def get_jobid_forensic_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_jobid_forensic_filter() called")

    ################################################################################
    # Filters successful url detonation job forensic results.
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

    filtered_result_0_data_url_status_filter = phantom.collect2(container=container, datapath=["filtered-data:url_status_filter:condition_1:url_detonation:action_result.parameter.url","filtered-data:url_status_filter:condition_1:url_detonation:action_result.data.*.JobID"])
    filtered_result_1_data_get_jobid_forensic_filter = phantom.collect2(container=container, datapath=["filtered-data:get_jobid_forensic_filter:condition_1:get_url_forensics_output:action_result.parameter.job_id","filtered-data:get_jobid_forensic_filter:condition_1:get_url_forensics_output:action_result.data.*.DisplayScore","filtered-data:get_jobid_forensic_filter:condition_1:get_url_forensics_output:action_result.data.*.Detections"])

    filtered_result_0_parameter_url = [item[0] for item in filtered_result_0_data_url_status_filter]
    filtered_result_0_data___jobid = [item[1] for item in filtered_result_0_data_url_status_filter]
    filtered_result_1_parameter_job_id = [item[0] for item in filtered_result_1_data_get_jobid_forensic_filter]
    filtered_result_1_data___displayscore = [item[1] for item in filtered_result_1_data_get_jobid_forensic_filter]
    filtered_result_1_data___detections = [item[2] for item in filtered_result_1_data_get_jobid_forensic_filter]

    normalized_url_forensic_output__url_score_object = None
    normalized_url_forensic_output__scores = None
    normalized_url_forensic_output__categories = None
    normalized_url_forensic_output__score_id = None
    normalized_url_forensic_output__url = None
    normalized_url_forensic_output__job_id = None

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
    
    normalized_url_forensic_output__url_score_object = []
    normalized_url_forensic_output__scores = []
    normalized_url_forensic_output__categories = []
    normalized_url_forensic_output__score_id = []
    normalized_url_forensic_output__url = []
    normalized_url_forensic_output__job_id = []

    ## pair forensic job results with url detonated
    job_url_dict = {}
    for orig_url, orig_job, filtered_job in zip(filtered_result_0_parameter_url, filtered_result_0_data___jobid, filtered_result_1_parameter_job_id):
        if orig_job == filtered_job:
            job_url_dict[filtered_job] = orig_url
    
    for job, score_num, detections in zip(filtered_result_1_parameter_job_id, filtered_result_1_data___displayscore, filtered_result_1_data___detections):
        
        ## translate scores
        score_id = int(score_num/10) if score_num > 0 else 0
        score = score_table[str(score_id)]
        url = job_url_dict[job]
        categories = [item.get('Description') for item in detections]
        
        # Attach final object
        normalized_url_forensic_output__url_score_object.append({'value': url, 'base_score': score_num, 'score': score, 'score_id': score_id, 'categories': categories})
        normalized_url_forensic_output__scores.append(score)
        normalized_url_forensic_output__categories.append(", ".join(categories))
        normalized_url_forensic_output__score_id.append(score_id)
        normalized_url_forensic_output__url.append(url)
        normalized_url_forensic_output__job_id.append(job)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalized_url_forensic_output:url_score_object", value=json.dumps(normalized_url_forensic_output__url_score_object))
    phantom.save_run_data(key="normalized_url_forensic_output:scores", value=json.dumps(normalized_url_forensic_output__scores))
    phantom.save_run_data(key="normalized_url_forensic_output:categories", value=json.dumps(normalized_url_forensic_output__categories))
    phantom.save_run_data(key="normalized_url_forensic_output:score_id", value=json.dumps(normalized_url_forensic_output__score_id))
    phantom.save_run_data(key="normalized_url_forensic_output:url", value=json.dumps(normalized_url_forensic_output__url))
    phantom.save_run_data(key="normalized_url_forensic_output:job_id", value=json.dumps(normalized_url_forensic_output__job_id))

    format_url_report(container=container)

    return


@phantom.playbook_block()
def format_url_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_url_report() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed URL(s) using Splunk Attack Analyzer.  The table below shows a summary of the information gathered.\n\n| URL | Normalized Score | Score Id | Categories | Report Link | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} | https://app.twinwave.io/job/{4} | Splunk Attack Analyzer (SAA) |\n%%\n\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "normalized_url_forensic_output:custom_function:url",
        "normalized_url_forensic_output:custom_function:scores",
        "normalized_url_forensic_output:custom_function:score_id",
        "normalized_url_forensic_output:custom_function:categories",
        "normalized_url_forensic_output:custom_function:job_id"
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

    normalized_url_forensic_output__url = json.loads(_ if (_ := phantom.get_run_data(key="normalized_url_forensic_output:url")) != "" else "null")  # pylint: disable=used-before-assignment
    normalized_url_forensic_output__job_id = json.loads(_ if (_ := phantom.get_run_data(key="normalized_url_forensic_output:job_id")) != "" else "null")  # pylint: disable=used-before-assignment
    normalized_url_forensic_output__url_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalized_url_forensic_output:url_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    build_url_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    from urllib.parse import urlparse
    build_url_output__observable_array = []
    #phantom.debug(playbook_input_url_values)
    # Build URL

        
    for url, external_id, url_object in zip(normalized_url_forensic_output__url, normalized_url_forensic_output__job_id, normalized_url_forensic_output__url_score_object):
        parsed_url = urlparse(url)
        #phantom.debug("url: {} jobs_id:{}".format(url, external_id))
        #phantom.debug("parsed_url: {}, url_object: {}".format(parsed_url, url_object))
        observable_object = {
                "value": url,
                "type": "url",
                "reputation": {
                    "base_score": url_object['base_score'],
                    "score": url_object['score'],
                    "score_id": url_object['score_id'],
                    "confidence": url_object['base_score'] #Attack Analyzer's score has confidence baked in.
                },
                "attributes": {
                    "hostname": parsed_url.hostname,
                    "scheme": parsed_url.scheme
                },
                "classifications": url_object['categories'],
                "source": "Splunk Attack Analyzer",
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

    phantom.act("detonate file", parameters=parameters, name="file_detonation", assets=["splunk_attack_analyzer"], callback=detonation_status_filter)

    return


@phantom.playbook_block()
def get_file_forensics_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_file_forensics_output() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries SAA Forensics data relative to the JobID of URL(s) or File(s) needs 
    # to be detonated.
    ################################################################################

    filtered_result_0_data_detonation_status_filter = phantom.collect2(container=container, datapath=["filtered-data:detonation_status_filter:condition_1:file_detonation:action_result.data.*.JobID"])

    parameters = []

    # build parameters list for 'get_file_forensics_output' call
    for filtered_result_0_item_detonation_status_filter in filtered_result_0_data_detonation_status_filter:
        if filtered_result_0_item_detonation_status_filter[0] is not None:
            parameters.append({
                "job_id": filtered_result_0_item_detonation_status_filter[0],
                "timeout": 10,
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

    phantom.act("get job forensics", parameters=parameters, name="get_file_forensics_output", assets=["splunk_attack_analyzer"], callback=file_forensics_filter)

    return


@phantom.playbook_block()
def normalized_file_forensic_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalized_file_forensic_output() called")

    ################################################################################
    # This block uses custom code for normalizing score. Adjust the logic as desired 
    # in the documented sections.
    ################################################################################

    filtered_result_0_data_detonation_status_filter = phantom.collect2(container=container, datapath=["filtered-data:detonation_status_filter:condition_1:file_detonation:action_result.parameter.file","filtered-data:detonation_status_filter:condition_1:file_detonation:action_result.data.*.JobID"])
    filtered_result_1_data_file_forensics_filter = phantom.collect2(container=container, datapath=["filtered-data:file_forensics_filter:condition_1:get_file_forensics_output:action_result.parameter.job_id","filtered-data:file_forensics_filter:condition_1:get_file_forensics_output:action_result.data.*.DisplayScore","filtered-data:file_forensics_filter:condition_1:get_file_forensics_output:action_result.data.*.Detections"])

    filtered_result_0_parameter_file = [item[0] for item in filtered_result_0_data_detonation_status_filter]
    filtered_result_0_data___jobid = [item[1] for item in filtered_result_0_data_detonation_status_filter]
    filtered_result_1_parameter_job_id = [item[0] for item in filtered_result_1_data_file_forensics_filter]
    filtered_result_1_data___displayscore = [item[1] for item in filtered_result_1_data_file_forensics_filter]
    filtered_result_1_data___detections = [item[2] for item in filtered_result_1_data_file_forensics_filter]

    normalized_file_forensic_output__file_score_object = None
    normalized_file_forensic_output__scores = None
    normalized_file_forensic_output__categories = None
    normalized_file_forensic_output__score_id = None
    normalized_file_forensic_output__file = None
    normalized_file_forensic_output__job_id = None

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
    
    normalized_file_forensic_output__file_score_object = []
    normalized_file_forensic_output__scores = []
    normalized_file_forensic_output__categories = []
    normalized_file_forensic_output__score_id = []
    normalized_file_forensic_output__file = []
    normalized_file_forensic_output__job_id = []
    
    ## pair forensic job results with url detonated
    job_file_dict = {}
    for orig_url, orig_job, filtered_job in zip(filtered_result_0_parameter_file, filtered_result_0_data___jobid, filtered_result_1_parameter_job_id):
        if orig_job == filtered_job:
            job_file_dict[filtered_job] = orig_url

    for job, score_num, detections in zip(filtered_result_1_parameter_job_id, filtered_result_1_data___displayscore, filtered_result_1_data___detections):
        
        ## translate scores
        score_id = int(score_num/10) if score_num > 0 else 0
        score = score_table[str(score_id)]
        file = job_file_dict[job]
        categories = [item.get('Description') for item in detections]
        
        normalized_file_forensic_output__file_score_object.append({'value': file, 'base_score': score_num, 'score': score, 'score_id': score_id, 'categories': categories})
        normalized_file_forensic_output__scores.append(score)
        normalized_file_forensic_output__categories.append(", ".join(categories))
        normalized_file_forensic_output__score_id.append(score_id)
        normalized_file_forensic_output__file.append(file)
        normalized_file_forensic_output__job_id.append(job)
        
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalized_file_forensic_output:file_score_object", value=json.dumps(normalized_file_forensic_output__file_score_object))
    phantom.save_run_data(key="normalized_file_forensic_output:scores", value=json.dumps(normalized_file_forensic_output__scores))
    phantom.save_run_data(key="normalized_file_forensic_output:categories", value=json.dumps(normalized_file_forensic_output__categories))
    phantom.save_run_data(key="normalized_file_forensic_output:score_id", value=json.dumps(normalized_file_forensic_output__score_id))
    phantom.save_run_data(key="normalized_file_forensic_output:file", value=json.dumps(normalized_file_forensic_output__file))
    phantom.save_run_data(key="normalized_file_forensic_output:job_id", value=json.dumps(normalized_file_forensic_output__job_id))

    format_file_report(container=container)

    return


@phantom.playbook_block()
def format_file_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_file_report() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed File(s) using Splunk Attack Analyzer.  The table below shows a summary of the information gathered.\n\n| Vauld Id | Normalized Score | Score Id | Categories | Report Link | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} | https://app.twinwave.io/job/{4} | Splunk Attack Analyzer (SAA) |\n%%\n\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "normalized_file_forensic_output:custom_function:file",
        "normalized_file_forensic_output:custom_function:score",
        "normalized_file_forensic_output:custom_function:score_id",
        "normalized_file_forensic_output:custom_function:categories",
        "normalized_file_forensic_output:custom_function:job_id"
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

    normalized_file_forensic_output__file = json.loads(_ if (_ := phantom.get_run_data(key="normalized_file_forensic_output:file")) != "" else "null")  # pylint: disable=used-before-assignment
    normalized_file_forensic_output__job_id = json.loads(_ if (_ := phantom.get_run_data(key="normalized_file_forensic_output:job_id")) != "" else "null")  # pylint: disable=used-before-assignment
    normalized_file_forensic_output__file_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalized_file_forensic_output:file_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    build_file_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    build_file_output__observable_array = []

    for _vault_id, external_id, file_object in zip(normalized_file_forensic_output__file, normalized_file_forensic_output__job_id, normalized_file_forensic_output__file_score_object):
        #phantom.debug("vault: {} id: {}".format(_vault_id, external_id))
        observable_object = {

                "value": _vault_id,
                "type": "hash",
                "reputation": {
                    "base_score": file_object['base_score'],
                    "score": file_object['score'],
                    "score_id": file_object['score_id'],
                    "confidence": file_object['base_score'] #Attack Analyzer's score has confidence baked in.
                },
                "classifications": file_object['categories'],
                "source": "Splunk Attack Analyzer",
                "source_link":f"https://app.twinwave.io/job/{external_id}"
            }
        build_file_output__observable_array.append(observable_object)
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_file_output:observable_array", value=json.dumps(build_file_output__observable_array))

    return


@phantom.playbook_block()
def url_status_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("url_status_filter() called")

    ################################################################################
    # Filters url detonation results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["url_detonation:action_result.status", "==", "success"]
        ],
        name="url_status_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_url_forensics_output(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def file_forensics_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("file_forensics_filter() called")

    ################################################################################
    # Filters successful file detonation job forensic results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["get_file_forensics_output:action_result.status", "==", "success"]
        ],
        name="file_forensics_filter:condition_1")

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