"""
Accepts a URL or File_Hash and does reputation analysis on the objects. Generates a global report and a per observable sub-report and normalized score. The score can be customized based on a variety of factors.\n\n
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################



import os
################################################################################
## Global Custom Code End
################################################################################

@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'input_filter' block
    input_filter(container=container)

    return

@phantom.playbook_block()
def input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("input_filter() called")

    ################################################################################
    # Determine branches based on provided inputs.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:url", "!=", ""]
        ],
        name="input_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        url_detonation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:vault_id", "!=", ""]
        ],
        name="input_filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        get_vault_id_information(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def url_detonation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("url_detonation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries CrowdStrike for information about the provided URL(s)
    ################################################################################

    playbook_input_url = phantom.collect2(container=container, datapath=["playbook_input:url"])

    parameters = []

    # build parameters list for 'url_detonation' call
    for playbook_input_url_item in playbook_input_url:
        if playbook_input_url_item[0] is not None:
            parameters.append({
                "limit": 50,
                "url": playbook_input_url_item[0],
                "environment": "Windows 7, 64-bit",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate url", parameters=parameters, name="url_detonation", assets=["crowdstrike"], callback=url_detonation_filter)

    return


@phantom.playbook_block()
def url_detonation_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("url_detonation_filter() called")

    ################################################################################
    # Filters successful url detonation results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["url_detonation:action_result.status", "==", "success"]
        ],
        name="url_detonation_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        normalized_url_detonation_output(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def normalized_url_detonation_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalized_url_detonation_output() called")

    ################################################################################
    # This block uses custom code for normalizing score. Adjust the logic as desired 
    # in the documented sections.
    ################################################################################

    filtered_result_0_data_url_detonation_filter = phantom.collect2(container=container, datapath=["filtered-data:url_detonation_filter:condition_1:crowdstrike_url_detonation:action_result.parameter.url","filtered-data:url_detonation_filter:condition_1:crowdstrike_url_detonation:action_result.data.*.verdict","filtered-data:url_detonation_filter:condition_1:crowdstrike_url_detonation:action_result.data.*.sandbox.*.threat_score","filtered-data:url_detonation_filter:condition_1:crowdstrike_url_detonation:action_result.data.*.sandbox.*.signatures.*.category","filtered-data:url_detonation_filter:condition_1:crowdstrike_url_detonation:action_result.data.*.sandbox.*.verdict"])

    filtered_result_0_parameter_url = [item[0] for item in filtered_result_0_data_url_detonation_filter]
    filtered_result_0_data___verdict = [item[1] for item in filtered_result_0_data_url_detonation_filter]
    filtered_result_0_data___sandbox___threat_score = [item[2] for item in filtered_result_0_data_url_detonation_filter]
    filtered_result_0_data___sandbox___signatures___category = [item[3] for item in filtered_result_0_data_url_detonation_filter]
    filtered_result_0_data___sandbox___verdict = [item[4] for item in filtered_result_0_data_url_detonation_filter]

    normalized_url_detonation_output__url_score_object = None
    normalized_url_detonation_output__scores = None
    normalized_url_detonation_output__categories = None
    normalized_url_detonation_output__score_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug("filtered_result_0_parameter_url: {}".format(filtered_result_0_parameter_url))
    #phantom.debug("filtered_result_0_data: {}".format(filtered_result_0_data))    
    #phantom.debug("filtered_result_0_data___verdict: {}".format(filtered_result_0_data___verdict))
    #phantom.debug("filtered_result_0_data___sandbox___threat_score: {}".format(filtered_result_0_data___sandbox___threat_score))
    #phantom.debug("filtered_result_0_data___sandbox___signatures___category: {}".format(filtered_result_0_data___sandbox___signatures___category))
    #phantom.debug("filtered_result_0_summary_verdict: {}".format(filtered_result_0_summary_verdict))
    #phantom.debug("filtered_result_0_data___sandbox___verdict: {}".format(filtered_result_0_data___sandbox___verdict))
    #phantom.debug("crowdstrike_url_detonation_result_data: {}".format(crowdstrike_url_detonation_result_data))    
    
    ## define variables for easy code debugging
    
    normalized_url_detonation_output__url_score_object = []
    normalized_url_detonation_output__scores = []
    normalized_url_detonation_output__categories = []
    normalized_url_detonation_output__score_id = []
    
    url_detonation_param_list =  [(i or "") for i in filtered_result_0_parameter_url] 
    url_detonation_verdict_list = [(i or "") for i in filtered_result_0_data___sandbox___verdict] 
    url_detonation_threat_score_list = [(i or "") for i in filtered_result_0_data___sandbox___threat_score] 
    url_detonation_category_list = [(i or "") for i in filtered_result_0_data___sandbox___signatures___category] 

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
    ## get the set() or unique input url parameter.
    
    index_url_dict = {}
    set_url_inputs = set(url_detonation_param_list)
    
    
    for url_input in set_url_inputs:
        url_list = []
        score_list = []
        verdict_list = []
        category_list = []
        
        ## getting the index of each detonation phase of the url group the result for each url detonation
        url_input_index = [indx for indx, url_val in enumerate(url_detonation_param_list) if url_val == url_input]
        index_url_dict[url_input] = url_input_index
        
        for idx,(_url, _score, _verdict, _category) in enumerate(zip(url_detonation_param_list, url_detonation_verdict_list, url_detonation_threat_score_list, url_detonation_category_list)):
            if _url == url_input and idx in index_url_dict[url_input]:
                url_list.append(_url)
                score_list.append(_score)
                verdict_list.append(_verdict)
                category_list.append(_category)
        
        score_id = round(list(set(verdict_list))[0] / 10)
        score = score_table[str(score_id)]
        
        # Attach final object
        normalized_url_detonation_output__url_score_object.append({'score': score, 'score_id': score_id,'confidence': list(set(score_list))[0], 'categories': list(set(category_list))})
        normalized_url_detonation_output__scores.append(score)
        normalized_url_detonation_output__categories.append(list(set(category_list)))
        normalized_url_detonation_output__score_id.append(score_id)
        #phantom.debug("normalized_url_detonation_output__url_score_object: {}".format(normalized_url_detonation_output__url_score_object))
        #phantom.debug("normalized_url_detonation_output__scores: {}".format(normalized_url_detonation_output__scores))
        #phantom.debug("normalized_url_detonation_output__categories: {}".format(normalized_url_detonation_output__categories))
        
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalized_url_detonation_output:url_score_object", value=json.dumps(normalized_url_detonation_output__url_score_object))
    phantom.save_run_data(key="normalized_url_detonation_output:scores", value=json.dumps(normalized_url_detonation_output__scores))
    phantom.save_run_data(key="normalized_url_detonation_output:categories", value=json.dumps(normalized_url_detonation_output__categories))
    phantom.save_run_data(key="normalized_url_detonation_output:score_id", value=json.dumps(normalized_url_detonation_output__score_id))

    format_report_url(container=container)

    return


@phantom.playbook_block()
def format_report_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_report_url() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed URL(s) or File using Crowdstrike.  The table below shows a summary of the information gathered.\n\n| URL | Normalized Score | score id |Categories | Report Link | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} |https://falcon.crowdstrike.com/intelligence/sandbox/reports/{4} | CrowdStrike OAuth API |\n%%\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:url",
        "normalized_url_detonation_output:custom_function:scores",
        "normalized_url_detonation_output:custom_function:score_id",
        "normalized_url_detonation_output:custom_function:categories",
        "url_detonation:action_result.data.*.id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug(phantom.format(container=container, template=template, parameters=parameters, name="format_report_url"))
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
    # This block uses custom code to generate an observable dictionary to output into 
    # the observables data path.
    ################################################################################

    playbook_input_url = phantom.collect2(container=container, datapath=["playbook_input:url"])
    url_detonation_result_data = phantom.collect2(container=container, datapath=["url_detonation:action_result.data.*.id"], action_results=results)
    normalized_url_detonation_output__url_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalized_url_detonation_output:url_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    playbook_input_url_values = [item[0] for item in playbook_input_url]
    url_detonation_result_item_0 = [item[0] for item in url_detonation_result_data]

    build_url_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
# Write your custom code here...
    from urllib.parse import urlparse
    build_url_output__observable_array = []
    
    # Build URL
    for url, external_id, url_object in zip(playbook_input_url_values, url_detonation_result_item_0, normalized_url_detonation_output__url_score_object):
        parsed_url = urlparse(url)
        phantom.debug("parsed_url: {}, url_object: {}".format(parsed_url, url_object))
        observable_object = {
            "value": url,
            "type": "url",
            "reputation": {
                "score": url_object['score'],
                "score_id": url_object['score_id'],
                "confidence": url_object['confidence'],
                "categories": url_object['categories']
            },
            "attributes": {
                "hostname": parsed_url.hostname,
                "scheme": parsed_url.scheme
            },
            
            "source": "CrowdStrike OAuth API",
            "source_link": f"https://falcon.crowdstrike.com/intelligence/sandbox/reports/{external_id}"
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
def get_vault_id_information(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_vault_id_information() called")

    ################################################################################
    # This block uses custom code for retrieving metadata of vault id that will distinguish 
    # what sandbox will be executed.
    ################################################################################

    playbook_input_vault_id = phantom.collect2(container=container, datapath=["playbook_input:vault_id"])

    playbook_input_vault_id_values = [item[0] for item in playbook_input_vault_id]

    get_vault_id_information__sandbox_type = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    get_vault_id_information__sandbox_type = []
    
    for vault_id_value in playbook_input_vault_id_values:
        success, msg, vault_info = phantom.vault_info(vault_id=vault_id_value, file_name=None, container_id=None, trace=False)
        phantom.debug("vault_info: {}, success: {}, msg: {}".format(vault_info, success, msg))

        if success == True:
            detonation_file_name = vault_info[0]['name']
            detonation_mime_type = vault_info[0]['mime_type']
            detonation_meta_data = vault_info[0]['contains']
            
            file_name, file_ext = os.path.splitext(detonation_file_name)
            
            if file_ext == ".exe" or file_ext == ".dll" or file_ext == ".sys" or "pe file" in detonation_meta_data or "dosexec" in detonation_mime_type:
                #get_vault_id_information__sandbox_type.append({vault_id_value: "Windows 10, 64-bit"})
                get_vault_id_information__sandbox_type.append({"value": vault_id_value, "sandbox_type": "Windows 10, 64-bit"})
                
            elif file_ext == ".dmg":
                #get_vault_id_information__sandbox_type.append({vault_id_value: "Linux Ubuntu 16.04, 64-bit"})
                get_vault_id_information__sandbox_type.append({"value": vault_id_value, "sandbox_type": "Linux Ubuntu 16.04, 64-bit"})
                
            elif file_ext == ".apk" and "application/zip" in detonation_mime_type:
                #get_vault_id_information__sandbox_type.append({vault_id_value: "Android (static analysis)"})
                get_vault_id_information__sandbox_type.append({"value": vault_id_value, "sandbox_type": "Android (static analysis)"})
                
            elif "x-executable" in detonation_mime_type:
                #get_vault_id_information__sandbox_type.append({vault_id_value: "Linux Ubuntu 16.04, 64-bit"})
                get_vault_id_information__sandbox_type.append({"value": vault_id_value, "sandbox_type":"Linux Ubuntu 16.04, 64-bit"})
                
            else:
                #get_vault_id_information__sandbox_type.append({vault_id_value: "Windows 10, 64-bit"})
                get_vault_id_information__sandbox_type.append({"value": vault_id_value, "sandbox_type": "Windows 10, 64-bit"})
                

    phantom.debug("vaultd_id: {} get_vault_id_information__sandbox_type: {}".format(vault_id_value, get_vault_id_information__sandbox_type))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="get_vault_id_information:sandbox_type", value=json.dumps(get_vault_id_information__sandbox_type))

    list_demux(container=container)

    return


@phantom.playbook_block()
def file_detonation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("file_detonation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries CrowdStrike for information about the provided vault_id(s)
    ################################################################################

    list_demux__result = phantom.collect2(container=container, datapath=["list_demux:custom_function_result.data.output.value","list_demux:custom_function_result.data.output.sandbox_type"])

    parameters = []

    # build parameters list for 'file_detonation' call
    for list_demux__result_item in list_demux__result:
        if list_demux__result_item[0] is not None and list_demux__result_item[1] is not None:
            parameters.append({
                "limit": 50,
                "is_confidential": True,
                "vault_id": list_demux__result_item[0],
                "environment": list_demux__result_item[1],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate file", parameters=parameters, name="file_detonation", assets=["crowdstrike"], callback=sandbox_filter)

    return


@phantom.playbook_block()
def sandbox_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("sandbox_filter() called")

    ################################################################################
    # Filters successful file detonation results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["file_detonation:action_result.status", "==", "success"]
        ],
        name="sandbox_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        normalized_file_detonation_output(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def normalized_file_detonation_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("normalized_file_detonation_output() called")

    ################################################################################
    # This block uses custom code for normalizing score. Adjust the logic as desired 
    # in the documented sections.
    ################################################################################

    filtered_result_0_data_sandbox_filter = phantom.collect2(container=container, datapath=["filtered-data:sandbox_filter:condition_1:file_detonation:action_result.parameter.vault_id","filtered-data:sandbox_filter:condition_1:file_detonation:action_result.data.*.verdict","filtered-data:sandbox_filter:condition_1:file_detonation:action_result.data.*.sandbox.*.threat_score","filtered-data:sandbox_filter:condition_1:file_detonation:action_result.data.*.sandbox.*.signatures.*.category","filtered-data:sandbox_filter:condition_1:file_detonation:action_result.data.*.sandbox.*.verdict"])

    filtered_result_0_parameter_vault_id = [item[0] for item in filtered_result_0_data_sandbox_filter]
    filtered_result_0_data___verdict = [item[1] for item in filtered_result_0_data_sandbox_filter]
    filtered_result_0_data___sandbox___threat_score = [item[2] for item in filtered_result_0_data_sandbox_filter]
    filtered_result_0_data___sandbox___signatures___category = [item[3] for item in filtered_result_0_data_sandbox_filter]
    filtered_result_0_data___sandbox___verdict = [item[4] for item in filtered_result_0_data_sandbox_filter]

    normalized_file_detonation_output__file_score_object = None
    normalized_file_detonation_output__scores = None
    normalized_file_detonation_output__categories = None
    normalized_file_detonation_output__score_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    normalized_file_detonation_output__file_score_object = []
    normalized_file_detonation_output__scores = []
    normalized_file_detonation_output__categories = []
    normalized_file_detonation_output__score_id = []
    ## normalized NoneType value to avoid enumeration failure
    file_detonation_param_list =  [(i or "") for i in filtered_result_0_parameter_vault_id] 
    file_detonation_threat_score_list = [(i or "") for i in filtered_result_0_data___sandbox___threat_score] 
    file_detonation_category_list = [(i or "") for i in filtered_result_0_data___sandbox___signatures___category] 
    file_detonation_verdict_list = [(i or "") for i in filtered_result_0_data___sandbox___verdict] 
    
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
    
    ## get the set() or unique input vault id parameter.
    
    index_file_dict = {}
    set_vault_id_inputs = set(file_detonation_param_list)
    
    for vault_id_input in set_vault_id_inputs:
        ## crowdstrike detonation can have a multiple phase of score, verdict and category during detonation. we will try to get all the unique values of each
        ## object filed we want to include in report. 
        
        file_list = []
        score_list = []
        verdict_list = []
        category_list = []
        
        ## getting the index of each detonation phase of the url/file. group the result for each detonation
        vault_id_input_index = [indx for indx, vault_id_val in enumerate(file_detonation_param_list) if vault_id_val == vault_id_input]
        index_file_dict[vault_id_input] = vault_id_input_index
        #phantom.debug("vault_id: {} vault_id_list: {}".format(vault_id_input, index_file_dict))
        
        for idx,(_vault_id, _score, _verdict, _category) in enumerate(zip(file_detonation_param_list, file_detonation_verdict_list, file_detonation_threat_score_list, file_detonation_category_list)):
            if _vault_id == vault_id_input and idx in index_file_dict[vault_id_input]:
                file_list.append(_vault_id)
                score_list.append(_score)
                verdict_list.append(_verdict)
                category_list.append(_category)
                
        # Attach final object
        score_id = round(list(set(verdict_list))[0] / 10)
        score = score_table[str(score_id)]
        
        normalized_file_detonation_output__file_score_object.append({'score': score, 'score_id': score_id,'confidence': list(set(score_list))[0], 'categories': list(set(category_list))})
        normalized_file_detonation_output__scores.append(score)
        normalized_file_detonation_output__categories.append(list(set(category_list)))
        normalized_file_detonation_output__score_id.append(score_id)
        #phantom.debug("normalized_file_detonation_output__file_score_object: {}".format(normalized_file_detonation_output__file_score_object))
        #phantom.debug("normalized_file_detonation_output__scores: {}".format(normalized_file_detonation_output__scores))
        #phantom.debug("normalized_file_detonation_output__categories: {}".format(normalized_file_detonation_output__categories))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalized_file_detonation_output:file_score_object", value=json.dumps(normalized_file_detonation_output__file_score_object))
    phantom.save_run_data(key="normalized_file_detonation_output:scores", value=json.dumps(normalized_file_detonation_output__scores))
    phantom.save_run_data(key="normalized_file_detonation_output:categories", value=json.dumps(normalized_file_detonation_output__categories))
    phantom.save_run_data(key="normalized_file_detonation_output:score_id", value=json.dumps(normalized_file_detonation_output__score_id))

    format_report_file(container=container)

    return


@phantom.playbook_block()
def format_report_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_report_file() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed File(s) using CrowdStrike.  The table below shows a summary of the information gathered.\n\n| vault_id | Normalized Score | score id |Categories | Report Link | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} |https://falcon.crowdstrike.com/intelligence/sandbox/reports/{4} | CrowdStrike OAuth API |\n%%\n\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:sandbox_filter:condition_1:file_detonation:action_result.parameter.vault_id",
        "normalized_file_detonation_output:custom_function:scores",
        "normalized_file_detonation_output:custom_function:score_id",
        "normalized_file_detonation_output:custom_function:categories",
        "filtered-data:windows_sandbox_filter:condition_1:windows_file_detonation:action_result.data.*.id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug(phantom.format(container=container, template=template, parameters=parameters, name="format_report_win_file"))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_report_file")

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
    filtered_result_0_data_sandbox_filter = phantom.collect2(container=container, datapath=["filtered-data:sandbox_filter:condition_1:file_detonation:action_result.data.*.id"])
    normalized_file_detonation_output__file_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalized_file_detonation_output:file_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    playbook_input_vault_id_values = [item[0] for item in playbook_input_vault_id]
    filtered_result_0_data___id = [item[0] for item in filtered_result_0_data_sandbox_filter]

    build_file_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    build_file_output__observable_array = []
    for _vault_id, external_id, file_object in zip(playbook_input_vault_id_values, filtered_result_0_data___id, normalized_file_detonation_output__file_score_object):
        observable_object = {
            
            "value": _vault_id,
            "type": "hash",
            "reputation": {
                "score": file_object['score'],
                "score_id": file_object['score_id'],
                "confidence": file_object['confidence'],
                "categories": file_object['categories']
            },
            "enrichment": {
                "provider": "CrowdStrike OAuth API",
                "type": "file",
                
            },
            "source": "CrowdStrike OAuth API",
            "source_link":f"https://falcon.crowdstrike.com/intelligence/sandbox/reports/{external_id}"
        }
        build_file_output__observable_array.append(observable_object)
        #phantom.debug("build_file_output__observable_array: {}".format(build_file_output__observable_array))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_file_output:observable_array", value=json.dumps(build_file_output__observable_array))

    return


@phantom.playbook_block()
def list_demux(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_demux() called")

    ################################################################################
    # A utility to create a dictionary contains the vault id and sandbox name type 
    # that will be used to distinguish sandboxes to be executed depending on the basic 
    # file type checking of vault id.
    ################################################################################

    get_vault_id_information__sandbox_type = json.loads(_ if (_ := phantom.get_run_data(key="get_vault_id_information:sandbox_type")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "input_list": get_vault_id_information__sandbox_type,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="list_demux", callback=list_demux_filter)

    return


@phantom.playbook_block()
def list_demux_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_demux_filter() called")

    ################################################################################
    # filter check if list demux output exist.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["list_demux:custom_function_result.success", "==", True],
            ["list_demux:custom_function_result.message", "!=", "\"Timed out while waiting for the result\""]
        ],
        name="list_demux_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_detonation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_report_url = phantom.get_format_data(name="format_report_url")
    format_report_file = phantom.get_format_data(name="format_report_file")
    build_file_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_file_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    build_url_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_url_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    observable_combined_value = phantom.concatenate(build_file_output__observable_array, build_url_output__observable_array)
    report_combined_value = phantom.concatenate(format_report_url, format_report_file)

    output = {
        "observable": observable_combined_value,
        "report": report_combined_value,
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