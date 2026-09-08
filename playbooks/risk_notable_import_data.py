"""
This playbook gathers all of the events associated with the Risk Notable and imports them as artifacts. It also generates a custom markdown formatted note.\t
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_splunk_asset_details' block
    get_splunk_asset_details(container=container)

    return

@phantom.playbook_block()
def get_splunk_asset_details(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_splunk_asset_details() called")

    parameters = []

    parameters.append({
        "asset": "splunk",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/asset_get_attributes", parameters=parameters, name="get_splunk_asset_details", callback=event_id_filter)

    return


@phantom.playbook_block()
def event_id_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("event_id_filter() called")

    ################################################################################
    # A notable event ID must be present to proceed with the playbook.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.event_id", "!=", ""]
        ],
        name="event_id_filter:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        run_risk_rule_query(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def run_risk_rule_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_risk_rule_query() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template=""" datamodel:Risk \n| search risk_object=\"{0}\" risk_object_type=\"{3}\" \n| where _time>={1} AND _time<={2}  | eval risk_event_id = if(isnull(risk_event_id), index + \"_\" + _cd + \"_\" + splunk_server, risk_event_id) | eventstats count by risk_event_id | where count < 2 \n| eval risk_message=coalesce(risk_message,source) \n| eval threat_zip = mvzip(threat_object, threat_object_type) \n| rename annotations.mitre_attack.mitre_technique_id as mitre_technique_id annotations.mitre_attack.mitre_tactic as mitre_tactic annotations.mitre_attack.mitre_technique as mitre_technique \n| fields - annotations* orig_sid orig_rid risk_factor* splunk_server host sourcetype tag threat_object* \n| stats list(risk_event_id) as risk_event_ids list(_time) as original_timestamps count as _event_count sum(calculated_risk_score) as _total_risk_score earliest(_time) as earliest latest(_time) as latest values(*) as * by search_name risk_message \n| where NOT (match(source, \"Splunk\\sSOAR\") AND _total_risk_score<=0) \n| fields mitre* _event_count _total_risk_score original_timestamps threat_zip risk_event_ids threat_object\n    [| rest /services/datamodel/model \n    | search eai:acl.app IN (Splunk_SA_CIM, SA-IdentityManagement, SA-NetworkProtection, SA-ThreatIntelligence, DA-ESS-ThreatIntelligence) \n    | fields description \n    | spath input=description path=objects{{}}.fields{{}}.fieldName \n    | spath input=description path=objects{{}}.calculations{{}}.outputFields{{}}.fieldName \n    | eval fieldNames=mvappend('objects{{}}.fields{{}}.fieldName', 'objects{{}}.calculations{{}}.outputFields{{}}.fieldName') \n    | stats values(fieldNames) as fieldNames \n    | mvexpand fieldNames \n    | regex fieldNames=\"^[_a-z]+$\" \n    | stats values(fieldNames) as search] \n| sort + latest \n| `uitime(earliest)` \n| `uitime(latest)` \n| eval _time=latest \n| rex field=threat_zip \"(?<threat_object>.*)\\,(?<threat_object_type>.*)\" \n| fields - threat_zip""",
        parameters=[
            "filtered-data:event_id_filter:condition_1:artifact:*.cef.risk_object",
            "filtered-data:event_id_filter:condition_1:artifact:*.cef.info_min_time",
            "filtered-data:event_id_filter:condition_1:artifact:*.cef.info_max_time",
            "filtered-data:event_id_filter:condition_1:artifact:*.cef.risk_object_type"
        ])

    ################################################################################
    # Reaches back into the risk index to pull out all the detections that led up 
    # to the notable firing.
    ################################################################################

    parameters = []

    if query_formatted_string is not None:
        parameters.append({
            "query": query_formatted_string,
            "command": "| from ",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_risk_rule_query", assets=["splunk"], callback=results_decision)

    return


@phantom.playbook_block()
def create_risk_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_risk_artifacts() called")

    id_value = container.get("id", None)
    parse_risk_results_1_data = phantom.collect2(container=container, datapath=["parse_risk_results_1:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'create_risk_artifacts' call
    for parse_risk_results_1_data_item in parse_risk_results_1_data:
        parameters.append({
            "name": None,
            "tags": None,
            "label": "risk_rule",
            "severity": "informational",
            "cef_field": None,
            "cef_value": None,
            "container": id_value,
            "input_json": parse_risk_results_1_data_item[0],
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="create_risk_artifacts", callback=create_risk_artifacts_callback)

    return


@phantom.playbook_block()
def create_risk_artifacts_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_risk_artifacts_callback() called")

    
    filter_artifact_score(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    mitre_format(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def filter_artifact_score(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_artifact_score() called")

    ################################################################################
    # Find artifacts with an individual contributing risk_score that is greater than 
    # or equal to 50.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            ["artifact:*.cef.calculated_risk_score", ">=", 70],
            ["artifact:*.cef.risk_score", ">=", 250]
        ],
        name="filter_artifact_score:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        artifact_update_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def mark_artifact_evidence(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("mark_artifact_evidence() called")

    id_value = container.get("id", None)
    filtered_artifact_0_data_filter_artifact_score = phantom.collect2(container=container, datapath=["filtered-data:filter_artifact_score:condition_1:artifact:*.id","filtered-data:filter_artifact_score:condition_1:artifact:*.id"], scope="all")

    parameters = []

    # build parameters list for 'mark_artifact_evidence' call
    for filtered_artifact_0_item_filter_artifact_score in filtered_artifact_0_data_filter_artifact_score:
        parameters.append({
            "container": id_value,
            "content_type": "artifact_id",
            "input_object": filtered_artifact_0_item_filter_artifact_score[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/mark_evidence", parameters=parameters, name="mark_artifact_evidence")

    return


@phantom.playbook_block()
def mitre_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("mitre_format() called")

    ################################################################################
    # This code block organizes all of the artifact descriptions by MITRE tactic and 
    # technique. Then, it outputs that information as a formatted string.
    ################################################################################

    mitre_format__output = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    from collections import OrderedDict 
    from operator import getitem 
    
    def mitre_sorter(item):
        tactic_list = [
            'reconnaissance', 'resource-development', 'initial-access', 'execution', 
            'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 
            'discovery', 'lateral-movement', 'collection', 'command-and-control', 
            'exfiltration', 'impact'
        ]
        index_map = {v: i for i, v in enumerate(tactic_list)}
        if ',' in item[0]:
            first_item = item[0].split(', ')[1]
            return index_map[first_item]
        else:
            return index_map[item[0]]

    artifact_data = phantom.collect2(
        container=container, datapath=[
            'artifact:*.cef.mitre_tactic', 
            'artifact:*.cef.mitre_technique', 
            'artifact:*.cef.mitre_technique_id', 
            'artifact:*.description'
        ], 
        scope='all'
    )
    
    def replace_all(text):
        char_list = ['[', ']', '"', "'"]
        for char in char_list:
            text = text.replace(char, '')
        return text

    mitre_dictionary = {}
    for mitre_tactic, mitre_technique, mitre_technique_id, risk_message in artifact_data:
        
        mitre_tactic = replace_all(json.dumps(mitre_tactic)) if mitre_tactic else None
        mitre_technique = replace_all(json.dumps(mitre_technique)) if mitre_technique else None
        mitre_technique_id = replace_all(json.dumps(mitre_technique_id)) if mitre_technique_id else None
        
        if mitre_tactic and mitre_tactic not in mitre_dictionary.keys():
            mitre_dictionary[mitre_tactic] = {mitre_technique: {'id': mitre_technique_id, 'risk_message': [risk_message]}}
        elif mitre_tactic and mitre_tactic in mitre_dictionary.keys():
            if mitre_technique and mitre_technique not in mitre_dictionary[mitre_tactic].keys():
                mitre_dictionary[mitre_tactic][mitre_technique] = {'id': mitre_technique_id, 'risk_message': [risk_message]}
            elif mitre_technique and mitre_technique in mitre_dictionary[mitre_tactic].keys():
                if risk_message not in mitre_dictionary[mitre_tactic][mitre_technique]['risk_message']:
                    mitre_dictionary[mitre_tactic][mitre_technique]['risk_message'].append(risk_message)
    
    mitre_copy = mitre_dictionary.copy()
    for k,v in mitre_copy.items():
        sorted_techniques = OrderedDict(sorted(v.items(),
                                               key = lambda x: getitem(x[1], 'id')
                                              )
                                       ) 
        for a,b in sorted_techniques.items():
            sorted_techniques[a] = b['risk_message']
        mitre_copy[k] = sorted_techniques

    final_dictionary = sorted(mitre_copy.items(), key=mitre_sorter)
    final_format = ""
    for tactics in final_dictionary:
        if ',' in tactics[0]:
            tactic_list = tactics[0].split(', ')
            final_format += "\n ## "
            for tactic in tactic_list[:-1]:
                split_tactic = tactic.split('-')
                for item in split_tactic[:-1]:
                    final_format += "{} ".format(item.capitalize())
                final_format += "{}, ".format(split_tactic[-1].capitalize())
            split_tactic = tactic_list[-1].split('-')
            for item in split_tactic[:-1]:
                final_format += "{} ".format(item.capitalize())
            final_format += "{}".format(split_tactic[-1].capitalize())
        else:
            tactic_list = tactics[0].split('-')
            final_format += "\n ## "
            for tactic in tactic_list[:-1]:
                final_format += "{} ".format(tactic.capitalize())
            final_format += "{}".format(tactic_list[-1].capitalize())
        for k,v in tactics[1].items():
            final_format += "\n - #### {}: {}".format(k, mitre_dictionary[tactics[0]][k]['id'])
            for risk_message in v:
                final_format += "\n   - ```{}```".format(risk_message)
        final_format += "\n"
    

    if final_format:
    	mitre_format__output = final_format
    else:
        mitre_format__output = "No Tactics / Techniques available in contributing risk events."
	

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="mitre_format:output", value=json.dumps(mitre_format__output))

    format_summary_note(container=container)

    return


@phantom.playbook_block()
def format_summary_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_summary_note() called")

    ################################################################################
    # Format a summary note with all of the information gathered up to this point.
    ################################################################################

    template = """### Splunk Enterprise Security has detected that {0} '**{1}**' generated {2} points of risk.\n\n### Full statistics and timeline on this user's risk behavior can be found [here](https://{3}/en-US/app/SplunkEnterpriseSecuritySuite/risk_analysis?earliest={4}&latest={5}&form.risk_object_type_raw={0}&form.risk_object_raw={1})\n\n| _time | event |\n| --- | --- |\n%%\n| **{7}** | `{8}` |\n%%\n\n&nbsp;\n\n# MITRE ATT&CK®\nSplunk SOAR has aggregated and aligned the following risk rules to ATT&CK Tactics and Techniques.\n\n{6}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:event_id_filter:condition_1:artifact:*.cef.risk_object_type",
        "filtered-data:event_id_filter:condition_1:artifact:*.cef.risk_object",
        "filtered-data:event_id_filter:condition_1:artifact:*.cef.risk_score",
        "get_splunk_asset_details:custom_function_result.data.configuration.device",
        "filtered-data:event_id_filter:condition_1:artifact:*.cef.info_min_time",
        "filtered-data:event_id_filter:condition_1:artifact:*.cef.info_max_time",
        "mitre_format:custom_function:output",
        "run_risk_rule_query:action_result.data.*._time",
        "run_risk_rule_query:action_result.data.*.risk_message"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_summary_note", scope="all")

    return


@phantom.playbook_block()
def parse_risk_results_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("parse_risk_results_1() called")

    run_risk_rule_query_result_data = phantom.collect2(container=container, datapath=["run_risk_rule_query:action_result.data","run_risk_rule_query:action_result.parameter.context.artifact_id"], action_results=results)

    run_risk_rule_query_result_item_0 = [item[0] for item in run_risk_rule_query_result_data]

    parameters = []

    parameters.append({
        "input_1": run_risk_rule_query_result_item_0,
        "input_2": None,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    from dateutil.parser import parse
    from django.utils.dateparse import parse_datetime
    import re
    from hashlib import sha256
    
    search_json = run_risk_rule_query_result_item_0[0]

    # overwrite parameters
    parameters = []
    
    cef_metadata_url = phantom.build_phantom_rest_url('cef_metadata')
    global_cef_mapping = phantom.requests.get(cef_metadata_url, verify=False).json()['cef']
        
    
    # Declare dictionary for cim to cef translation
    # adjust as needed
    cim_cef = {
        "action": "act", 
        "action_name": "act", 
        "app": "app", 
        "bytes_in": "bytesIn", 
        "bytes_out": "bytesOut", 
        "category": "cat",
        "dest": "destinationAddress", 
        "dest_ip": "destinationAddress", 
        "dest_mac": "destinationMacAddress", 
        "dest_nt_domain": "destinationNtDomain", 
        "dest_port": "destinationPort", 
        "dest_translated_ip": "destinationTranslatedAddress", 
        "dest_translated_port": "destinationTranslatedPort", 
        "direction": "deviceDirection",
        "dns": "destinationDnsDomain", 
        "dvc": "dvc", 
        "dvc_ip": "deviceAddress", 
        "dvc_mac": "deviceMacAddress", 
        "file_create_time": "fileCreateTime", 
        "file_hash": "fileHash", 
        "file_modify_time": "fileModificationTime", 
        "file_name": "fileName", 
        "file_path": "filePath", 
        "file_size": "fileSize", 
        "message": "message", 
        "protocol": "transportProtocol", 
        "request_payload": "request", 
        "request_payload_type": "requestMethod", 
        "src": "sourceAddress", 
        "src_dns": "sourceDnsDomain", 
        "src_ip": "sourceAddress", 
        "src_mac": "sourceMacAddress", 
        "src_nt_domain": "sourceNtDomain", 
        "src_port": "sourcePort", 
        "src_translated_ip": "sourceTranslatedAddress", 
        "src_translated_port": "sourceTranslatedPort", 
        "src_user": "sourceUserId", 
        "transport": "transportProtocol", 
        "url": "requestURL", 
        "user": "destinationUserName", 
        "user_id": "destinationUserId", 
    }
    
    
    # Iterate through Splunk search results
    for index, artifact_json in enumerate(search_json):
        field_mapping = {}
        data = []
        risk_event_set = set()
        for key in list(artifact_json.keys()):
            tags = []
            # Swap CIM for CEF values
            if cim_cef.get(key.lower()):
                # if src or dest matches an IP use src or dest' otherwise use sourceHostName or destinationHostName'
                if key.lower() == 'dest' or key.lower() == 'src':
                    hostname_map = { 'src': 'sourceHostName', 'dest': 'destinationHostName' }
                    if re.match('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', artifact_json[key]):
                        artifact_json[cim_cef[key.lower()]] = artifact_json.pop(key)
                    else:
                        cef_equivalent = hostname_map[key.lower()]
                        artifact_json[cef_equivalent] = artifact_json.pop(key)
                else:
                    artifact_json[cim_cef[key.lower()]] = artifact_json.pop(key)
        
        
        temp_dictionary = artifact_json.copy()
        for k,v in temp_dictionary.items():
            if isinstance(v, list) and k not in ['threat_object', 'threat_object_type', 'risk_event_ids', 'original_timestamps']:
                sub_dictionary = {}
                # Enumerate items in the globval cef mapping.
                # Up to 25 for contains types up to 10 for non contains types.
                if global_cef_mapping.get(k) and global_cef_mapping[k]['contains']:
                    for idx, item in enumerate(v[:25]):
                        sub_dictionary[f'{k}_{idx + 1}'] = item
                        field_mapping[f'{k}_{idx + 1}'] = global_cef_mapping[k]['contains']
                    if len(v) > 25:
                        phantom.debug("Limiting number of subfields with contains types to 25")
                    artifact_json.pop(k)
                    artifact_json.update(sub_dictionary)
                elif global_cef_mapping.get(k):
                    for idx, item in enumerate(v[:10]):
                        sub_dictionary[f'{k}_{idx + 1}'] = item
                    if len(v) > 10:
                        phantom.debug("Limiting number of subfields without contains types to 10")
                    artifact_json.pop(k)
                    artifact_json.update(sub_dictionary)
                else:
                    artifact_json[k] = str(v)
        
        # Add extra data to data attribute of artifact
        if isinstance(artifact_json.get('threat_object'), list):
            data.extend([{'threat_object': item} for item in artifact_json.get('threat_object', [])])
        elif artifact_json.get('threat_object'):
            data.append({'threat_object': artifact_json['threat_object']})
        if artifact_json.get('risk_event_ids') and artifact_json.get('original_timestamps'):
            risk_event_ids = artifact_json['risk_event_ids']
            original_timestamps = artifact_json['original_timestamps']
            # Both should be lists so only checking one.
            # If both aren't lists, something went wrong with the search.
            # Since risk_event_ids and original timestamps are optional for resetting risk scores, 
            # this will not error out at this time.
            if isinstance(risk_event_ids, list) and isinstance(original_timestamps, list):
                for event_id, timestamp in zip(risk_event_ids, original_timestamps):
                    data.append({'risk_event': {'id': event_id, 'timestamp': timestamp}})
                    risk_event_set.add(event_id)
                artifact_json.pop('risk_event_ids')
                artifact_json.pop('original_timestamps')
            else:
                risk_event_set.add(risk_event_ids)
                data.append({'risk_event': {'id': risk_event_ids, 'timestamp': original_timestamps}})
            
        # Make _time easier to read
        if artifact_json.get('_time'):
            timestring = parse(artifact_json['_time'])
            artifact_json['_time'] = "{} {}".format(timestring.date(), timestring.time())

        # Add threat_object_type to threat_object field_mapping
        if artifact_json.get('threat_object') and artifact_json.get('threat_object_type'):
            if isinstance(artifact_json['threat_object'], list) and isinstance(artifact_json['threat_object_type'], list):
                sub_dictionary = {}
                for idx, (threat_object, threat_object_type) in enumerate(zip(artifact_json['threat_object'], artifact_json['threat_object_type'])):
                    # remove unknown threat_objects
                    if threat_object != 'unknown':
                        sub_dictionary[f'threat_object_{idx + 1}'] = threat_object
                        sub_dictionary[f'threat_object_{idx + 1}_type'] = threat_object_type
                        field_mapping[f'threat_object_{idx + 1}'] = [threat_object_type]
                
                artifact_json.pop('threat_object')
                artifact_json.pop('threat_object_type')
                artifact_json.update(sub_dictionary)                              
            else:
                field_mapping['threat_object'] = [artifact_json['threat_object_type']]
            

        # Set the underlying data type in field mapping based on the risk_object_type     
        if artifact_json.get('risk_object') and artifact_json.get('risk_object_type'):
            if 'user' in artifact_json['risk_object_type']:
                field_mapping['risk_object'] = ["user name"]
            elif artifact_json['risk_object_type'] == 'system':
                field_mapping['risk_object'] = ["host name"]
            else:
                field_mapping['risk_object'] = [artifact_json['risk_object_type']]
            
        # Extract tags
        if artifact_json.get('rule_attack_tactic_technique'):
            for match in re.findall('(^|\|)(\w+)\s+',artifact_json['rule_attack_tactic_technique']):
                tags.append(match[1])
            tags=list(set(tags))

        # Final setp is to build the output. This is reliant on the source field existing which should be present in all Splunk search results
        if artifact_json.get('search_name'):  
            # populate artifact description
            if artifact_json.get('risk_message'):
                description = artifact_json['risk_message']
            elif artifact_json.get('description'):
                description = artifact_json.pop('description')
            else:
                description = None
                
            name = artifact_json.pop('search_name')
            if risk_event_set:
                data_id = sha256(''.join(risk_event_set).encode('utf-8')).hexdigest()
            else:
                data_id = None
            parameters.append(
                {
                    'input_1': json.dumps(
                        {
                            'cef_data': artifact_json, 
                            'data': data,
                            'tags': tags, 
                            'name': name, 
                            'source_data_identifier': data_id,
                            'description': description, 
                            'field_mapping': field_mapping, 
                            'run_automation': False if index < len(search_json[0]) - 1 else True
                        }
                    )
                }
            )

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/passthrough", parameters=parameters, name="parse_risk_results_1", callback=create_risk_artifacts)

    return


@phantom.playbook_block()
def results_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("results_decision() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["run_risk_rule_query:action_result.summary.total_events", ">", 0]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        parse_risk_results_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def artifact_update_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_update_2() called")

    filtered_artifact_0_data_filter_artifact_score = phantom.collect2(container=container, datapath=["filtered-data:filter_artifact_score:condition_1:artifact:*.id","filtered-data:filter_artifact_score:condition_1:artifact:*.id"], scope="all")

    parameters = []

    # build parameters list for 'artifact_update_2' call
    for filtered_artifact_0_item_filter_artifact_score in filtered_artifact_0_data_filter_artifact_score:
        parameters.append({
            "name": None,
            "tags": "high_risk_score",
            "label": None,
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "input_json": None,
            "artifact_id": filtered_artifact_0_item_filter_artifact_score[0],
            "cef_data_type": None,
            "overwrite_tags": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="artifact_update_2", callback=mark_artifact_evidence)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_summary_note = phantom.get_format_data(name="format_summary_note")

    output = {
        "note_title": ["[Auto-Generated] Notable Event Summary"],
        "note_content": format_summary_note,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################
	
    # Error handling in case of playbook not being able to import data properly
    if not format_summary_note:
        raise RuntimeError("Error occured during import data and summary note is missing")
    
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