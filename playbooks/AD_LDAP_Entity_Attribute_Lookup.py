"""
Accepts a user or device and looks up the most recent attributes and groups for that user or device. This playbook produces a normalized output for each user and device.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'playbook_inputs_filter' block
    playbook_inputs_filter(container=container)

    return

@phantom.playbook_block()
def get_user_attributes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_user_attributes() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Query for the user attributes for filtered playbook inputs.
    ################################################################################

    filtered_input_0_user = phantom.collect2(container=container, datapath=["filtered-data:playbook_inputs_filter:condition_1:playbook_input:user"])

    parameters = []

    # build parameters list for 'get_user_attributes' call
    for filtered_input_0_user_item in filtered_input_0_user:
        if filtered_input_0_user_item[0] is not None:
            parameters.append({
                "attributes": "userPrincipalName;mail;accountExpires;name;memberOf;title;department;manager;sAMAccountName;distinguishedName;mobile;ipPhone;homePhone;telephoneNumber;otherMobile;otherIpPhone;otherHomePhone;otherTelephone;whenCreated;objectSid;objectGUID",
                "principals": filtered_input_0_user_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get attributes", parameters=parameters, name="get_user_attributes", assets=["ad_ldap"], callback=filter_user_results)

    return


@phantom.playbook_block()
def format_user_outputs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_user_outputs() called")

    ################################################################################
    # Format a normalized output for each user.
    ################################################################################

    filtered_result_0_data_filter_user_results = phantom.collect2(container=container, datapath=["filtered-data:filter_user_results:condition_1:get_user_attributes:action_result.data.*.entries.*.attributes","filtered-data:filter_user_results:condition_1:get_user_attributes:action_result.parameter.principals"])
    get_user_group_attributes_result_data = phantom.collect2(container=container, datapath=["get_user_group_attributes:action_result.data.*.entries.*.attributes"], action_results=results)

    filtered_result_0_data___entries___attributes = [item[0] for item in filtered_result_0_data_filter_user_results]
    filtered_result_0_parameter_principals = [item[1] for item in filtered_result_0_data_filter_user_results]
    get_user_group_attributes_result_item_0 = [item[0] for item in get_user_group_attributes_result_data]

    format_user_outputs__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    format_user_outputs__observable_array = []
    
    # create dictionary of group attributes
    group_dict = {}
    for group in get_user_group_attributes_result_item_0:
        group_dict[group['distinguishedname']] = group
    
    # create normalized output dictionary
    for pb_input, user in zip(filtered_result_0_parameter_principals, filtered_result_0_data___entries___attributes):
        user_dict = {
            "account_type": "LDAP Account",
            "account_type_id": 1,
            "account_uid": user['userPrincipalName'],
            "domain": user['userPrincipalName'].split('@')[1],
            "email_addr": user['mail'],
            "end_date": user['accountExpires'],
            "full_name": user['name'],
            "labels": [
                user['title'],
                user['department']
            ],
            "managed_by": user['manager'],
            "name": user['sAMAccountName'],
            "start_date": user['whenCreated'],
            "type": "User",
            "type_id": 1,
            "uid": user['distinguishedName'],
            "uuid": user['objectGUID']
        }
        phones = [
            user['mobile'],
            user['ipPhone'],
            user['homePhone'],
            user['telephoneNumber'],
            user['otherMobile'],
            user['otherIpPhone'],
            user['otherHomePhone'],
            user['otherTelephone']
        ]
        
        # lookup groups
        group_list = []
        for group in user['memberOf']:
            if group_dict.get(group):
                group_details = group_dict[group]
                if not group_details['description']:
                    group_details['description'].append("None")
                temp_group_dict = {
                    "type": "Domain",
                    "desc": group_details['description'][0],
                    "name": group_details['name'],
                    "privileges": group_details['memberof'],
                    "uid": group_details['distinguishedname']
                }
                # drop values with []
                for k,v in temp_group_dict.copy().items():
                    if v == []:
                        temp_group_dict.pop(k)
                group_list.append(temp_group_dict)
                
                
        if group_list:
            user_dict['groups'] = group_list
                
        # clean up phone numbers
        phones = [phone for phone in phones if phone != []]
        if phones:
            user_dict['phones'] = phones
        
                
        final_output = {
            "type": "user",
            "value": pb_input,
            "attributes": user_dict,
            "soure": "AD LDAP"
        }
        format_user_outputs__observable_array.append(final_output)
        
    # phantom.debug(format_user_outputs__observable_array)
        

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="format_user_outputs:observable_array", value=json.dumps(format_user_outputs__observable_array))

    return


@phantom.playbook_block()
def merge_user_groups(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_user_groups() called")

    ################################################################################
    # Merge user groups, from preceding action block results, into a single deduplicated 
    # list.
    ################################################################################

    filtered_result_0_data_filter_user_results = phantom.collect2(container=container, datapath=["filtered-data:filter_user_results:condition_1:get_user_attributes:action_result.data.*.entries.*.attributes.memberOf"])

    filtered_result_0_data___entries___attributes_memberof = [item[0] for item in filtered_result_0_data_filter_user_results]

    merge_user_groups__list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    
    group_list = []
    for group in filtered_result_0_data___entries___attributes_memberof:
        group_list.extend(group)
    
    merge_user_groups__list = list(set(group_list))
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="merge_user_groups:list", value=json.dumps(merge_user_groups__list))

    get_user_group_attributes(container=container)

    return


@phantom.playbook_block()
def get_user_group_attributes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_user_group_attributes() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filter_formatted_string = phantom.format(
        container=container,
        template="""(|\n%%\n(distinguishedName={0})\n%%\n)\n""",
        parameters=[
            "merge_user_groups:custom_function:list"
        ])

    ################################################################################
    # Get details for the groups to which the user belongs.
    ################################################################################

    merge_user_groups__list = json.loads(_ if (_ := phantom.get_run_data(key="merge_user_groups:list")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if filter_formatted_string is not None:
        parameters.append({
            "filter": filter_formatted_string,
            "attributes": "description;name;memberOf;distinguishedName",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="get_user_group_attributes", assets=["ad_ldap"], callback=format_user_outputs)

    return


@phantom.playbook_block()
def get_device_attributes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_device_attributes() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Query for the device attributes for filtered playbook inputs.
    ################################################################################

    format_device_query__as_list = phantom.get_format_data(name="format_device_query__as_list")

    parameters = []

    # build parameters list for 'get_device_attributes' call
    for format_device_query__item in format_device_query__as_list:
        if format_device_query__item is not None:
            parameters.append({
                "filter": format_device_query__item,
                "attributes": "description;distinguishedName;objectSid;memberOf;name;sAMAccountName",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="get_device_attributes", assets=["ad_ldap"], callback=filter_device_results)

    return


@phantom.playbook_block()
def playbook_inputs_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_inputs_filter() called")

    ################################################################################
    # Filter inputs to route inputs to appropriate actions.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:user", "!=", None]
        ],
        name="playbook_inputs_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_user_attributes(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:device", "!=", None]
        ],
        name="playbook_inputs_filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        format_device_query(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def merge_device_groups(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_device_groups() called")

    ################################################################################
    # Merge device groups, from preceding action block results, into a single deduplicated 
    # list.
    ################################################################################

    filtered_result_0_data_filter_device_results = phantom.collect2(container=container, datapath=["filtered-data:filter_device_results:condition_1:get_device_attributes:action_result.data.*.entries.*.attributes.memberof"])

    filtered_result_0_data___entries___attributes_memberof = [item[0] for item in filtered_result_0_data_filter_device_results]

    merge_device_groups__list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    group_list = []
    for group in filtered_result_0_data___entries___attributes_memberof:
        group_list.extend(group)
    
    merge_device_groups__list = list(set(group_list))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="merge_device_groups:list", value=json.dumps(merge_device_groups__list))

    get_device_group_attributes(container=container)

    return


@phantom.playbook_block()
def get_device_group_attributes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_device_group_attributes() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filter_formatted_string = phantom.format(
        container=container,
        template="""(|\n%%\n(distinguishedName={0})\n%%\n)""",
        parameters=[
            "merge_device_groups:custom_function:list"
        ])

    ################################################################################
    # Get details for the groups to which the device belongs.
    ################################################################################

    merge_device_groups__list = json.loads(_ if (_ := phantom.get_run_data(key="merge_device_groups:list")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if filter_formatted_string is not None:
        parameters.append({
            "filter": filter_formatted_string,
            "attributes": "description;name;memberOf;distinguishedName",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="get_device_group_attributes", assets=["ad_ldap"], callback=format_device_outputs)

    return


@phantom.playbook_block()
def format_device_outputs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_device_outputs() called")

    ################################################################################
    # Format a normalized output for each device.
    ################################################################################

    filtered_result_0_data_filter_device_results = phantom.collect2(container=container, datapath=["filtered-data:filter_device_results:condition_1:get_device_attributes:action_result.data.*.entries.*.attributes","filtered-data:filter_device_results:condition_1:get_device_attributes:action_result.parameter.filter"])
    get_device_group_attributes_result_data = phantom.collect2(container=container, datapath=["get_device_group_attributes:action_result.data.*.entries.*.attributes"], action_results=results)

    filtered_result_0_data___entries___attributes = [item[0] for item in filtered_result_0_data_filter_device_results]
    filtered_result_0_parameter_filter = [item[1] for item in filtered_result_0_data_filter_device_results]
    get_device_group_attributes_result_item_0 = [item[0] for item in get_device_group_attributes_result_data]

    format_device_outputs__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    import re
    
    format_device_outputs__observable_array = []
    
    def extract_domain_name(dn):
        dn_rex = re.search(r'(DC=.+)', dn)
        if dn_rex:
            dc_list = dn_rex.group(1).replace('DC=', '').split(',')
            return '.'.join(dc_list)
    
    def extract_ou(dn):
        dn_rex = re.search(r'(OU=.+?),DC', dn)
        if dn_rex:
            ou_list = dn_rex.group(1).replace('OU=', '').split(',')
            return ou_list
        
    def extract_pb_input_from_filter(filter_query_list):
        pb_input_list = []
        for query in filter_query_list:
            query_rex = re.search(r'sAMAccountName=([^\)]+)', query)
            hostname = query_rex.group(1).replace('*', '')
            pb_input_list.append(hostname)
        return pb_input_list
    
    # create dictionary of group attributes
    group_dict = {}
    for group in get_device_group_attributes_result_item_0:
        group_dict[group['distinguishedname']] = group
        
    pb_input_hostname_list = extract_pb_input_from_filter(filtered_result_0_parameter_filter)
    # create normalized output dictionary
    for pb_input, device in zip(pb_input_hostname_list, filtered_result_0_data___entries___attributes):
        device_dict = {
            "desc": device['description'],
            "domain": extract_domain_name(device['distinguishedname']),
            "hostname": device['name'],
            "name": device['samaccountname'],
            "type": "Unknown",
            "type_id": 0,
            "uid": device['objectsid']        
        }
        
        # use OUs as labels
        ou_list = extract_ou(device['distinguishedname'])
        if ou_list:
            device_dict['labels'] = ou_list
            
        # lookup groups
        group_list = []
        for group in device['memberof']:
            if group_dict.get(group):
                group_details = group_dict[group]
                if not group_details['description']:
                    group_details['description'].append("None")
                temp_group_dict = {
                    "type": "Domain",
                    "desc": group_details['description'][0],
                    "name": group_details['name'],
                    "privileges": group_details['memberof'],
                    "uid": group_details['distinguishedname']
                }
                # drop values with []
                for k,v in temp_group_dict.copy().items():
                    if v == []:
                        temp_group_dict.pop(k)
                group_list.append(temp_group_dict)
        if group_list:
            device_dict['groups'] = group_list

                
        final_output = {
            "type": "host name",
            "value": pb_input,
            "attributes": device_dict,
            "source": "AD LDAP"
        }
        format_device_outputs__observable_array.append(final_output)
        
    # phantom.debug(format_device_outputs__observable_array)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="format_device_outputs:observable_array", value=json.dumps(format_device_outputs__observable_array))

    return


@phantom.playbook_block()
def filter_user_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_user_results() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["get_user_attributes:action_result.summary.total_objects", ">", 0]
        ],
        name="filter_user_results:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_user_groups(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_device_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_device_results() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["get_device_attributes:action_result.summary.total_objects", ">", 0]
        ],
        name="filter_device_results:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_device_groups(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def format_device_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_device_query() called")

    ################################################################################
    # Iterate through the playbook inputs and format a list of queries.
    ################################################################################

    template = """%%\n(&(objectCategory=computer)(|(sAMAccountName={0}*)(distinguishedName={0}*)(userPrincipalName={0}*)))\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:playbook_inputs_filter:condition_2:playbook_input:device"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_device_query")

    get_device_attributes(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_user_outputs__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="format_user_outputs:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    format_device_outputs__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="format_device_outputs:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    observable_combined_value = phantom.concatenate(format_user_outputs__observable_array, format_device_outputs__observable_array)

    output = {
        "observable": observable_combined_value,
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