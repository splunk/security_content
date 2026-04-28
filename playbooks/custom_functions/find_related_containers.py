def find_related_containers(field_list=None, value_list=None, minimum_match_count=None, container=None, earliest_time=None, filter_status=None, filter_label=None, filter_severity=None, filter_in_case=None, **kwargs):
    """
    Takes a list of indicator values or field names that may appear in other containers on the system. If any related containers are found, it will produce a list of the related container details.
    
    Args:
        field_list (CEF type: *): A comma separated list of fields to search on. Do not use data paths, only field names. Not compatible with value_list. Field/value combinations are OR'd together. Only containers that share the exact value(s) contained in the exact field(s) will contribute to minimum_match_count. 
        value_list (CEF type: *): A list of indicator values to search on, such as a file hash or IP address. Values are OR'd together. To search on all indicator values in the container, use "*". Not compatible with field_list.
        minimum_match_count: The minimum number of values from the value_list parameter or the fields from the field_list that must match with related containers. Supports an integer or the string 'all'. Adding 'all' will set the minimum_match_count to the length of the number of unique values in the value_list or the number of unique fields in the field_list. If no match count provided, this will default to 1.
        container (CEF type: phantom container id): The container to run indicator analysis against. Supports container object or container_id. This container will also be excluded from the results for related_containers.
        earliest_time: Optional modifier to only consider related containers within a time window. Default is -30d.  Supports year (y), month (m), day (d), hour (h), or minute (m)  Custom function will always set the earliest container window based on the input container "create_time".
        filter_status: Optional comma-separated list of status IDs or status names to filter on. Only containers that have statuses matching an item in this list will be included. If status names are provided, the automation user must have administrator privileges. Use `/rest/container_status` to obtain status ids instead of adding administrator privileges.
        filter_label (CEF type: phantom container label): Optional comma-separated list of labels to filter on. Only containers that have labels matching an item in this list will be included.
        filter_severity: Optional comma-separated list of severities to filter on. Only containers that have severities matching an item in this list will be included.
        filter_in_case: Optional parameter to filter containers that are in a case or not. True for only containers in cases, False for only containers not in cases. Default is all containers.
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.container_id (CEF type: *): The unique id of the related container
        *.container_indicator_match_count: The number of indicators matched to the related container if value_list provided
        *.container_status: The status of the related container e.g. new, open, closed
        *.container_type: The type of the related container, e.g. default or case
        *.container_name: The name of the related container
        *.in_case: True or False if the related container is already included in a case
        *.indicator_ids: Indicator ID that matched if value list provided
        *.container_url (CEF type: url): Link to container
        *.container_field_list: List of fields that matched if field_list provided.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    from datetime import datetime, timedelta
    from urllib import parse
    from hashlib import sha256
    from collections import Counter
    from typing import Tuple

    outputs = []
    offset_time = None
    
    def grouper(seq, size) -> iter:
        # for iterting over a list {size} at a time
        return (seq[pos:pos + size] for pos in range(0, len(seq), size))
    
    def get_status_ids(status_list) -> list:
        status_url = phantom.build_phantom_rest_url('container_status')
        status_url += f'?_filter_name__in={status_list}'
        status_response = phantom.requests.get(status_url, verify=False).json()
        if status_response.get('failed') == True and "does not have permission" in status_response.get('message', ""):
            raise RuntimeError(
                "User does not have permission to view container_status. "      
                "Consider using a list of status ids instead of status names - "
                "`/rest/container_status` can be used to find Status IDs."
            )
        return [item['id'] for item in status_response.get('data', [])]
        
    
    def format_offset_time(seconds) -> str:
        # Get indicator ids based on value_list
        datetime_obj = datetime.now() - timedelta(seconds=seconds)
        formatted_time = datetime_obj.strftime('%Y-%m-%dT%H:%M:%S.%fZ')  
        return formatted_time
    
    def build_outputs(container_dict, **kwargs) -> list:
        # Take container dict of id and indicators and built a list of outputs
        output_list = []
        base_url = phantom.get_base_url()     
        container_url = phantom.build_phantom_rest_url('container') + '?page_size=0'

        for k, v in kwargs.items():
            if v:
                if k == 'earliest_time':
                    container_url += f'&_filter_create_time__gt="{format_offset_time(v)}"'
                if k == 'filter_status':
                    container_url += f'&_filter_status__in={v}'
                if k == 'filter_label':
                    container_url += f'&_filter_label__in={v}'
                if k == 'filter_severity':
                    container_url += f'&_filter_severity__in={v}'
                if k == 'filter_in_case':
                    container_url += f'&_filter_in_case="{str(v).lower()}"'              
                    
        container_id_list = list(container_dict.keys())
        for group in grouper(container_id_list, 100):
            query_url = container_url + f'&_filter_id__in={group}'
            container_response = phantom.requests.get(query_url, verify=False).json()
            for container_data in container_response.get('data', []):
                temp_dict = {
                    'container_id': container_data['id'],
                    'container_status': container_data['status'],
                    'container_type': container_data['container_type'],
                    'container_name': container_data['name'],
                    'container_url': base_url.rstrip('/') + f"/mission/{container_data['id']}",
                    'in_case': container_data['in_case']
                }
                if container_dict[str(container_data['id'])].get('indicator_ids'):
                    indicator_ids = list(container_dict[str(container_data['id'])]['indicator_ids'])
                    match_count = len(indicator_ids) 
                    temp_dict['container_indicator_match_count'] = match_count
                    temp_dict['indicator_ids'] = indicator_ids
                if container_dict[str(container_data['id'])].get('field_list'):
                    field_list = container_dict[str(container_data['id'])]['field_list']
                    temp_dict['container_field_list'] = field_list
                output_list.append(temp_dict)
        return output_list
    
    def get_field_dictionary(field_list,  current_container) -> list:
        pairing_list = []
        artifact_url = phantom.build_phantom_rest_url('container', current_container, 'artifacts')
        artifact_list = phantom.requests.get(artifact_url, verify=False).json()['data']
        if not artifact_list:
            raise RuntimeError(f"No artifacts found for {current_container}")
        for artifact in artifact_list:
            for field in field_list:
                if artifact['cef'].get(field):
                    pairing_list.append({field: artifact['cef'][field]})
        # deduplicate and return
        return list({str(i):i for i in pairing_list}.values())
        
    def find_common_containers_by_field(pairing_list, current_container, seconds) -> dict:
        container_dictionary = {}
        artifact_url = phantom.build_phantom_rest_url('artifact')
        offset_time = format_offset_time(seconds)
        for pairing in pairing_list:
            for k,v in pairing.items():
                params = {
                    '_filter_create_time__gt': f'"{offset_time}"',
                    f'_filter_cef__{k}': f'"{v}"', 
                    'page_size': 0, 
                    '_exclude_container': current_container
                }
                related_artifacts = phantom.requests.get(artifact_url, params=params, verify=False).json()
                if related_artifacts.get('data'):
                    container_id_set = set([item['container'] for item in related_artifacts['data']])
                    for container_id in container_id_set:
                        if not container_dictionary.get(str(container_id)):
                            container_dictionary[str(container_id)] = {'field_list': [{k: v}]}
                        else: 
                            container_dictionary[str(container_id)]['field_list'].append({k: v})
        for key in list(container_dictionary.keys()):   
            field_list = container_dictionary[key]['field_list']
            container_dictionary[key]['field_list'] = list({str(i):i for i in field_list}.values())
        return container_dictionary
                
    def fetch_indicators(value_list) -> Tuple[dict, set]:
        # Creats a dictionary with the value_hash as the key with a sub dictionary of indicator ids
        indicator_dictionary = {}
        indicator_url = phantom.build_phantom_rest_url('indicator')
        hashed_list = [sha256(item.encode('utf-8')).hexdigest() for item in value_list]
        indicator_id_set = set()
        for group in grouper(hashed_list, 100):
            query_url = indicator_url + f'?_filter_value_hash__in={group}&timerange=all&page_size=0'
            indicator_response = phantom.requests.get(query_url, verify=False).json()
            for data in indicator_response.get('data', []):
                indicator_dictionary[data['value_hash']] = {'indicator_id': data['id']}
                indicator_id_set.add(data['id'])
        return indicator_dictionary, indicator_id_set
    
    def add_common_containers(indicator_dictionary) -> dict:
        # Adds container_ids to the indicator dictionary
        indicator_common_container_url = phantom.build_phantom_rest_url('indicator_common_container') + '?page_size=0'
        for indicator_hash, dict_object in indicator_dictionary.items():
            indicator_dictionary[indicator_hash].update({'container_ids': []})
            query_url = indicator_common_container_url + f"&indicator_ids={dict_object['indicator_id']}"
            container_response = phantom.requests.get(query_url, verify=False).json()
            for container_object in container_response:
                indicator_dictionary[indicator_hash]['container_ids'].append(container_object['container_id'])
        return indicator_dictionary
    
    def match_indicator_per_container(indicator_dictionary, exclude_container) -> dict:
        # Create a new dictionary filled with container_ids as keys and the set of related indicators as values
        container_dictionary = {}
        for dict_object in indicator_dictionary.values():
            for container_id in dict_object['container_ids']:
                if container_id != exclude_container:
                    if not container_dictionary.get(str(container_id)):
                        container_dictionary[str(container_id)] = {'indicator_ids': {dict_object['indicator_id']}}
                    else:
                        container_dictionary[str(container_id)]['indicator_ids'].add(dict_object['indicator_id'])
        return container_dictionary
    
    def test_minimum_match(minimum_match_count, input_list) -> None:
        # Fail early if minimum_match_count exceeds the number of provided values
        if isinstance(minimum_match_count, int) and minimum_match_count > len(input_list):
            raise RuntimeError(
                f"The provided minimum_match_count '{minimum_match_count}' "
                f"exceeds the number of unique fields or values given: '{len(input_list)}'. "
                f"Try providing additional values in the value_list, additional fields in the field_list, "
                f"decreasing the minimum_match_count, or entering 'all' in minimum_match_count."
            )
        return
    
    
    ## Start Input Checking ##
    ## -------------------- ##
    
    # Ensure valid time modifier
    if earliest_time:
        # convert user-provided input to seconds
        char_lookup = {'y': 31557600, 'mon': 2592000, 'w': 604800, 'd': 86400, 'h': 3600, 'm': 60}
        pattern = re.compile(r'-(\d+)([mM][oO][nN]|[yYwWdDhHmM]{1})$')
        if re.search(pattern, earliest_time):
            integer, char = (re.findall(pattern, earliest_time)[0])
            time_in_seconds = int(integer) * char_lookup[char.lower()]
        else:
            raise RuntimeError(
                f"earliest_time string '{earliest_time}' is incorrectly formatted. "
                f"Format is -<int><time> where <int> is an integer and <time> is y, mon, w, d, h, or m. Example: '-1h'")
    else:
        earliest_time = "-30d"
        # default 30 days in seconds
        time_in_seconds = 2592000

    # Ensure valid container input
    if isinstance(container, dict) and container.get('id'):
        current_container = container['id']
    elif isinstance(container, int):
        current_container = container
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor an int, so it cannot be used")
    
    # Check for conflicting inputs
    if field_list and value_list:
        raise ValueError("Cannot provide both field_list and value_list")
    # If it exists, ensures field list is always a list
    if field_list:
        if isinstance(field_list, str):
            field_list = [item.strip(' ') for item in field_list.split(',')]
        elif isinstance(field_list, list):
            field_list = [item for item in field_list if isinstance(item, str)]
        else:
            raise TypeError(f"Invalid input for field_list: '{field_list}'. Must be str or list.")

    # If value list is equal to * then proceed to grab all indicator records for the current container
    elif value_list and ((isinstance(value_list, list) and "*" in value_list) or (isinstance(value_list, str) and value_list == "*")):
        new_value_list = set()
        url = phantom.build_phantom_rest_url('container', current_container, 'artifacts') + '?page_size=0'
        response_data = phantom.requests.get(url, verify=False).json()
        for data in response_data.get('data', []):
            for k,v in data['cef'].items():
                if isinstance(v, str) or isinstance(v, bool) or isinstance(v, int) or isinstance(v, float):
                     new_value_list.add(str(v))
        value_list = list(new_value_list)
    elif isinstance(value_list, list):
        value_set = set()
        for item in value_list:
            if isinstance(item, str) or isinstance(item, bool) or isinstance(item, int) or isinstance(item, float):
                value_set.add(str(item))
        value_list = list(value_set)
    elif isinstance(value_list, str) or isinstance(value_list, bool) or isinstance(value_list, int) or isinstance(value_list, float):
        value_list = [str(value_list)]
    else:
        raise TypeError(f"Invalid input for value_list: '{value_list}'")
    
    # check minimum_match_count is valid
    if minimum_match_count and not isinstance(minimum_match_count, int) and not isinstance(minimum_match_count, str):
        raise TypeError(f"Invalid type for 'minimum_match_count', {type(minimum_match_count)}, must be 'int' or the string 'all'")
    elif isinstance(minimum_match_count, str) and minimum_match_count.lower() == 'all':
        minimum_match_count = len(field_list if field_list else value_list)
    elif not minimum_match_count:
        minimum_match_count = 1
    test_minimum_match(minimum_match_count, field_list if field_list else value_list)
    
    # Put filters in list form
    if isinstance(filter_status, list) and len(filter_status) == 1 and isinstance(filter_status[0], str):
        filter_status = [item.strip().lower() for item in filter_status[0].split(',')]
    elif isinstance(filter_status, str) and ',' in filter_status:
        filter_status = [item.strip().lower() for item in filter_status.split(',')]
    elif isinstance(filter_status, str) or isinstance(filter_status, int):
        filter_status = [filter_status]
    if filter_label and len(filter_label) == 1 and isinstance(filter_label[0], str):
        filter_label = [item.strip().lower() for item in filter_label[0].split(',')]
    if filter_severity and len(filter_severity) == 1 and isinstance(filter_severity[0], str):
        filter_severity = [item.strip().lower() for item in filter_severity[0].split(',')]
    if isinstance(filter_in_case, str) and filter_in_case.lower() == 'false':
        filter_in_case = False
    elif isinstance(filter_in_case, str) and filter_in_case.lower() == 'true':
        filter_in_case = True
    elif filter_in_case and not isinstance(filter_in_case, bool):
        raise TypeError("Invalid input for filter_in_case. Must be 'true' or 'false' or none")
        
        
    ## ------------------- ##
    ## End Input Checking ##

    if filter_status:
        if all(elem.isnumeric() for elem in filter_status):
            filter_status = [int(elem) for elem in filter_status]
        elif all(isinstance(elem, str) for elem in filter_status) and any(elem.isnumeric() for elem in filter_status):
            raise ValueError("filter_status must be all strings or all integers")
        elif all(isinstance(elem, str) for elem in filter_status):
            filter_status = get_status_ids(filter_status)
            
    if value_list:
        indicator_dictionary, indicator_id_set = fetch_indicators(value_list)

        # Quit early if no indicator_ids were found
        if not indicator_dictionary:
            phantom.debug(f"No indicators IDs found for provided values: '{value_list}'")
            assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
            return outputs

        add_common_containers(indicator_dictionary)
        container_dict = match_indicator_per_container(indicator_dictionary, current_container)
        for container_id in list(container_dict.keys()):
            if len(container_dict[container_id]['indicator_ids'].intersection(indicator_id_set)) < minimum_match_count:
                del(container_dict[container_id])

            
    elif field_list:
        pairings_list = get_field_dictionary(field_list,  current_container)
        if not pairings_list:
            raise RuntimeError(f"No matches found for provided field_list: {field_list}")
        container_dict = find_common_containers_by_field(pairings_list, current_container, time_in_seconds)
        for container_id in list(container_dict.keys()):
            if len(container_dict[container_id]['field_list']) < minimum_match_count:
                del(container_dict[container_id])
                
    if container_dict:
        outputs = build_outputs(
            container_dict,
            earliest_time=time_in_seconds, 
            filter_status=filter_status, 
            filter_label=filter_label, 
            filter_severity=filter_severity, 
            filter_in_case=filter_in_case
        )
    if outputs:
        phantom.debug(
            f"{len(outputs)} containers found for '{minimum_match_count}' "
            f"minimum matches out of the provided input, '{field_list if field_list else value_list}', "
            f"in the past '{earliest_time}'"
        )
    else:
        phantom.debug(
            f"No related containers found for '{minimum_match_count}' "
            f"minimum matches out of the provided input, '{field_list if field_list else value_list}', "
            f"in the past '{earliest_time}'"
        )
            
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
