def find_related_containers(value_list=None, minimum_match_count=None, container=None, earliest_time=None, filter_status=None, filter_label=None, filter_severity=None, filter_in_case=None, **kwargs):
    """
    Takes a provided list of indicator values to search for and finds all related containers. It will produce a list of the related container details.
    
    Args:
        value_list (CEF type: *): An indicator value to search on, such as a file hash or IP address. To search on all indicator values in the container, use "*".
        minimum_match_count (CEF type: *): The minimum number of similar indicator records that a container must have to be considered "related."  If no match count provided, this will default to 1.
        container (CEF type: phantom container id): The container to run indicator analysis against. Supports container object or container_id. This container will also be excluded from the results for related_containers.
        earliest_time: Optional modifier to only consider related containers within a time window. Default is -30d.  Supports year (y), month (m), day (d), hour (h), or minute (m)  Custom function will always set the earliest container window based on the input container "create_time".
        filter_status: Optional comma-separated list of statuses to filter on. Only containers that have statuses matching an item in this list will be included.
        filter_label: Optional comma-separated list of labels to filter on. Only containers that have labels matching an item in this list will be included.
        filter_severity: Optional comma-separated list of severities to filter on. Only containers that have severities matching an item in this list will be included.
        filter_in_case: Optional parameter to filter containers that are in a case or not. Defaults to True (drop containers that are already in a case).
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.container_id (CEF type: *): The unique id of the related container
        *.container_indicator_match_count: The number of indicators matched to the related container
        *.container_status: The status of the related container e.g. new, open, closed
        *.container_type: The type of the related container, e.g. default or case
        *.container_name: The name of the related container
        *.in_case: True or False if the related container is already included in a case
        *.indicator_ids: Indicator ID that matched
        *.container_url (CEF type: url): Link to container
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    from datetime import datetime, timedelta
    from urllib import parse
    
    outputs = []
    related_containers = []
    indicator_id_dictionary = {}
    container_dictionary = {}
    offset_time = None
    
    base_url = phantom.get_base_url()
    indicator_by_value_url = phantom.build_phantom_rest_url('indicator_by_value')
    indicator_common_container_url = phantom.build_phantom_rest_url('indicator_common_container')
    container_url = phantom.build_phantom_rest_url('container')

    # Get indicator ids based on value_list
    def format_offset_time(seconds):
        datetime_obj = datetime.now() - timedelta(seconds=seconds)
        formatted_time = datetime_obj.strftime('%Y-%m-%dT%H:%M:%S.%fZ')  
        return formatted_time
    
    def fetch_indicator_ids(value_list):
        indicator_id_list = []
        for value in value_list:
            params = {'indicator_value': f'{value}', 'timerange': 'all'}
            indicator_id = phantom.requests.get(indicator_by_value_url, params=params, verify=False).json().get('id')
            if indicator_id:
                indicator_id_list.append(indicator_id)
        return indicator_id_list
    
    # Ensure valid time modifier
    if earliest_time:
        # convert user-provided input to seconds
        char_lookup = {'y': 31557600, 'mon': 2592000, 'w': 604800, 'd': 86400, 'h': 3600, 'm': 60}
        pattern = re.compile(r'-(\d+)([mM][oO][nN]|[yYwWdDhHmM]{1})$')
        if re.search(pattern, earliest_time):
            integer, char = (re.findall(pattern, earliest_time)[0])
            time_in_seconds = int(integer) * char_lookup[char.lower()]
        else:
            raise RuntimeError(f'earliest_time string "{earliest_time}" is incorrectly formatted. Format is -<int><time> where <int> is an integer and <time> is y, mon, w, d, h, or m. Example: "-1h"')
    else:
        # default 30 days in seconds
        time_in_seconds = 2592000

    # Ensure valid container input
    if isinstance(container, dict) and container.get('id'):
        current_container = container['id']
    elif isinstance(container, int):
        current_container = container
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor an int, so it cannot be used")
    
    if minimum_match_count and not isinstance(minimum_match_count, int):
        raise TypeError(f"Invalid type for 'minimum_match_count', {type(minimum_match_count)}, must be 'int'")
    elif not minimum_match_count:
        minimum_match_count = 1
    
    # Ensure valid filter inputs
    status_list, label_list, severity_list = [], [], []
    if isinstance(filter_status, str):
        status_list = [item.strip().lower() for item in filter_status.split(',')]
    if isinstance(filter_label, str):
        label_list = [item.strip().lower() for item in filter_label.split(',')]
    if isinstance(filter_severity, str):
        severity_list = [item.strip().lower() for item in filter_severity.split(',')]
    if isinstance(filter_in_case, str) and filter_in_case.lower() == 'false':
        filter_in_case = False
    else:
        filter_in_case = True
    
    # If value list is equal to * then proceed to grab all indicator records for the current container
    if value_list and (isinstance(value_list, list) and "*" in value_list) or (isinstance(value_list, str) and value_list == "*"):
        new_value_list = []
        url = phantom.build_phantom_rest_url('container', current_container, 'artifacts') + '?page_size=0'
        response_data = phantom.requests.get(uri=url, verify=False).json().get('data')
        if response_data:
            for data in response_data:
                for k,v in data['cef'].items():
                    if isinstance(v, list):
                        for item in v:
                            new_value_list.append(item)
                    else:
                        new_value_list.append(v)
        new_value_list = list(set(new_value_list))
        indicator_id_list = fetch_indicator_ids(new_value_list)
    elif isinstance(value_list, list):
        # dedup value_list
        value_list = list(set(value_list))
        indicator_id_list = fetch_indicator_ids(value_list)
    else:
        raise TypeError(f"Invalid input for value_list: '{value_list}'")

    # Quit early if no indicator_ids were found
    if not indicator_id_list:
        phantom.debug(f"No indicators IDs found for provided values: '{value_list}'")
        assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
        return outputs
    
    # Get list of related containers
    for indicator_id in list(set(indicator_id_list)):
        params = {'indicator_ids': indicator_id}
        response_data = phantom.requests.get(indicator_common_container_url, params=params, verify=False).json()
        
        # Populate an indicator dictionary where the original ids are the dictionary keys and the                     
        # associated continers are the values
        if response_data:
            indicator_id_dictionary[str(indicator_id)] = []
            for item in response_data:
                # Append all related containers except for current container
                if item['container_id'] != current_container:
                    indicator_id_dictionary[str(indicator_id)].append(item['container_id'])

    # Iterate through the newly created indicator id dictionary and create a dictionary where 
    # the keys are related containers and the values are the associated indicator ids
    for k,v in indicator_id_dictionary.items():
        for item in v:
            if str(item) not in container_dictionary.keys():
                container_dictionary[str(item)] = [str(k)]
            else:
                container_dictionary[str(item)].append(str(k))
        
    # Iterate through the newly created container dictionary                
    if container_dictionary:
        
        container_number = 0
        # Dedupe the number of indicators
        for k,v in container_dictionary.items():
            container_dictionary[str(k)] = list(set(v))
             # Count how many containers are actually going to be queried based on minimum_match_count
            if len(container_dictionary[str(k)]) >= minimum_match_count:
                container_number += 1
                
        # If the container number is greater than 600, then its faster to grab all containers
        if container_number >= 600:

            # Gather container data
            params = {'page_size': 0}
            params['_filter__create_time__gt'] = f'"{format_offset_time(time_in_seconds)}"'
            containers_response = phantom.requests.get(uri=container_url, params=params, verify=False).json()
            all_container_dictionary = {}
            if containers_response['count'] > 0:
                
                # Build repository of available container data
                for data in containers_response['data']:
                    all_container_dictionary[str(data['id'])] = data

                for k,v in container_dictionary.items():

                    # Omit any containers that have less than the minimum match count
                    if len(container_dictionary[str(k)]) >= minimum_match_count:
                        valid_container = True
                        # Grab container details if its a valid container based on previous filtering.
                        if str(k) in all_container_dictionary.keys():
                            container_data = all_container_dictionary[str(k)]
                            
                            # Omit any containers that don't meet the specified criteria
                            if container_data['create_time'] < format_offset_time(time_in_seconds): 
                                valid_container = False
                            if status_list and container_data['status'].lower() not in status_list:
                                valid_container = False
                            if label_list and container_data['label'].lower() not in label_list:
                                valid_container = False
                            if severity_list and container_data['severity'].lower() not in severity_list:
                                valid_container = False
                            if response_data['in_case'] and filter_in_case:
                                valid_container = False
                                
                            # Build outputs if checks are passed
                            if valid_container:
                                outputs.append({
                                    'container_id': str(k),
                                    'container_indicator_match_count': len(container_dictionary[str(k)]),
                                    'container_status': container_data['status'],
                                    'container_type': container_data['container_type'],
                                    'container_name': container_data['name'],
                                    'container_url': base_url.rstrip('/') + '/mission/{}'.format(str(k)),
                                    'in_case': container_data['in_case'],
                                    'indicator_id': container_dictionary[str(k)]
                                })

            else:
                raise RuntimeError(f"'Unable to find any valid containers at url: '{url}'")
                
        elif container_number < 600 and container_number > 0:
            # if the container number is smaller than 600, its faster to grab each container individiually
            for k,v in container_dictionary.items():
                # Dedupe the number of indicators
                container_dictionary[str(k)] = list(set(v))

                # If any of the containers contain more than the minimum match count request that container detail.
                if len(container_dictionary[str(k)]) >= minimum_match_count:
                    
                    valid_container = True
                    
                    # Grab container details
                    url = phantom.build_phantom_rest_url('container', k)
                    response_data = phantom.requests.get(url, verify=False).json()
                            
                    # Omit any containers that don't meet the specified criteria
                    if response_data['create_time'] < format_offset_time(time_in_seconds): 
                        valid_container = False
                    if status_list and response_data['status'].lower() not in status_list:
                        valid_container = False
                    if label_list and response_data['label'].lower() not in label_list:
                        valid_container = False
                    if severity_list and response_data['severity'].lower() not in severity_list:
                        valid_container = False
                    if response_data['in_case'] and filter_in_case:
                        valid_container = False
                    
                    # Build outputs if checks are passed and valid_container is still true
                    if valid_container: 
                        outputs.append({
                            'container_id': str(k),
                            'container_indicator_match_count': len(container_dictionary[str(k)]),
                            'container_status': response_data['status'],
                            'container_severity': response_data['severity'],
                            'container_type':  response_data['container_type'],
                            'container_name':  response_data['name'],
                            'container_url': base_url.rstrip('/') + '/mission/{}'.format(str(k)),
                            'in_case': response_data['in_case'],
                            'indicator_ids': container_dictionary[str(k)]
                        })


    else:
        raise RuntimeError('Unable to create container_dictionary')               
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
