def indicator_collect(container=None, artifact_ids_include=None, indicator_types_include=None, indicator_types_exclude=None, indicator_tags_include=None, indicator_tags_exclude=None, **kwargs):
    """
    Collect all indicators in a container and separate them by data type. Additional output data paths are created for each data type. Artifact scope is ignored.
    
    Args:
        container (CEF type: phantom container id): The current container
        artifact_ids_include (CEF type: phantom artifact id): Optional parameter to only look for indicator values that occur in the artifacts with these IDs. Must be one of: json serializable list, comma separated integers, or a single integer.
        indicator_types_include: Optional parameter to only include indicators with at least one of the provided types in the output. If left empty, all indicator types will be included except those that are explicitly excluded. Accepts a comma-separated list.
        indicator_types_exclude: Optional parameter to exclude indicators with any of the provided types from the output. Accepts a comma-separated list.
        indicator_tags_include: Optional parameter to only include indicators with at least one of the provided tags in the output. If left empty, tags will be ignored except when they are excluded. Accepts a comma-separated list.
        indicator_tags_exclude: Optional parameter to exclude indicators with any of the provided tags from the output. Accepts a comma-separated list.
    
    Returns a JSON-serializable object that implements the configured data paths:
        all_indicators.*.cef_key
        all_indicators.*.cef_value
        all_indicators.*.data_types
        all_indicators.*.artifact_id
        domain.*.cef_key
        domain.*.cef_value (CEF type: domain)
        domain.*.artifact_id
        file_name.*.cef_key (CEF type: file name)
        file_name.*.cef_value (CEF type: file name)
        file_name.*.artifact_id
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from hashlib import sha256
    
    outputs = {'all_indicators': []}
    
    def grouper(seq, size):
        return (seq[pos:pos + size] for pos in range(0, len(seq), size))
    
    def get_indicator_json(value_set):
        value_list = list(value_set)
        indicator_url = phantom.build_phantom_rest_url('indicator') + '?page_size=0&timerange=all'
        hashed_list = [sha256(item.encode('utf-8')).hexdigest() for item in value_list]
        indicator_dictionary = {}
        for group in grouper(hashed_list, 100):
            query_url = indicator_url + f'&_filter_value_hash__in={group}'
            indicator_response = phantom.requests.get(query_url, verify=False)
            indicator_json = indicator_response.json() if indicator_response.status_code == 200 else {}
            for data in indicator_json.get('data', []):
                indicator_dictionary[data['value_hash']] = data
        return indicator_dictionary
    
    def check_numeric_list(input_list):
        return (all(isinstance(x, int) for x in input_list) or all(x.isnumeric() for x in input_list))
    
    def is_valid_indicator(list_1=None, list_2=None, check_type="include"):
        list_1 = [] if not list_1 else list_1
        list_2 = [] if not list_2 else list_2
        if check_type == 'exclude':
            if list_1 and any(item in list_1 for item in list_2):
                return False
        elif check_type == 'include':
            if list_1 and not any(item in list_1 for item in list_2):
                return False
        return True

    # validate container and get ID
    if isinstance(container, dict) and container['id']:
        container_dict = container
        container_id = container['id']
    elif isinstance(container, int):
        rest_container = phantom.requests.get(uri=phantom.build_phantom_rest_url('container', container), verify=False).json()
        if 'id' not in rest_container:
            raise RuntimeError('Failed to find container with id {container}')
        container_dict = rest_container
        container_id = container
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor a valid container id, so it cannot be used")

    if indicator_types_include:
        indicator_types_include = [item.strip(' ') for item in indicator_types_include.split(',')]
    if indicator_types_exclude:
        indicator_types_exclude = [item.strip(' ') for item in indicator_types_exclude.split(',')]
    if indicator_tags_include:
        indicator_tags_include = [item.strip(' ').replace(' ', '_') for item in indicator_tags_include.split(',')]
    if indicator_tags_exclude:
        indicator_tags_exclude = [item.strip(' ').replace(' ', '_') for item in indicator_tags_exclude.split(',')]

    if artifact_ids_include:
        # Try to convert to a valid list
        if isinstance(artifact_ids_include, str) and artifact_ids_include.startswith('[') and artifact_ids_include.endswith(']'):
            artifact_ids_include = json.loads(artifact_ids_include)
        elif isinstance(artifact_ids_include, str):
            artifact_ids_include = artifact_ids_include.replace(' ','').split(',')
        elif isinstance(artifact_ids_include, int):
            artifact_ids_include = [artifact_ids_include]
        
        # Check validity of list
        if isinstance(artifact_ids_include, list) and not check_numeric_list(artifact_ids_include):
            raise ValueError(
                f"Invalid artifact_ids_include entered: '{artifact_ids_include}'. Must be a list of integers."
            )
            
        artifact_ids_include = [int(art_id) for art_id in artifact_ids_include]
        
    indicator_set = set()
    # fetch all artifacts in the container
    container_artifact_url = phantom.build_phantom_rest_url('artifact')
    container_artifact_url += f'?_filter_container={container_id}&page_size=0&include_all_cef_types'
    artifacts = phantom.requests.get(container_artifact_url, verify=False).json()['data']
    
    for artifact in artifacts:
        artifact_id = artifact['id']
        if (artifact_ids_include and artifact_id in artifact_ids_include) or not artifact_ids_include:
            
            for cef_key in artifact['cef']:
                cef_value = artifact['cef'][cef_key]
                data_types = artifact['cef_types'].get(cef_key, [])

                # get indicator details if valid type    
                if (
                    (
                        is_valid_indicator(indicator_types_exclude, data_types, check_type='exclude')
                        and is_valid_indicator(indicator_types_include, data_types, check_type='include')
                    )
                    and
                    (
                        isinstance(cef_value, str) or isinstance(cef_value, bool) or isinstance(cef_value, int) or isinstance(cef_value, float)
                    )
                ):
                    indicator_set.add(str(cef_value))
    
    indicator_dictionary = get_indicator_json(indicator_set)
    for artifact in artifacts:
        artifact_id = artifact['id']
        if (artifact_ids_include and artifact_id in artifact_ids_include) or not artifact_ids_include:
            for cef_key in artifact['cef']:

                cef_value = artifact['cef'][cef_key]
                cef_value_hash = sha256(str(cef_value).encode('utf-8')).hexdigest()
                data_types = artifact['cef_types'].get(cef_key, [])
                if indicator_dictionary.get(cef_value_hash):
                    
                    tags = indicator_dictionary[cef_value_hash]['tags']
                    if (
                        is_valid_indicator(indicator_tags_exclude, tags, check_type='exclude')
                        and is_valid_indicator(indicator_tags_include, tags, check_type='include')
                    ):
                        outputs['all_indicators'].append({
                            'cef_key': cef_key, 
                            'cef_value': cef_value, 
                            'artifact_id': artifact_id, 
                            'data_types': data_types, 
                            'tags': tags
                        })
                        for data_type in data_types:
                            # outputs will have underscores instead of spaces
                            data_type_escaped = data_type.replace(' ', '_') 
                            if data_type_escaped not in outputs:
                                outputs[data_type_escaped] = []
                            outputs[data_type_escaped].append(
                                {'cef_key': cef_key, 'cef_value': cef_value, 'artifact_id': artifact_id, 'tags': tags}
                            )
    if outputs.get('all_indicators'):                        
        # sort the all_indicators outputs to make them more consistent
        outputs['all_indicators'].sort(key=lambda indicator: str(indicator['cef_value']))

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
