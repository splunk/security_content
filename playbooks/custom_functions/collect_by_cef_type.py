def collect_by_cef_type(container=None, data_types=None, scope=None, tags=None, **kwargs):
    """
    Collect all artifact values that match the desired CEF data types, such as "ip", "url", "sha1", or "all". Optionally also filter for artifacts that have the specified tags.
    
    Args:
        container: (Optional) Collect data from this container. Defaults to current container.
        data_types: (Required) The CEF data type to collect values for. This could be a single string or a comma separated list such as "hash,filehash,file_hash". The special value "all" can also be used to collect all field values from all artifacts.
        scope: (Optional) Define custom scope and defaults to 'new'. Advanced Settings Scope is not passed to a custom function. Options are 'all' or 'new'.
        tags: (Optional) Only return fields from artifacts that have all of the provided tags. This could be an individual tag or a comma separated list.
    
    Returns a JSON-serializable object that implements the configured data paths:
        artifact_id (CEF type: phantom artifact id): ID of the artifact that contains the value.
        artifact_tags: The tags associated with the artifact
        cef_keys: A list of keys from that artifact where this value appears. This will usually be a list of 1.
        cef_types: A list of cef types associated with this value
        cef_value: The value of the field with the matching CEF data type.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import traceback
    
    outputs = []
    # validate container and get ID
    if isinstance(container, dict) and container['id']:
        container_dict = container
        container_id = container['id']
    elif isinstance(container, int):
        container_dict = phantom.get_container(container)
        container_id = container
    elif not container:
        container_id = phantom.get_current_container_id_()
        container_dict = phantom.get_container(container_id)
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor an int, so it cannot be used")
    
    # validate the data_types input
    if isinstance(data_types, list) and len(data_types) == 1:
        data_types = [item.strip() for item in data_types[0].split(",")]
    elif isinstance(data_types, str):
        data_types = [item.strip() for item in data_types.split(",")]
    elif not data_types:
        raise ValueError("The input 'data_types' is required and was blank")
    if 'all' in data_types and scope == 'new':
        raise ValueError("'all' datatypes not compatible with 'new' scope")
        
    # validate scope input
    if isinstance(scope, str) and scope.lower() in ['new', 'all']:
        scope = scope.lower()
    elif not scope:
        if 'all' in data_types:
            scope = 'all'
        else:
            scope = 'new'
    else:
        raise ValueError("The input 'scope' is not one of 'new' or 'all'")
        
    # tag inpuit validation
    if not tags:
        tags = []
    # if tags has a comma, split it and treat it as a list
    elif isinstance(tags, list) and len(tags) == 1:
        tags = [item.strip() for item in tags[0].split(",")]
    elif isinstance(tags, str):
        tags = [item.strip() for item in tags.split(",")]
    
    if 'all' not in data_types and scope == 'new':
        # collect all values matching the cef type (this is to support scope)
        collected_field_values = phantom.collect_from_contains(
            container=container_dict, 
            action_results=None, 
            contains=data_types, 
            scope=scope,
            tags=tags
        )
    else:
        collected_field_values = []
    
    # terminate early because there were no new artifacts
    if 'all' not in data_types and scope == 'new' and not collected_field_values:
        phantom.debug("No new artifacts found")
        return outputs
    
    # fetch all artifacts in the container
    container_artifact_url = phantom.build_phantom_rest_url('artifact')
    container_artifact_url += f'?_filter_container={container_id}&page_size=0&include_all_cef_types'
    artifacts = phantom.requests.get(container_artifact_url, verify=False).json()['data']
    # build the output list from artifacts with the collected field values
    for artifact in artifacts:
        # if any tags are provided, make sure each provided tag is in the artifact's tags
        if tags:
            if not set(tags).issubset(set(artifact['tags'])):
                continue
                
        cef_dict = {}
        for cef_key, cef_value in artifact['cef'].items():
            match = False

            # "all" is a special value to collect every value from every artifact
            if 'all' in data_types:
                # if user put 'new' in scope
                if collected_field_values and str(cef_value) in collected_field_values:
                    match = True
                # if user put 'all' in scope
                elif not collected_field_values:
                    match = True
                    
            # if user put 'new' in scope
            elif scope == 'new' and str(cef_value) in collected_field_values:
                match = True

            # if user put 'all' in scope
            elif scope == 'all':
                for data_type in data_types:
                    if data_type and data_type in artifact['cef_types'].get(cef_key, []):
                        match = True
            if match:
                if cef_dict and str(cef_value) in cef_dict.keys():
                    cef_dict[str(cef_value)]['cef_keys'].append(cef_key)
                    if artifact['cef_types'].get(cef_key):
                        cef_dict[str(cef_value)]['cef_types'].update(artifact['cef_types'][cef_key])
                else:
                    cef_dict[str(cef_value)] = {
                        'cef_keys': list(set([cef_key])),
                        'cef_value': str(cef_value), 
                        'artifact_id': artifact['id'],
                        'artifact_tags': list(set(artifact['tags'])),
                        'cef_types': set(artifact['cef_types'].get(cef_key, []))
                    }
                    
        for item in cef_dict.values():
            item['cef_types'] = list(item['cef_types'])
            outputs.append(item)

    # Return a JSON-serializable object
    assert isinstance(outputs, list)  # Will raise an exception if the :outputs: object is not a list
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
