def collect_by_cef_type(container=None, data_types=None, tags=None, scope=None, **kwargs):
    """
    Collect all artifact values that match the desired CEF data types, such as "ip", "url", "sha1", or "all". Optionally also filter for artifacts that have the specified tags.
    
    Args:
        container (CEF type: phantom container id): Container ID or container object.
        data_types: The CEF data type to collect values for. This could be a single string or a comma separated list such as "hash,filehash,file_hash". The special value "all" can also be used to collect all field values from all artifacts.
        tags: If tags are provided, only return fields from artifacts that have all of the provided tags. This could be an individual tag or a comma separated list.
        scope: Defaults to 'new'. Define custom scope. Advanced Settings Scope is not passed to a custom function. Options are 'all' or 'new'.
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.artifact_value (CEF type: *): The value of the field with the matching CEF data type.
        *.artifact_id (CEF type: phantom artifact id): ID of the artifact that contains the value.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import traceback

    # validate container and get ID
    if isinstance(container, dict) and container['id']:
        container_dict = container
        container_id = container['id']
    elif isinstance(container, int):
        rest_container = phantom.requests.get(uri=phantom.build_phantom_rest_url('container', container), verify=False).json()
        if 'id' not in rest_container:
            raise ValueError('Failed to find container with id {container}')
        container_dict = rest_container
        container_id = container
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor an int, so it cannot be used")
    
    # validate the data_types input
    if not data_types or not isinstance(data_types, str):
        raise ValueError("The input 'data_types' must exist and must be a string")
    # if data_types has a comma, split it and treat it as a list
    elif "," in data_types:
        data_types = [item.strip() for item in data_types.split(",")]
    # else it must be a single data type
    else:
        data_types = [data_types]
    
    # validate scope input
    if isinstance(scope, str) and scope.lower() in ['new', 'all']:
        scope = scope.lower()
    elif not scope:
        scope = None
    else:
        raise ValueError("The input 'scope' is not one of 'new' or 'all'")
        
    # split tags if it contains commas or use as-is
    if not tags:
        tags = []
    # if tags has a comma, split it and treat it as a list
    elif tags and "," in tags:
        tags = [item.strip() for item in tags.split(",")]
    # if there is no comma, treat it as a single tag
    else:
        tags = [tags]

    # collect all values matching the cef type (which was previously called "contains")
    collected_field_values = phantom.collect_from_contains(container=container_dict, action_results=None, contains=data_types, scope=scope)
    phantom.debug(f'found the following field values: {collected_field_values}')

    # collect all the artifacts in the container to get the artifact IDs
    artifacts = phantom.requests.get(uri=phantom.build_phantom_rest_url('container', container_id, 'artifacts'), params={'page_size': 0}, verify=False).json()['data']

    # build the output list from artifacts with the collected field values
    outputs = []
    for artifact in artifacts:
        # if any tags are provided, make sure each provided tag is in the artifact's tags
        if tags:
            if not set(tags).issubset(set(artifact['tags'])):
                continue
        # "all" is a special value to collect every value from every artifact
        if data_types == ['all']:
            for cef_key in artifact['cef']:
                new_output = {'artifact_value': artifact['cef'][cef_key], 'artifact_id': artifact['id']}
                if new_output not in outputs:
                    outputs.append(new_output)
            continue
        for cef_key in artifact['cef']:
            if artifact['cef'][cef_key] in collected_field_values:
                new_output = {'artifact_value': artifact['cef'][cef_key], 'artifact_id': artifact['id']}
                if new_output not in outputs:
                    outputs.append(new_output)

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
