def indicator_collect(container=None, **kwargs):
    """
    Collect all indicators in a container and separate them by data type. Additional output data paths are created for each data type. Artifact scope is ignored. 
    
    Args:
        container (CEF type: phantom container id): The current container
    
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
    
    outputs = {'all_indicators': []}
    data_types = [
        "domain",
        "file name",
        "file path",
        "hash",
        "host name",
        "ip",
        "mac address",
        "md5",
        "port",
        "process name",
        "sha1",
        "sha256",
        "sha512",
        "url",
        "user name",
        "vault id"
    ]
    
    for data_type in data_types:
        data_type_escaped = data_type.replace(' ', '_')
        outputs[data_type_escaped] = []

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
    
    # fetch all artifacts in the container
    artifacts = phantom.requests.get(uri=phantom.build_phantom_rest_url('container', container_id, 'artifacts'), params={'page_size': 0}, verify=False).json()['data']
    
    for artifact in artifacts:
        artifact_id = artifact['id']
        for cef_key in artifact['cef']:
            cef_value = artifact['cef'][cef_key]
            params = {'indicator_value': cef_value, "_special_contains": True, 'page_size': 1}
            indicator_data = phantom.requests.get(uri=phantom.build_phantom_rest_url('indicator_by_value'), params=params, verify=False)
            if indicator_data.status_code == 200:
                indicator_json = indicator_data.json()
            data_types = []
            if indicator_json.get('id'):
                data_types = indicator_json['_special_contains']
                # drop none
                data_types = [item for item in data_types if item]

            # store the value in all_indicators and a list of values for each data type
            outputs['all_indicators'].append({'cef_key': cef_key, 'cef_value': cef_value, 'artifact_id': artifact_id, 'data_types': data_types})
            for data_type in data_types:
                # outputs will have underscores instead of spaces
                data_type_escaped = data_type.replace(' ', '_')
                if data_type_escaped not in outputs:
                    outputs[data_type_escaped] = []
                outputs[data_type_escaped].append({'cef_key': cef_key, 'cef_value': cef_value, 'artifact_id': artifact_id})

    # sort the all_indicators outputs to make them more consistent
    outputs['all_indicators'].sort(key=lambda indicator: str(indicator['cef_value']))

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
