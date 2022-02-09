def artifact_update(artifact_id=None, name=None, label=None, severity=None, cef_field=None, cef_value=None, cef_data_type=None, tags=None, input_json=None, **kwargs):
    """
    Update an artifact with the specified attributes. All parameters are optional, except that cef_field and cef_value must both be provided if one is provided.
    
    Args:
        artifact_id (CEF type: phantom artifact id): ID of the artifact to update, which is required.
        name: Change the name of the artifact.
        label: Change the label of the artifact.
        severity: Change the severity of the artifact. Typically this is either "High", "Medium", or "Low".
        cef_field: The name of the CEF field to populate in the artifact, such as "destinationAddress" or "sourceDnsDomain". Required only if cef_value is provided.
        cef_value (CEF type: *): The value of the CEF field to populate in the artifact, such as the IP address, domain name, or file hash. Required only if cef_field is provided.
        cef_data_type: The CEF data type of the data in cef_value. For example, this could be "ip", "hash", or "domain". Optional, but only operational if cef_field is provided.
        tags: A comma-separated list of tags to apply to the artifact, which is optional.
        input_json: Optional parameter to modify any extra attributes of the artifact. Input_json will be merged with other inputs. In the event of a conflict, input_json will take precedence.
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    updated_artifact = {}
    
    if not isinstance(artifact_id, int):
        raise TypeError("artifact_id is required")

    if name:
        updated_artifact['name'] = name
    if label:
        updated_artifact['label'] = label
    if severity:
        updated_artifact['severity'] = severity

    # validate that if cef_field or cef_value is provided, the other is also provided
    if (cef_field and not cef_value) or (cef_value and not cef_field):
        raise ValueError("only one of cef_field and cef_value was provided")

    # cef_data should be formatted {cef_field: cef_value}
    if cef_field:
        updated_artifact['cef'] = {cef_field: cef_value}
        if cef_data_type and isinstance(cef_data_type, str):
            updated_artifact['cef_types'] = {cef_field: [cef_data_type]}
    
    # separate tags by comma
    if tags:
        tags = tags.replace(" ", "").split(",")
        updated_artifact['tags'] = tags
    
    if input_json:
        json_dict = json.loads(input_json)
        # Merge dictionaries, using the value from json_dict if there are any conflicting keys
        for json_key in json_dict:
            updated_artifact[json_key] = json_dict[json_key]
    
    # now actually update the artifact
    phantom.debug('updating artifact {} with the following attributes:\n{}'.format(artifact_id, updated_artifact))
    url = phantom.build_phantom_rest_url('artifact', artifact_id)
    response = phantom.requests.post(url, json=updated_artifact, verify=False).json()

    phantom.debug('POST /rest/artifact returned the following response:\n{}'.format(response))
    if 'success' not in response or response['success'] != True:
        raise RuntimeError("POST /rest/artifact failed")

    return
