def artifact_update(artifact_id=None, name=None, label=None, severity=None, cef_field=None, cef_value=None, cef_data_type=None, tags=None, overwrite_tags=None, input_json=None, **kwargs):
    """
    Update an artifact with the specified attributes. All parameters are optional, except that an artifact_id must be provided and if one of cef_field or cef_value is provided then they must both be provided. Supports all fields available in /rest/artifact. Add any unlisted inputs as dictionary keys in input_json. Unsupported keys will automatically be dropped.
    
    Args:
        artifact_id (CEF type: phantom artifact id): ID of the artifact to update, which is required unless artifact_id is a key within input_json
        name: Change the name of the artifact.
        label: Change the label of the artifact.
        severity: Change the severity of the artifact. Typically this is either "High", "Medium", or "Low".
        cef_field: The name of the CEF field to populate in the artifact, such as "destinationAddress" or "sourceDnsDomain". Required only if cef_value is provided.
        cef_value (CEF type: *): The value of the CEF field to populate in the artifact, such as the IP address, domain name, or file hash. Required only if cef_field is provided.
        cef_data_type: The CEF data type of the data in cef_value. For example, this could be "ip", "hash", or "domain". Optional, but only operational if cef_field is provided.
        tags: A comma-separated list of tags to apply to the artifact, which is optional.
        overwrite_tags: Optional input. Either True or False with default as False. If set to True, existing tags on the indicator record will be replaced by the provided input. If set to False, the new tags will be appended to the existing indicator tags.
        input_json: Optional parameter to modify any extra attributes of the artifact. Input_json will be merged with other inputs. In the event of a conflict, input_json will take precedence.
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    json_dict = None
    valid_keys = [
        'artifact_id', 'artifact_type', 'cef', 'cef_data', 'cef_types', 'field_mapping', 
        'data', 'end_time', 'label', 'name', 'owner_id', 
        'raw_data', 'run_automation', 'severity','start_time', 'tags', 'type'
    ]
    
    # check the input_json first, because it might have an artifact_id in it
    if input_json:
        # ensure valid input_json
        if isinstance(input_json, dict):
            json_dict = input_json
        elif isinstance(input_json, str):
            json_dict = json.loads(input_json)
        else:
            raise ValueError("input_json must be either 'dict' or valid json 'string'")
        if 'artifact_id' in json_dict:
            artifact_id = int(json_dict['artifact_id'])
    
    if not isinstance(artifact_id, int):
        raise TypeError("artifact_id is required")
    
    rest_artifact = phantom.build_phantom_rest_url('artifact', artifact_id)
    updated_artifact = phantom.requests.get(rest_artifact, verify=False).json()
    if updated_artifact.get('failed'):
        raise RuntimeError(f"GET /rest/artifact/{artifact_id} failed, {updated_artifact.get('message')}")
        
    if name:
        updated_artifact['name'] = name
    if label:
        updated_artifact['label'] = label
    if severity:
        updated_artifact['severity'] = severity 
    if overwrite_tags:
        if not isinstance(overwrite_tags, bool):
            raise TypeError("Must be a boolean, True or False")
    if tags:
        if not overwrite_tags:
            new_tags = updated_artifact['tags'] + tags.replace(" ", "").split(",")
            updated_artifact['tags'] = list(set(new_tags))
        else:
            updated_artifact['tags'] = list(set(tags.replace(" ", "").split(",")))

    # validate that if cef_field or cef_value is provided, the other is also provided
    if (cef_field and not cef_value) or (cef_value and not cef_field):
        raise ValueError("only one of cef_field and cef_value was provided")

    # cef_data should be formatted {cef_field: cef_value}
    if cef_field:
        updated_artifact['cef'].update({cef_field: cef_value})
        if cef_data_type and isinstance(cef_data_type, str):
            updated_artifact['cef_types'].update({cef_field: [cef_data_type]})
            
    if json_dict:
        # Merge dictionaries, using the value from json_dict if there are any conflicting keys
        for json_key in json_dict:
            if json_key == 'artifact_id':
                continue
            if json_key in valid_keys:
                # translate keys supported in phantom.add_artifact() to their corresponding values in /rest/artifact
                if json_key == 'raw_data':
                    updated_artifact['data'].update(json_dict[json_key])
                elif json_key == 'cef_data':
                    updated_artifact['cef'].update(json_dict[json_key])
                elif json_key == 'artifact_type':
                    updated_artifact['type'] = json_dict[json_key]
                elif json_key == 'field_mapping':
                    updated_artifact['cef_types'].update(json_dict[json_key])
                else:
                    if isinstance(updated_artifact[json_key], dict):
                        updated_artifact[json_key].update(json_dict[json_key])
                    elif isinstance(updated_artifact[json_key], list):
                        updated_artifact[json_key] = updated_artifact[json_key] + json_dict[json_key]
                        updated_artifact[json_key] = list(set(updated_artifact[json_key]))
                    else:
                        updated_artifact[json_key] = json_dict[json_key]
            else:
                phantom.debug(f"Unsupported key: '{json_key}'")
    
    # now actually update the artifact
    phantom.debug('Updating artifact {} with the following attributes:\n{}'.format(artifact_id, updated_artifact))
    response_json = phantom.requests.post(rest_artifact, json=updated_artifact, verify=False).json()
    if not response_json.get('success'):
        raise RuntimeError("POST /rest/artifact failed")
    else:
        phantom.debug(response_json)
        outputs['artifact_id'] = response_json['id']

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
