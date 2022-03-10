def artifact_create(container=None, name=None, label=None, severity=None, cef_field=None, cef_value=None, cef_data_type=None, tags=None, run_automation=None, input_json=None, **kwargs):
    """
    Create a new artifact with the specified attributes. Supports all fields available in /rest/artifact. Add any unlisted inputs as dictionary keys in input_json. Unsupported keys will automatically be dropped.
    
    Args:
        container (CEF type: phantom container id): Container which the artifact will be added to.
        name: The name of the new artifact, which is optional and defaults to "artifact".
        label: The label of the new artifact, which is optional and defaults to "events"
        severity: The severity of the new artifact, which is optional and defaults to "Medium". Typically this is either "High", "Medium", or "Low".
        cef_field: The name of the CEF field to populate in the artifact, such as "destinationAddress" or "sourceDnsDomain". Required only if cef_value is provided.
        cef_value (CEF type: *): The value of the CEF field to populate in the artifact, such as the IP address, domain name, or file hash. Required only if cef_field is provided.
        cef_data_type: The CEF data type of the data in cef_value. For example, this could be "ip", "hash", or "domain". Optional.
        tags: A comma-separated list of tags to apply to the created artifact, which is optional.
        run_automation: Either "true" or "false", depending on whether or not the new artifact should trigger the execution of any playbooks that are set to active on the label of the container the artifact will be added to. Optional and defaults to "false".
        input_json: Optional parameter to modify any extra attributes of the artifact. Input_json will be merged with other inputs. In the event of a conflict, input_json will take precedence.
    
    Returns a JSON-serializable object that implements the configured data paths:
        artifact_id (CEF type: phantom artifact id): The ID of the created artifact.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    valid_keys = [
        'artifact_type', 'cef', 'cef_data', 'cef_types', 'container', 'container_id',  
        'field_mapping', 'data', 'description', 'end_time', 'has_note', 'identifier', 
        'ingest_app', 'ingest_app_id', 'kill_chain', 'label', 'name', 'owner_id', 
        'parent_container', 'parent_artifact', 'raw_data', 'run_automation', 'severity',
        'source_data_identifier', 'start_time', 'tags', 'type'
    ]
    new_artifact = {}
    json_dict = None
    rest_artifact = phantom.build_phantom_rest_url('artifact')
    outputs = {}
    
    if isinstance(container, int):
        new_artifact['container_id'] = container
    elif isinstance(container, dict):
        new_artifact['container_id'] = container['id']
    else:
        raise TypeError("container is neither an int nor a dictionary")
    
    new_artifact['name'] = name if name else 'artifact'
    new_artifact['label'] = label if label else 'events'
    new_artifact['severity'] = severity if severity else 'Medium'
    new_artifact['tags'] = tags.replace(" ", "").split(",") if tags else None

    # validate that if cef_field or cef_value is provided, the other is also provided
    if (cef_field and not cef_value) or (cef_value and not cef_field):
        raise ValueError("only one of cef_field and cef_value was provided")

    # cef_data should be formatted {cef_field: cef_value}
    if cef_field:
        new_artifact['cef'] = {cef_field: cef_value}
        if cef_data_type and isinstance(cef_data_type, str):
            new_artifact['cef_types'] = {cef_field: [cef_data_type]}

    # run_automation must be "true" or "false" and defaults to "false"
    if run_automation:
        if not isinstance(run_automation, str):
            raise TypeError("run automation must be a string")
        if run_automation.lower() == 'true':
            new_artifact['run_automation'] = True
        elif run_automation.lower() == 'false':
            new_artifact['run_automation'] = False
        else:
            raise ValueError("run_automation must be either 'true' or 'false'")
    else:
        new_artifact['run_automation'] = False
    
    if input_json:
        # ensure valid input_json
        if isinstance(input_json, dict):
            json_dict = input_json
        elif isinstance(input_json, str):
            json_dict = json.loads(input_json)
        else:
            raise ValueError("input_json must be either 'dict' or valid json 'string'")
        
    if json_dict:
        # Merge dictionaries, using the value from json_dict if there are any conflicting keys
        for json_key in json_dict:
            if json_key in valid_keys:
                # translate keys supported in phantom.add_artifact() to their corresponding values in /rest/artifact
                if json_key == 'container':
                    new_artifact['container_id'] = json_dict[json_key]
                elif json_key == 'raw_data':
                    new_artifact['data'] = json_dict[json_key]
                elif json_key == 'cef_data':
                    new_artifact['cef'] = json_dict[json_key]
                elif json_key == 'identifier':
                    new_artifact['source_data_identifier'] = json_dict[json_key]
                elif json_key == 'ingest_app':
                    new_artifact['ingest_app_id'] = json_dict[json_key]
                elif json_key == 'artifact_type':
                    new_artifact['type'] = json_dict[json_key]
                elif json_key == 'field_mapping':
                    new_artifact['cef_types'] = json_dict[json_key]
                else:
                    new_artifact[json_key] = json_dict[json_key]
            else:
                phantom.debug(f"Unsupported key: '{json_key}'")
                
    # now actually create the artifact
    phantom.debug(f"Creating artifact with the following details: '{new_artifact}'")
    response_json = phantom.requests.post(rest_artifact, json=new_artifact, verify=False).json()
    if response_json.get('message', '') == 'artifact already exists':
        phantom.debug(f"Artifact already exists: '{response_json['existing_artifact_id']}'")
    elif not response_json.get('success'):
        raise RuntimeError(f"Error creating artifact: '{response_json}'")
    else:
        outputs['artifact_id'] = response_json['id']
        
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs