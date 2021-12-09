def artifact_create(container=None, name=None, label=None, severity=None, cef_field=None, cef_value=None, cef_data_type=None, tags=None, run_automation=None, input_json=None, **kwargs):
    """
    Create a new artifact with the specified attributes.
    
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
    
    new_artifact = {}
    json_dict = None
    
    if isinstance(container, int):
        container_id = container
    elif isinstance(container, dict):
        container_id = container['id']
    else:
        raise TypeError("container is neither an int nor a dictionary")

    if name:
        new_artifact['name'] = name
    else:
        new_artifact['name'] = 'artifact'
    if label:
        new_artifact['label'] = label
    else:
        new_artifact['label'] = 'events'
    if severity:
        new_artifact['severity'] = severity
    else:
        new_artifact['severity'] = 'Medium'

    # validate that if cef_field or cef_value is provided, the other is also provided
    if (cef_field and not cef_value) or (cef_value and not cef_field):
        raise ValueError("only one of cef_field and cef_value was provided")

    # cef_data should be formatted {cef_field: cef_value}
    if cef_field:
        new_artifact['cef_data'] = {cef_field: cef_value}
        if cef_data_type and isinstance(cef_data_type, str):
            new_artifact['field_mapping'] = {cef_field: [cef_data_type]}

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
            # extract tags from json_dict since it is not a valid parameter for phantom.add_artifact()
            if json_key == 'tags':
                tags = json_dict[json_key]
            else:
                new_artifact[json_key] = json_dict[json_key]
                
    # now actually create the artifact
    phantom.debug('creating a new artifact with the following attributes:\n{}'.format(new_artifact))
    success, message, artifact_id = phantom.add_artifact(**new_artifact)

    phantom.debug('add_artifact() returned the following:\nsuccess: {}\nmessage: {}\nartifact_id: {}'.format(success, message, artifact_id))
    if not success:
        raise RuntimeError("add_artifact() failed")

    # add the tags in a separate REST call because there is no tags parameter in add_artifact()
    if tags:
        tags = tags.replace(" ", "").split(",")
        url = phantom.build_phantom_rest_url('artifact', artifact_id)
        response = phantom.requests.post(uri=url, json={'tags': tags}, verify=False).json()
        phantom.debug('response from POST request to add tags:\n{}'.format(response))
        
    # Return the id of the created artifact
    return {'artifact_id': artifact_id}
