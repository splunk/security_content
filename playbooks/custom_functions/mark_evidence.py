def mark_evidence(container=None, input_object=None, content_type=None, **kwargs):
    """
    Mark an object as Evidence in a container
    
    Args:
        container (CEF type: phantom container id): Container ID or Container Object
        input_object (CEF type: *): The object to mark as evidence. This could be a vault_id, artifact_id, note_id, container_id, or action_run_id. If the previous playbook block is an action then "keyword_argument:results" can be used for the action_run_id with the content_type "action_run_id". Vault_id can be an ID or a vault hash.
        content_type (CEF type: *): The content type of the object to add as evidence which must be one of the following:
                        
                        vault_id
                        artifact_id
                        container_id
                        note_id
                        action_run_id
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.id (CEF type: *): ID of the evidence item
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    container_id = None
    data = []
    valid_types = ['vault_id','artifact_id','container_id', 'note_id','action_run_id']
    
    # Ensure valid content_type: 
    if content_type.lower() not in valid_types:
        raise TypeError(f"The content_type '{content_type}' is not a valid content_type")
    
    # Ensure valid container input
    if isinstance(container, dict) and container.get('id'):
        container_id = container['id']
    elif isinstance(container, int) or (isinstance(container, str) and container.isdigit()):
        container_id = container
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor an int, so it cannot be used")
    
    # If content added is type 'action_run_id',
    # then iterate through an input object that is a results object,
    # and append the action_run_id's to data
    if isinstance(input_object, list) and content_type.lower() == 'action_run_id':
        for action_result in input_object:
            if action_result.get('action_run_id'):
                data.append({
                    "container_id": container_id,
                    "object_id": action_result['action_run_id'],
                    "content_type": 'actionrun',
                })
        # If data is still an empty list after for loop, 
        # it indicates that the input_object was not a valid results object
        if not data:
            raise TypeError("The input for 'input_object' is not a valid integer or supported object.")
    
    # If 'input_object' is already an action_run_id, no need to translate it.
    elif (isinstance(input_object, int) or (isinstance(input_object, str) and input_object.isdigit())) and content_type.lower() == 'action_run_id':
        data = [{
            "container_id": container_id,
            "object_id": input_object,
            "content_type": 'actionrun',
            }]
            
    # If vault_id was entered, check to see if user already entered a vault integer
    # else if user entered a hash vault_id, attempt to translate to a vault integer            
    elif input_object and content_type.lower() == 'vault_id':
        if isinstance(input_object, int) or (isinstance(input_object, str) and input_object.isdigit()):
            content_type = "containerattachment"
        else:
            success, message, info = phantom.vault_info(vault_id=input_object)
            if success == False:
                raise RuntimeError(f"Invalid vault_id: {message}")
            else:
                input_object = info[0]['id']    
                content_type = "containerattachment"
        data = [{
            "container_id": container_id,
            "object_id": input_object,
            "content_type": content_type,
            }]
        
    # If 'container_id' was entered, the content_type needs to be set to 'container'.
    # Phantom does not allow a literal input of 'container' so thus 'container_id is used.
    elif (isinstance(input_object, int) or (isinstance(input_object, str) and input_object.isdigit())) and content_type.lower() == 'container_id':
        data = [{
            "container_id": container_id,
            "object_id": input_object,
            "content_type": 'container',
            }]
    
    # If 'artifact_id' was entered, the content_type needs to be set to 'artifact'
    elif (isinstance(input_object, int) or (isinstance(input_object, str) and input_object.isdigit())) and content_type.lower() == 'artifact_id':
        data = [{
            "container_id": container_id,
            "object_id": input_object,
            "content_type": 'artifact',
            }]  
    # If 'note_id' was entered, the content_type needs to be set to 'note'
    elif (isinstance(input_object, int) or (isinstance(input_object, str) and input_object.isdigit())) and content_type.lower() == 'note_id':
        data = [{
            "container_id": container_id,
            "object_id": input_object,
            "content_type": 'note',
            }]  
    else:
        raise TypeError(f"The input_object is not a valid integer or supported object. Type '{type(input_object)}'")
    
    # Build url for evidence endpoint
    url = phantom.build_phantom_rest_url('evidence')
    
    # Post data to evidence endpoint
    for item in data:
        response = phantom.requests.post(uri=url, json=item, verify=False).json()

        # If successful add evidence id to outputs
        # elif evidence already exists print to debug
        # else error out 
        if response.get('success'):
            outputs.append({'id': response['id']})
        elif response.get('failed') and response.get('message') == 'Already added to Evidence.':
            phantom.debug(f"{content_type} \'{container_id}\' {response['message']}")
        else:
            raise RuntimeError(f"Unable to add evidence: {response}")

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
