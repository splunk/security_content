def container_merge(target_container=None, container_list=None, workbook=None, close_containers=None, **kwargs):
    """
    An alternative to the add-to-case API call. This function will copy all artifacts, automation, notes and comments over from every container within the container_list into the target_container. The target_container will be upgraded to a case.
    
    The notes will be copied over with references to the child containers from where they came. A note will be left in the child containers with a link to the target container. The child containers will be marked as evidence within the target container. 
    
    Any notes left as a consequence of the merge process will be skipped in subsequent merges.
    
    Args:
        target_container (CEF type: phantom container id): The target container to copy the information over. Supports container dictionary or container id.
        container_list: A list of container IDs to copy into the target container.
        workbook: Name or ID of the workbook to add if the container does not have a workbook yet. If no workbook is provided, the system default workbook will be added.
        close_containers: True or False to close the child containers in the container_list after merge. Defaults to False.
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Check if valid target_container input was provided
    if isinstance(target_container, int):
        container = phantom.get_container(target_container)
    elif isinstance(target_container, dict):
        container = target_container
    else:
        raise TypeError(f"target_container '{target_container}' is neither a int or a dictionary")
    
    container_url = phantom.build_phantom_rest_url('container', container['id'])
    
    # Check if container_list input is a list of IDs
    if isinstance(container_list, list) and (all(isinstance(x, int) for x in container_list) or all(x.isnumeric() for x in container_list)):
        pass
    else:
        raise TypeError(f"container_list '{container_list}' is not a list of integers")

    ## Prep parent container as case with workbook ##
    workbook_name = phantom.requests.get(container_url, verify=False).json().get('workflow_name')
    # If workbook already exists, proceed to promote to case
    if workbook_name:
        phantom.debug("workbook already exists. adding [Parent] to container name and promoting to case")
        update_data = {'container_type': 'case'}
        if not '[Parent]' in container['name']:
            update_data['name'] = "[Parent] {}".format(container['name'])
            phantom.update(container, update_data)
        else:
            phantom.update(container, update_data)
    # If no workbook exists, add one
    else:
        phantom.debug("no workbook in container. adding one by name or using the default")
        # If workbook ID was provided, add it
        if isinstance(workbook, int):
            workbook_id = workbook
            phantom.add_workbook(container=container['id'], workbook_id=workbook_id)
        # elif workbook name was provided, attempt to translate it to an id
        elif isinstance(workbook, str):
            workbook_url = phantom.build_phantom_rest_url('workbook_template') + '?_filter_name="{}"'.format(workbook)
            response = phantom.requests.get(workbook_url, verify=False).json()
            if response['count'] > 1:
                raise RuntimeError('Unable to add workbook - more than one ID matches workbook name')
            elif response['data'][0]['id']:
                workbook_id = response['data'][0]['id']
                phantom.add_workbook(container=container['id'], workbook_id=workbook_id)
        else:
            # Adding default workbook
            phantom.promote(container=container['id'])
        # Check again to see if a workbook now exists
        workbook_name = phantom.requests.get(container_url, verify=False).json().get('workflow_name')
        # If workbook is now present, promote to case
        if workbook_name:
            update_data = {'container_type': 'case'}
            if not '[Parent]' in container['name']:
                update_data['name'] = "[Parent] {}".format(container['name'])
                phantom.update(container, update_data)
            else:
                phantom.update(container, update_data)
        else:
            raise RuntimeError(f"Error occurred during workbook add for workbook '{workbook_name}'")
            
    ## Check if current phase is set. If not, set the current phase to the first available phase to avoid artifact merge error ##
    if not container.get('current_phase_id'):
        phantom.debug("no current phase, so setting first available phase to current")
        workbook_phase_url = phantom.build_phantom_rest_url('workbook_phase') + "?_filter_container={}".format(container['id'])
        request_json = phantom.requests.get(workbook_phase_url, verify=False).json()
        update_data = {'current_phase_id': request_json['data'][0]['id']}
        phantom.update(container, update_data)
    
    child_container_list = []
    child_container_name_list = []
    # Iterate through child containers 
    for child_container_id in container_list:
        
        ### Begin child container processing ###
        phantom.debug("Processing Child Container ID: {}".format(child_container_id))
        
        child_container = phantom.get_container(child_container_id)
        child_container_list.append(child_container_id)
        child_container_name_list.append(child_container['name'])
        child_container_url = phantom.build_phantom_rest_url('container', child_container_id) 
        
        ## Update container name with parent relationship
        if not "[Parent:" in child_container['name']:
            update_data = {'name': "[Parent: {0}] {1}".format(container['id'], child_container['name'])}
            phantom.update(child_container, update_data)
        
        ## Gather and add notes ##
        for note in phantom.get_notes(container=child_container_id):
            # Avoid copying any notes related to the merge process.
            if note['success'] and not note['data']['title'] in ('[Auto-Generated] Related Containers', 
                                                                 '[Auto-Generated] Parent Container', 
                                                                 '[Auto-Generated] Child Containers'):
                phantom.add_note(container=container['id'],
                                 note_type='general',
                                 note_format=note['data']['note_format'],
                                 title="[From Event {0}] {1}".format(note['data']['container'], note['data']['title']),
                                 content=note['data']['content'])
                 
        ## Copy information and add to case
        data = {'add_to_case': True,
                'container_id': child_container_id,
                'copy_artifacts': True,
                'copy_automation': True,
                'copy_files': True,
                'copy_comments': True
               }   
        phantom.requests.post(container_url, json=data, verify=False)
        
        ## Leave a note with a link to the parent container
        phantom.debug("Adding parent relationship note to child container '{}'".format(child_container_id))
        data_row = "{0} | [{1}]({2}/mission/{0}) |".format(container['id'], container['name'], phantom.get_base_url())
        phantom.add_note(container=child_container_id,
                         note_type="general",
                         note_format="markdown",
                         title="[Auto-Generated] Parent Container",
                         content="| Container_ID | Container_Name |\n| --- | --- |\n| {}".format(data_row))
        
        ## Mark child container as evidence in target_container
        data = {
            "container_id": container['id'],
            "object_id": child_container_id,
            "content_type": "container"
        }
        evidence_url = phantom.build_phantom_rest_url('evidence')
        response = phantom.requests.post(evidence_url, json=data, verify=False).json()
        
        ## Close child container
        if isinstance(close_containers, str) and close_containers.lower() == 'true':
            phantom.set_status(container=child_container_id, status="closed")
            
        ### End child container processing ###
        
    ## Format and add note for link back to child_containers in parent_container
    note_title = "[Auto-Generated] Child Containers"
    note_format = "markdown"
    format_list = []
    # Build new note
    for child_container_id,child_container_name in zip(child_container_list,child_container_name_list):
        format_list.append("| {0} | [{1}]({2}/mission/{0}) |\n".format(child_container_id, child_container_name, phantom.get_base_url()))
    # Fetch any previous merge note
    params = {'_filter_container': '"{}"'.format(container['id']), '_filter_title': '"[Auto-Generated] Child Containers"'}
    note_url = phantom.build_phantom_rest_url('note')
    response_data = phantom.requests.get(note_url, params=params, verify=False).json()
    # If an old note was found, proceed to overwrite it
    if response_data['count'] > 0:
        note_item = response_data['data'][0]
        note_content = note_item['content']
        # Append new information to existing note
        for c_note in format_list:
            note_content += c_note
        data = {"note_type": "general",
                "title": note_title,
                "content": note_content,
                "note_format": note_format}
        # Overwrite note
        response_data = phantom.requests.post(note_url + "/{}".format(note_item['id']), json=data, verify=False).json()
    # If no old note was found, add new with header               
    else:
        template = "| Container ID | Container Name |\n| --- | --- |\n"
        for c_note in format_list:
            template += c_note
        success, message, process_container_merge__note_id = phantom.add_note(container=container, 
                                                                              note_type="general", 
                                                                              title=note_title, 
                                                                              content=template, 
                                                                              note_format=note_format)
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
