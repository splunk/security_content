def workbook_task_update(task_name=None, note_title=None, note_content=None, status=None, owner=None, container=None, **kwargs):
    """
    Update a workbook task by task name or the task where the currently running playbook appears. Requires a task_name, container_id, and a note_title, note_content, owner, or status.
    
    Args:
        task_name (CEF type: *): Name of a workbook task or keyword 'playbook' to update the task where the currently running playbook appears. (Required)
        note_title (CEF type: *): Note title. (Optional)
        note_content (CEF type: *): Note content. (Optional)
        status (CEF type: *): Accepts 'incomplete', 'in_progress, or 'complete'. (Optional)
        owner (CEF type: *): A user to assign as the task owner or keyword 'current" to assign the task to the user that launched the playbook. (Optional)
        container (CEF type: phantom container id): The ID of a SOAR Container. (Required)
    
    Returns a JSON-serializable object that implements the configured data paths:
        note_id: Returns note_id if a note was added. A closing note on a required task note will not produce a note_id.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    closing_note = False # special variable to keep track of if this note should be treated as a closing note
    
    # Ensure valid container input
    if isinstance(container, dict) and container.get('id'):
        container_id = container['id']
    elif isinstance(container, int):
        container_id = container
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor an int, so it cannot be used")
    
    if not any([note_title, note_content, owner, status]):
        raise RuntimeError("Workbook task update requires a note_title, note_content, owner, or status.")
    
    task_id = None
    if task_name:
        task_list = phantom.get_tasks(container_id)
        task_count = 0
        current_playbook = ""
        
        if task_name == 'playbook':
            current_playbook = (phantom.get_playbook_info()[0]['repo_name'], phantom.get_playbook_info()[0]['name'])
            
        for task in task_list:
            if task['success'] and task.get('data'):
                task_data = task['data']
                match = False
                if task_name == 'playbook':
                    playbooks = task_data['suggestions'].get('playbooks', [])
                    for playbook in playbooks:
                        if playbook['scm'] == current_playbook[0] and playbook['playbook'] == current_playbook[1]:
                            match = True
                            task_count += 1
                elif task_name == task_data['name']:
                    match = True
                    task_count += 1

                if match == True:
                    task_id = task_data['id']
                    task_is_note_required = task_data['is_note_required']
                    task_status = task_data['status']
                    task_notes = task_data['notes']
                    task_owner = task_data['owner']
                    if task_is_note_required and status == 'complete' and task_status != 1:
                        closing_note = True
                
    elif not task_name:
        raise RuntimeError("Missing input for task_name.")
    
    if task_count > 1:
        raise RuntimeError(f"'Unable to update workbook task. {task_count} match criteria '{task_name}'")
    elif task_count == 0:
        if task_name == "playbook" and current_playbook:
            raise RuntimeError(f"No task contains the current playbook: '{current_playbook}'")
        else:
            raise RuntimeError(f"No task name matches input task_name: '{task_name}'")

    if task_is_note_required and not note_content and status == 'complete' and task_status != 1:
        raise RuntimeError('Unable to update workbook task - The task requires a closing note and a closing title')     

    # Use add note if this is not a closing note otherwise add note during status change.
    if note_content and not closing_note:
        _, _, note_id = phantom.add_note(
            container=container_id, 
            note_type='task',
            task_id=task_id, 
            title=note_title if note_title else "", 
            content=note_content,
            note_format='markdown'
        )
        outputs['note_id'] = str(note_id)

    # Set owner
    if owner:
        owner_dict = {}
        # If keyword 'current' entered then translate effective_user id to a username
        if owner.lower() == 'current':
            owner_dict['owner_id'] = phantom.get_effective_user()
        else:
            # Attempt to translate name to owner_id
            url = phantom.build_phantom_rest_url('ph_user') + f'?_filter_username="{owner}"'
            data = phantom.requests.get(url, verify=False).json().get('data')
            if data and len(data) == 1:
                owner_dict['owner_id'] = data[0]['id']
            elif data and len(data) > 1:
                raise RuntimeError(f'Multiple matches for owner "{owner}"')
            else:
                # Attempt to translate name to role_id
                url = phantom.build_phantom_rest_url('role') + f'?_filter_name="{owner}"'
                data = phantom.requests.get(url, verify=False).json().get('data')
                if data and len(data) == 1:
                    owner_dict['role_id'] = data[0]['id']
                elif data and len(data) > 1:
                    raise RuntimeError(f'Multiple matches for owner "{owner}"')
                else:
                    raise RuntimeError(f'"{owner}" is not a valid username or role')

        url = phantom.build_phantom_rest_url('workbook_task') + '/{}'.format(task_id)
        response = phantom.requests.post(url, data=json.dumps(owner_dict), verify=False).json()             
        if not response.get('success'):
            raise RuntimeError(f'Error setting "{owner}" - {response}')

    # Set Status
    if isinstance(status, str):
        status = status.lower()
        url = phantom.build_phantom_rest_url('workbook_task') + '/{}'.format(task_id)
        if status == 'complete' and task_status == 0:
            # Move to in progress
            data = {'status': 2}
            response = phantom.requests.post(url, data=json.dumps(data), verify=False).json()
            if not response.get('success'):
                raise RuntimeError(f'Error setting status "{status}" - {response}')
                # Then move to close
            data = {'status': 1}
            if task_is_note_required and note_content:
                data['note'] = note_content
                data['title'] = note_title if note_title else ""
                data['note_format'] = 'markdown'
            response = phantom.requests.post(url, data=json.dumps(data), verify=False).json()
            if not response.get('success'):
                raise RuntimeError(f'Error setting status "{status}" - {response}')
        elif (status == 'in progress' or status == 'in_progress') and task_status != 2:
            data = {'status': 2}
            # Move to in progress
            response = phantom.requests.post(url, data=json.dumps(data), verify=False).json()
            if not response.get('success'):
                raise RuntimeError(f'Error setting status "{status}" - {response}')
        elif status == 'incomplete' and task_status != 0:
            data = {'status': 0}
            # Move to incomplete
            response = phantom.requests.post(url, data=json.dumps(data), verify=False).json()
            if not response.get('success'):
                raise RuntimeError(f'Error setting status "{status}" - {response}')
        elif status == 'complete' and task_status != 1:
            data = {'status': 1}
            # Move to complete
            if task_is_note_required and note_content:
                data['note'] = note_content
                data['title'] = note_title if note_title else ""
                data['note_format'] = 'markdown'
            response = phantom.requests.post(url, data=json.dumps(data), verify=False).json()
            if not response.get('success'):
                raise RuntimeError(f'Error setting status "{status}" - {response}')

        
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
