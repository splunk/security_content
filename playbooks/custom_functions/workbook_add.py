def workbook_add(container=None, workbook=None, check_for_existing_workbook=None, start_workbook=None, **kwargs):
    """
    Add a workbook to a container. Provide a container id and a workbook name or id
    
    Args:
        container (CEF type: phantom container id): A phantom container id
        workbook (CEF type: *): A workbook name or id
        check_for_existing_workbook: Defaults to True. Check to see if workbook already exists in container before adding.
        start_workbook: Defaults to True. Sets the added workbook to the current phase.
    
    Returns a JSON-serializable object that implements the configured data paths:
        workbook_id: ID of the workbook that was added
        current_phase_id: ID of the current phase if start_workbook set to True.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    existing_templates = []
    container_id = None
    
    # Ensure valid container input
    if isinstance(container, dict) and container.get('id'):
        container_id = container['id']
    elif isinstance(container, int):
        container_id = container
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor an int, so it cannot be used")
    
    # Determine if check_for_existing_workbook should be overwritten by function input
    if isinstance(check_for_existing_workbook, str) and check_for_existing_workbook.lower() == 'false':
        check_for_existing_workbook = False
    else:
        check_for_existing_workbook = True
        
    # Determine if start_workbook should be overwritten by function input
    if isinstance(start_workbook, str) and start_workbook.lower() == 'false':
        start_workbook = False
    else:
        start_workbook = True
        
    if check_for_existing_workbook:
        #phantom.debug('Checking for existing workbook')
        url = phantom.build_phantom_rest_url('container', container_id, 'phases')
        container_data = phantom.requests.get(url, verify=False).json()
        if container_data['count'] > 0:
            phase_names = set([phase_id['name'] for phase_id in container_data['data']])
            existing_templates = []
            for name in phase_names:
                url = phantom.build_phantom_rest_url('workbook_phase_template') + '?_filter_name="{}"'.format(name)
                phase_template_response = phantom.requests.get(url, verify=False).json()
                if phase_template_response['count'] > 0:
                    for phase in phase_template_response['data']:
                        existing_templates.append(phase['template'])
            existing_templates = set(existing_templates)
            
    if isinstance(workbook,int):
        workbook_id = workbook
        if workbook_id in existing_templates:
                phantom.debug("Workbook already added to container. Skipping")
        else:
            phantom.add_workbook(container=container_id, workbook_id=workbook_id)
            
        
    elif isinstance(workbook, str):
        url = phantom.build_phantom_rest_url('workbook_template') + '?_filter_name="{}"'.format(workbook)
        response = phantom.requests.get(url, verify=False).json()
        if response['count'] > 1:
            raise RuntimeError('Unable to add workbook - more than one ID matches workbook name')
        elif response['data'][0]['id']:
            workbook_id = response['data'][0]['id']
            
            if workbook_id in existing_templates:
                phantom.debug("Workbook already added to container. Skipping")
            else:
                phantom.add_workbook(container=container_id, workbook_id=workbook_id)
    
    outputs['workbook_id'] = workbook_id
    
    if start_workbook:
        url = phantom.build_phantom_rest_url('workbook_phase_template') + '?_filter_template="{}"'.format(workbook_id)
        first_phase = phantom.requests.get(url, verify=False).json()['data'][0]['name']
        url = phantom.build_phantom_rest_url('container', container_id, 'phases') + '?_filter_name="{}"'.format(first_phase)
        existing_phases = phantom.requests.get(url, verify=False).json()
        if existing_phases['count'] > 1:
            raise RuntimeError('Cannot set current phase - duplicate phase names exist in container')
        else:
            phantom.set_phase(container=container_id, phase=existing_phases['data'][0]['id'], trace=False)
            outputs['current_phase_id'] = existing_phases['data'][0]['id']
            
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs

