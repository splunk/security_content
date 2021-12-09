def playbooks_list(name=None, category=None, tags=None, repo=None, playbook_type=None, **kwargs):
    """
    List all playbooks matching the provided name, category, and tags. If no filters are provided, list all playbooks.
    
    Args:
        name: Only return playbooks with the provided name.
        category: Only returns playbooks that match the provided category.
        tags: Only return playbooks that contain ALL the provided tags. Multiple tags must be a comma-separated list.
        repo: Only return playbooks that exist in this repo.
        playbook_type: Only return playbooks that match the provided type. Accepts 'automation', 'input' or 'data.'
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.id: Playbook ID:
            e.g. 1234
        *.full_name: Playbook full name with repo, e.g.:
            local/playbook_name
        *.name: Playbook Name:
            e.g. My Playbook
        *.category: Playbook category:
            e.g. Uncategorized
        *.tags: List of tags:
            e.g. [ tag1, tag2, tag3 ]
        *.active: Playbook automation status:
            e.g. True or False
        *.disabled: Playbook enabled / disabled status:
            e.g. True or False
        *.playbook_type: Playbook type: 'automation' or 'data'
        *.input_spec: If the playbook type is 'data,' this will be a list of dictionaries for the accepted inputs.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    
    url = phantom.build_phantom_rest_url('playbook')
    params = {'pretty' : True, 'page_size': 0}
    
    # Add Name
    if name:
        params['_filter_name'] = f'"{name}"'
    # Add Category
    if category:
        params['_filter_category'] = f'"{category}"'
        
    # Create list of tags and add tags minus whitespace 
    if tags:
        tags = [item.replace(' ','') for item in tags.split(',')]
        params['_filter_tags__contains'] = f'{json.dumps(tags)}'
    
    # Add Repo
    if isinstance(repo, int):
        params['_filter_scm'] = f'{repo}'
    # Translate string to id
    elif isinstance(repo, str):
        scm_params = {'_filter_name': f'"{repo}"'}
        response = phantom.requests.get(uri=phantom.build_phantom_rest_url('scm'), params=scm_params, verify=False).json()
        if response['count'] == 1:
            params['_filter_scm'] = '{}'.format(response['data'][0]['id'])
        else:
            raise RuntimeError(f"Invalid repo specified: '{repo}'")       
    
    # Add type
    if isinstance(playbook_type, str) and playbook_type.lower() in ['automation', 'input', 'data']:
        # Alias 'input' to 'data'
        if playbook_type.lower() == 'input':
            playbook_type = 'data'
        playbook_type = playbook_type.lower()
    elif playbook_type:
        raise TypeError(f"Invalid playbook type specified - '{playbook_type}' - must be one of: 'automation', 'input', 'data'")
                     
    # Fetch playbook data
    response = phantom.requests.get(uri=url, params=params, verify=False).json()
    # If playbooks were found generate output
    if response['count'] > 0:
        for data in response['data']:
            
            valid_playbook = False
            # SOAR < 5.0 does not have playbook_type so providing a playbook type will raise an error
            if not data.get('playbook_type') and playbook_type:
                raise TypeError("playbook_type filter not valid on SOAR prior to 5.0")
            # If no playbook type exists user does not want to filter on playbook types
            elif not playbook_type:
                valid_playbook = True
            # If user provided a playbook type then only output playbooks that match that provided type
            elif data.get('playbook_type') == playbook_type:
                valid_playbook = True
                
            if valid_playbook:
                outputs.append({'id': data['id'],
                                'full_name': f"{data['_pretty_scm']}/{data['name']}",
                                'name': data['name'],
                                'category': data['category'],
                                'tags': data['tags'],
                                'active': data['active'],
                                'disabled': data['disabled'],
                                'playbook_type': data.get('playbook_type'),
                                'input_spec': data.get('input_spec')
                               })
    else:
        phantom.debug("No playbook found for supplied filter")
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
