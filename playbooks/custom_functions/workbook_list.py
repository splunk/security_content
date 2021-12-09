def workbook_list(**kwargs):
    """
    Return a list of all the workbooks on this Phantom instance. This might be useful to display possible options for workbooks to add to this event.
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.id: Unique workbook ID
        *.name: Workbook name
        *.description: Workbook description
        *.status: Status of the workbook, e.g. published
        *.is_default: True or False if it is the default workbook
        *.is_note_required: True or False if a note is required to finish each task in the workbook
        *.creator: Unique ID of the user that created the workbook
        *.create_time: Timestamp when the workbook was created
        *.modified_time: Timestamp when the workbook was last modified
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    url = phantom.build_phantom_rest_url('workbook_template') + '?page_size=0'
    phantom.debug(f"Querying for workbooks using URL: '{url}'")
    
    response = phantom.requests.get(uri=url, verify=False).json()
    if response and response['count'] > 0:
        for data in response['data']:
            outputs.append({"id": data['id'],
                            "name": data['name'],
                            "description": data['description'],
                            "status": data['status'],
                            "is_default": data['is_default'],
                            "is_note_required": data['is_note_required'],
                            "creator": data['creator'],
                            "create_time": data['create_time'],
                            "modified_time": data['modified_time']})
    else:
        raise RuntimeError(f"Error getting workbook data: {response}") 
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
