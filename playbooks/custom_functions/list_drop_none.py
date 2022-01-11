def list_drop_none(input_list=None, **kwargs):
    """
    Filter out all values from a list where the value evaluates to False in Python (such as None, "", or [])
    
    Args:
        input_list (CEF type: *): a list of items to filter
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.item (CEF type: *): a return item for each value that did not evaluate to False
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    # this only works on lists, so print a warning and return None if the input is not a list
    if not isinstance(input_list, list):
        phantom.debug("unable to process because the input is not a list")
        return
    
    # iterate through the items in the list and append each non-falsy one as its own dictionary
    outputs = []
    for item in input_list:
        if item:
            outputs.append({"item": item})
        
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
