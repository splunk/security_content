def list_deduplicate(input_list=None, **kwargs):
    """
    Remove non-unique items from a list.
    
    Args:
        input_list (CEF type: *): A list of items to deduplicate
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.item (CEF type: *): A deduplicated list with all the unique items in input_list
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    # this only works on lists, so print a warning and return None if the input is not a list    
    if not isinstance(input_list, list):
        phantom.debug("unable to deduplicate because the input is not a list")
        return
    
    # deduplicate the list by converting it to a set. this will fail if items are not hashable
    unique_set = set(input_list)
    
    # iterate through the unique items in the set and append each one as its own dictionary
    outputs = []
    for item in unique_set:
        outputs.append({"item": item})
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
