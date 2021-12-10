def regex_filter_list(input_list=None, regex=None, action=None, **kwargs):
    """
    Filter values in a list using a regex and either keep or drop values that match, depending on the action parameter.
    
    Args:
        input_list (CEF type: *): The list of items to filter using a regex
        regex: The regular expression to use to filter the list
        action: Either 'keep' or 'drop' to specify what to do with the items that match the regular expression. The default is 'keep'.
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.item (CEF type: *): List of output items
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re

    # this only works on lists, so print a warning and return None if the input is not a list
    if not isinstance(input_list, list):
        raise ValueError('input_list is not a list')

    action = action.lower()
    if action not in ('keep', 'drop'):
        raise ValueError("action is not 'keep' or 'drop'")

    # iterate through the items in the list and append each non-falsy one as its own dictionary
    outputs = []
    for item in input_list:
        if item:
            if re.match(str(regex), str(item)):
                if action == 'keep':
                    outputs.append({"item": item})
            else:
                if action == 'drop':
                    outputs.append({"item": item})
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
