def string_to_lowercase(input_string=None, **kwargs):
    """
    Convert the provided string to all lowercase characters
    
    Args:
        input_string (CEF type: *): The string to convert to lowercase
    
    Returns a JSON-serializable object that implements the configured data paths:
        lowercase_string (CEF type: *): The lowercase string after conversion
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    try:
        lowercase_string = input_string.lower()
    except AttributeError:
        raise ValueError('input_string must be a string or unicode')
    
    outputs = {"lowercase_string": lowercase_string}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
