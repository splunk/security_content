def string_to_uppercase(input_string=None, **kwargs):
    """
    Convert the provided string to all uppercase characters.
    
    Args:
        input_string (CEF type: *): The string to convert to uppercase
    
    Returns a JSON-serializable object that implements the configured data paths:
        uppercase_string (CEF type: *): The string after converting to upper case
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    try:
        uppercase_string = input_string.upper()
    except AttributeError:
        raise ValueError('input_string must be a string or unicode')
    
    outputs = {"uppercase_string": uppercase_string}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
