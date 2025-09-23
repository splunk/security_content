def string_uri_decode(input_string=None, **kwargs):
    """
    Decodes a URI-encoded string to a plain text string.
    
    Args:
        input_string: The URI encoded string to decode
    
    Returns a JSON-serializable object that implements the configured data paths:
        decoded_string: The decoded, plain text string
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import urllib.parse
    import phantom.rules as phantom
    
    outputs = {}
    
    try:
        decoded_string = urllib.parse.unquote(input_string)
    except TypeError:
        raise ValueError('input_string must be a string or bytes')
        
    outputs = {"decoded_string": decoded_string}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
