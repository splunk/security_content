def json_safe_format(json_input=None, **kwargs):
    """
    Load JSON string in a non-strict mode to allow unescaped control characters to be correctly escaped before passing them on to actions that require it.
    
    Args:
        json_input: String in JSON format with possible unescaped control characters.
    
    Returns a JSON-serializable object that implements the configured data paths:
        json_output: JSON-serializable string with correctly escaped control characters.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    safe_json = json.dumps(json.loads(json_input, strict=False))
        
    outputs['json_output'] = safe_json
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
