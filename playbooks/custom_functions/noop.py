def noop(**kwargs):
    """
    Do nothing and return nothing. Use this if you want to do something in a custom function setup section or leave a placeholder block in a playbook. This does not sleep or wait and will return as soon as possible.
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
        
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
