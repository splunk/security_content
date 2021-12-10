def string_split(input_string=None, delimiter=None, strip_whitespace=None, **kwargs):
    """
    Return a list of the components of input_string when split using the specified delimiter. If strip_whitespace is not specified or is "True", strip all whitespace from the beginning and end of each resulting component.
    
    Args:
        input_string (CEF type: *): The string to split
        delimiter: The delimiter to split by, which defaults to a comma
        strip_whitespace: Either True or False to indicate whether or not to remove whitespace before and after each item. Defaults to True
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.item (CEF type: *): One result for each output item
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    if not delimiter:
        delimiter = ","
    
    # strip_whitespace defaults to True, but if any value besides "True" is provided, it will be set to False
    if strip_whitespace == "True" or strip_whitespace == True or strip_whitespace == None:
        strip_whitespace = True
    else:
        strip_whitespace = False
    
    output_list = input_string.split(delimiter)
    
    outputs = []
    for item in output_list:
        if strip_whitespace:
            item = item.strip()
        outputs.append({"item": item})

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
