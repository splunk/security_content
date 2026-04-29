def regex_split(input_string=None, regex=None, strip_whitespace=None, **kwargs):
    """
    Use a regular expression to split an input_string into multiple items.
    
    Args:
        input_string (CEF type: *): The input string to split.
        regex: The regular expression to use to split the string. Reserved regular expression characters should be escaped with a backslash, so '\.' will match '.' and '\\\\' will match '\'.
        strip_whitespace: Either True or False to indicate whether or not to remove whitespace before and after each item. Defaults to True
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.item (CEF type: *): A list of items created by splitting the input string.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    
    outputs = []
    
    # strip_whitespace defaults to True
    if strip_whitespace:
        if isinstance(strip_whitespace, str):
            if strip_whitespace.lower() == 'true':
                strip_whitespace = True
            elif strip_whitespace.lower() == 'false':
                strip_whitespace = False
            else:
                raise ValueError("If strip_whitespace is a string, it must be a string of true or false.")
        elif not isinstance(strip_whitespace, bool):
            raise TypeError("strip_whitespace must be a string or bool")
    else:
        strip_whitespace = True
    
    regex = regex.replace('\\\\','\\')
    results = re.split(regex, input_string)
    
    if strip_whitespace:
        results = [result.strip() for result in results]

    phantom.debug("the input string {} was split into {}".format(input_string, results))

    for result in results:
        outputs.append({'item': result})
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
