def regex_extract_ipv4(input_string=None, **kwargs):
    """
    Takes a single input and extracts all IPv4 addresses from it using regex.
    
    Args:
        input_string (CEF type: *): An input string that may contain an arbitrary number of ipv4 addresses
    
    Returns a JSON-serializable object that implements the configured data paths:
        extracted_ipv4 (CEF type: ip): Extracted ipv4 address. Will be none if no IP was extracted.
        input_value: The value that was used as input to produce the extracted IP.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    
    outputs = []
    ip_list = []
    if input_string:
        ip_rex = re.findall('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', input_string)
        for ip in set(ip_rex):
            ip_list.append(ip)
    if ip_list:
        for ip in set(ip_list):
            outputs.append({"extracted_ipv4": ip, "input_value": input_string})
    else:
        outputs.append({"extracted_ipv4": None, "input_value": input_string})

    phantom.debug("Extracted ips: {}".format(outputs))
    
    # Return a JSON-serializable object
    assert isinstance(outputs, list)  # Will raise an exception if the :outputs: object is not a list
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
