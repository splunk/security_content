def regex_extract_email(input_string=None, **kwargs):
    """
    Provide a string with one or more email addresses in it to be extracted.
    Can be helpful with strings from the To or CC fields of an email: "<other_email@domain.com>, 'Name' <e-mail@domain.com>"
    
    Args:
        input_string (CEF type: *): String containing email addresses
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.email_address (CEF type: email): Parsed email addresses
        *.domain (CEF type: domain): Domain names of the parsed email addresses (everything after the "@")
    """
    ############################ Custom Code Goes Below This Line #################################

    if not input_string:
        raise ValueError('Missing input_string to process.')

    import re
    import json
    import phantom.rules as phantom
    
    outputs = []

    email_regex = r'[a-z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}'

    for email in re.findall(email_regex, input_string, re.IGNORECASE):
        phantom.debug('found email address: {}'.format(email))
        outputs.append({
            'email_address': email,
            'domain': email.split('@')[-1]}
        )

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
