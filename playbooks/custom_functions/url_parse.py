def url_parse(input_url=None, **kwargs):
    """
    Separate a URL into its components using urlparse() from the urllib module of Python 3.
    
    Args:
        input_url (CEF type: url): The URL to parse
    
    Returns a JSON-serializable object that implements the configured data paths:
        scheme: The scheme of the URL, such as HTTP, HTTPS, or FTP.
        netloc (CEF type: domain): The network location of the URL, which is typically the hostname.
        path: The path to the resource after the first slash in the URL, such as "en_us/software/splunk-security-orchestration-and-automation.html".
        params: The parameters in the URL after the semicolon.
        query: The query string of the URL after the question mark. Multiple parameters are not separated from each other.
        fragment: The subcomponent of the resource which is identified after the hash sign.
        output_url (CEF type: url): Passthrough of the original url
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from urllib.parse import urlparse
    
    outputs = {}
    if input_url:
        parsed = urlparse(input_url)
        outputs = {'scheme': parsed.scheme, 'netloc': parsed.netloc, 'path': parsed.path, 'params': parsed.params, 'query': parsed.query, 'fragment': parsed.fragment, 'output_url': input_url}
                
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
