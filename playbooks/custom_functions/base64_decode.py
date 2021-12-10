def base64_decode(input_string=None, split_input=None, delimiter=None, **kwargs):
    """
    Decode one or more strings encoded with base64. The input can be a single chunk of base64 or a list of strings separated by a delimiter.
    
    Args:
        input_string (CEF type: *): Y2FsYy5leGU=
        split_input: Defaults to False. If True, use the delimiter to split the input string and decode each of the components separately if it is base64.
        delimiter: The character to use as a delimiter if split_input is True. Defaults to a comma. The special option "space" can be used to split on a single space character (" ").
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.input_string (CEF type: *): Base64 string before being decoded
        *.output_string (CEF type: *): Resulting string after decoding from base64
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import base64

    if not input_string or not isinstance(input_string, str):
        raise ValueError('input_string must be a string')

    def isBase64(sb):
        try:
            if isinstance(sb, str):
                # If there's any unicode here, an exception will be thrown and the function will return false
                sb_bytes = bytes(sb, 'ascii')
            elif isinstance(sb, bytes):
                sb_bytes = sb
            else:
                raise ValueError("Argument must be string or bytes")
            return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
        except Exception:
            return False
    
    outputs = []
    
    # split_input defaults to false
    if split_input == True or (isinstance(split_input, str) and split_input.lower() == 'true'):
        split_input = True
    else:
        split_input = False
        
    # create the list of inputs, whether it be the single input or a delimiter-separated list
    if not split_input:
        input_list = [input_string]
    else:
        if not isinstance(delimiter, str):
            delimiter = ','
        if delimiter == 'space':
            delimiter = ' '
        input_list = input_string.split(delimiter)
    
    # now that input_list is set up, perform the base64 decode on each item that is valid base64
    for index, value in enumerate(input_list):         
        if isBase64(value):
            try:
                value_bytes = value.encode('ascii')
                data = base64.b64decode(value_bytes, validate=True)
                if data:
                    outputs.append({'input_string': value, 'output_string': data.decode('ascii').replace('\x00','')})

            except Exception as e:
                phantom.error(f'Unable to decode string: {e}')

    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
