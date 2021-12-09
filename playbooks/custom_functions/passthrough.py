def passthrough(input_1=None, input_2=None, input_3=None, input_4=None, input_5=None, input_6=None, input_7=None, input_8=None, input_9=None, input_10=None, **kwargs):
    """
    Return the inputs as outputs. This is useful for publishing pieces of data for other blocks in the playbook to use.
    
    Args:
        input_1 (CEF type: *)
        input_2 (CEF type: *)
        input_3 (CEF type: *)
        input_4 (CEF type: *)
        input_5 (CEF type: *)
        input_6 (CEF type: *)
        input_7 (CEF type: *)
        input_8 (CEF type: *)
        input_9 (CEF type: *)
        input_10 (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.item (CEF type: *): The output item for each input
        *.input_name: The corresponding input name for each output
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    for index, input_value in enumerate([input_1, input_2, input_3, input_4, input_5, input_6, input_7, input_8, input_9, input_10]):
        if input_value:
            if isinstance(input_value, list):
                for input_item in input_value:
                    this_output = {}
                    this_output['item'] = input_item
                    this_output['input_name'] = "input_{}".format(index+1) 
                    outputs.append(this_output)
                
            else:
                this_output = {}
                this_output['item'] = input_value
                this_output['input_name'] = "input_{}".format(index+1) 
                outputs.append(this_output)

    phantom.debug('outputs of passthrough:\n{}'.format(outputs))

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
