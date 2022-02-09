def debug(input_1=None, input_2=None, input_3=None, input_4=None, input_5=None, input_6=None, input_7=None, input_8=None, input_9=None, input_10=None, **kwargs):
    """
    Print debug messages with the type and value of 0-10 different inputs. This is useful for checking the values of input data or the outputs of other playbook blocks.
    
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
        *.input_name: The variable name used for this input, such as input_1 or input_7
        *.value (CEF type: *): The string representation of the value of this input
        *.types: The string representation of the type of this input, such as "<type 'list'>"
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    output = []
    for index, input_value in enumerate([input_1, input_2, input_3, input_4, input_5, input_6, input_7, input_8, input_9, input_10]):
        this_output = {}
        phantom.debug("input_{}:".format(index+1))
        this_output['input_name'] = "input_{}".format(index+1)        
        phantom.debug("    value: " + str(input_value))
        this_output['value'] = str(input_value)
        if isinstance(input_value, list):
            list_item_types = str([type(list_item) for list_item in input_value])
            phantom.debug("    types:  " + list_item_types)
            this_output['types'] = list_item_types
        output.append(this_output)
	
    assert json.dumps(output)  # Will raise an exception if the :outputs: object is not JSON-serializable    
    return output
