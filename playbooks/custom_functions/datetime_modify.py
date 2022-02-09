def datetime_modify(input_datetime=None, input_format_string=None, modification_unit=None, amount_to_modify=None, output_format_string=None, **kwargs):
    """
    Change a timestamp by adding or subtracting minutes, hours, or days.
    
    Args:
        input_datetime: The datetime to modify, which should be provided in a string format determined by input_format_string
        input_format_string: The format string to use for the input according to the Python's datetime.strptime() formatting rules. If none is provided the default will be '%Y-%m-%dT%H:%M:%S.%fZ'. In addition to strptime() formats, the special format "epoch" can be used to accept unix epoch timestamps.
        modification_unit: Choose a unit to modify the date by, which must be either seconds, minutes, hours, or days. If none is provided the default will be 'minutes'
        amount_to_modify: The number of seconds, minutes, hours, or days to add or subtract. Use a negative number such as -1.5 to subtract time. Defaults to zero.
        output_format_string: The format string to use for the output according to the Python's datetime.strftime() formatting rules. If none is provided the default will be '%Y-%m-%dT%H:%M:%S.%fZ'.
    
    Returns a JSON-serializable object that implements the configured data paths:
        datetime_string: The output datetime as formatted by the given output_format_string using Python's datetime.strftime()
        epoch_time: An integer representing the output time as a number of seconds since January 1 1970 assuming a naive UTC timezone. This is easier to use for comparisons to other epoch timestamps.
        seconds_modified: The number of seconds (positive or negative) by which the input was modified
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import datetime
    
    outputs = {}
    
    # set the input format string to the phantom default if none is provided
    if not input_format_string:
        input_format_string = "%Y-%m-%dT%H:%M:%S.%fZ"
    
    # set the date to the default, which is the current time if none is provided
    if not input_datetime:
        input_datetime = datetime.datetime.now().strftime(input_format_string)
    
    # use the phantom default as the output format string if none is provided
    if not output_format_string:
        output_format_string = "%Y-%m-%dT%H:%M:%S.%fZ"
    
    if input_format_string.lower() == 'epoch':
        parsed_input = datetime.datetime.utcfromtimestamp(int(input_datetime))
    else:
        parsed_input = datetime.datetime.strptime(input_datetime, input_format_string)
    phantom.debug("parsed the input datetime as: {}".format(parsed_input))
    
    # validate the modification_unit parameter, which must be a unit of time
    if modification_unit == None:
        modification_unit = 'minutes'
    if modification_unit not in ['seconds', 'minutes', 'hours', 'days']:
        raise ValueError('invalid modification_unit. must be either seconds, minutes, hours, or days.')
    
    # amount_to_modify defaults to zero
    if not amount_to_modify:
        amount_to_modify = 0
        
    # validate that amount_to_modify is an int or float (booleans will work as 0 or 1, but should not be used)
    if not isinstance(amount_to_modify, int) and not isinstance(amount_to_modify, float):
        raise ValueError('invalid amount_to_modify. must be an int or float')

    # convert all time units to seconds
    conversions = {
        "seconds": 1,
        "minutes": 60,
        "hours": 60*60,
        "days": 60*60*24
    }
    conversion_multiplier = conversions.get(modification_unit, None)
    if not conversion_multiplier:
        raise KeyError("failed to convert modification_unit to seconds")

    seconds_to_modify = amount_to_modify * conversion_multiplier
    if seconds_to_modify < 0:
        phantom.debug("subtracting {} {} which is {} seconds".format(amount_to_modify * -1, modification_unit, seconds_to_modify * -1))
    else:
        phantom.debug("adding {} {} which is {} seconds".format(amount_to_modify, modification_unit, seconds_to_modify))
    
    outputs['seconds_modified'] = seconds_to_modify
    seconds_to_modify = datetime.timedelta(seconds=seconds_to_modify)
    
    # do the actual modification
    phantom.debug("adding {} plus {}".format(parsed_input, seconds_to_modify))
    result_time = parsed_input + seconds_to_modify
    phantom.debug("the unformatted result is: {}".format(result_time))
    
    # use the provided output_format_string to turn the output into a string
    string_output = result_time.strftime(output_format_string)
    phantom.debug("the formatted result is: {}".format(string_output))
    outputs['datetime_string'] = string_output
    
    # also return an epoch time (seconds since Jan 1 1970) which assumes the input is a naive UTC datetime for time zone purposes
    epoch_time = (result_time - datetime.datetime.utcfromtimestamp(0)).total_seconds()
    outputs['epoch_time'] = epoch_time
        
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs