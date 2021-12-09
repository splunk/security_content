def custom_list_value_in_strings(custom_list=None, comparison_strings=None, **kwargs):
    """
    Iterates through all items of a custom list to see if any list value (i.e. "sample.com") exists in the input you are comparing it to (i.e "findme.sample.com"). Returns a list of matches, a list of misses, a count of matches, and a count of misses.
    
    Args:
        custom_list: Name of the custom list. Every string in this list will be compared to see if it is a substring of any of the comparison_strings
        comparison_strings (CEF type: *): String to use for comparison.
    
    Returns a JSON-serializable object that implements the configured data paths:
        matches.*.match (CEF type: *): List of all items from the list that are substrings of any of the comparison strings
        match_count: Number of matches
        misses.*.miss (CEF type: *): List of all items from the list that are not substrings of any of the comparison strings
        miss_count: Number of misses
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom

    # Get the custom list
    success, message, this_list = phantom.get_list(list_name=custom_list)

    # Create the lists to store matches and misses
    matches = []
    misses = []

    # Loop through each comparison string
    for comparison_string in comparison_strings:

        # Loop through the custom list to see if any list value is found in the comparison string
        for row in this_list:
            for cell in row:
                if comparison_string.find(cell) != -1:
                    matches.append({"match": cell})
                else:
                    misses.append({"miss": cell})

    # Prepare the outputs
    match_count = len(matches)
    miss_count = len(misses)
    outputs = {
        'matches': matches,
        'match_count': match_count,
        'misses': misses,
        'miss_count': miss_count,
    }

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs