def indicator_get_by_tag(tags_or=None, tags_and=None, indicator_timerange=None, container=None, tags_exclude=None, **kwargs):
    """
    Get indicator(s) by tags.
    
    Args:
        tags_or: Comma separated list of tags. Tags will be OR'd together: e.g. tag1 OR tag2 OR tag3. Tags do not support whitespace and whitespace will be automatically removed.
        tags_and: Comma separated list of tags. Tags will be AND'd together: e.g. tag1 AND tag2 AND tag3. Tags do not support whitespace and whitespace will be automatically removed.
        indicator_timerange: Defaults to last_30_days
            options:
            today
            yesterday
            this_week
            this_month
            last_7_days
            last_30_days
            last_week
            last_month
        container: Optional parameter to ensure the fetched indicator exists in the supplied container.
        tags_exclude: Comma separated list of tags to filter out. If the indicator's tags contain any of the values in this list, they will be omitted from the output.
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.indicator_id (CEF type: *): A matching indicator id record
        *.indicator_value (CEF type: *): A matching indicator value
        *.indicator_tags (CEF type: *): List of tags associated with the indicator record
        *.indicator_cef_type: List of cef types associated with the indicator record
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from datetime import datetime, timedelta
    
    outputs = []
    indicator_record = {}
    container_id = None
    allowed_timeranges = ['today', 'yesterday', 'this_week', 'this_month', 'this_year', 'last_7_days',
                          'last_30_days', 'last_week', 'last_month', 'last_year']
    
    # Helper function to translate timeranges to relative datetime.
    # Uses filter_earliest / filter_later for anything 30 days and under as it is quicker. 
    # Uses summary timeranges for items greater than 30 days.
    def translate_relative_input(relative_time):
        now = datetime.utcnow()
        relative_time = relative_time.lower()
        time_format = "%Y-%m-%dT%H:%M:%S.%fZ"
        if relative_time == 'today':
            earliest = now.replace(hour=0, minute=0, second=0, microsecond=0)
            params = {"_filter_earliest_time__gt": '"{}"'.format(earliest.strftime(time_format))}
        elif relative_time == 'yesterday':
            earliest = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
            latest = earliest.replace(hour=23, minute=59, second=59, microsecond=0)
            params = {"_filter_earliest_time__gt": '"{}"'.format(earliest.strftime(time_format)),
                     "_filter_latest_time__lt": '"{}"'.format(latest.strftime(time_format))}
        elif relative_time == 'this_week':
            earliest = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=now.weekday())
            params = {"_filter_earliest_time__gt": '"{}"'.format(earliest.strftime(time_format))}
        elif relative_time == 'this_month':
            earliest = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            params = {"_filter_earliest_time__gt": '"{}"'.format(earliest.strftime(time_format))}
        elif relative_time == 'last_7_days':
            earliest = now - timedelta(days=7)
            params = {"_filter_earliest_time__gt": '"{}"'.format(earliest.strftime(time_format))}
        elif relative_time == 'last_30_days':
            params = {}
        elif relative_time == 'last_week':
            latest = now.replace(hour=23, minute=59, second=59, microsecond=0) - timedelta(days=now.weekday() + 1)
            earliest = latest.replace(hour=0, minute=0, second=0) - timedelta(days=8)
            params = {"_filter_earliest_time__gt": '"{}"'.format(earliest.strftime(time_format)),
                     "_filter_latest_time__lt": '"{}"'.format(latest.strftime(time_format))}
        else:
            params = {'timerange': relative_time}
            
        return params
    
    if indicator_timerange and isinstance(indicator_timerange, str) and indicator_timerange.lower() in allowed_timeranges:
        time_params = translate_relative_input(indicator_timerange)
    elif not indicator_timerange:
        time_params = {}
    else:
        raise ValueError(f"invalid indicator_timerange: '{indicator_timerange}'")

        
    if isinstance(container, int):
        container_id = container
    elif isinstance(container, dict):
        container_id = container['id']
    elif container:
        raise TypeError("container_input is neither a int or a dictionary")  
        
    url = phantom.build_phantom_rest_url('indicator')
    if tags_or:
        tags_or = tags_or.replace(' ','')
        for tag in tags_or.split(','):
            params = {'_filter_tags__contains': f'"{tag}"', "_special_contains": True, 'page_size': 0, **time_params}
            response = phantom.requests.get(url, params=params, verify=False).json()
            if response['count'] > 0:
                for data in response['data']:
                    indicator_record[data['id']] = {'indicator_value': data['value'], 'indicator_tags': data['tags'], 'indicator_cef_type': data['_special_contains']}
    if tags_and:
        tags = tags_and.replace(' ','').split(',')
        params = {'_filter_tags__contains': f'{json.dumps(tags)}', "_special_contains": True, 'page_size': 0, **time_params}
        response = phantom.requests.get(url, params=params, verify=False).json()
        if response['count'] > 0:
            for data in response['data']:
                indicator_record[data['id']] = {'indicator_value': data['value'], 'indicator_tags': data['tags'], 'indicator_cef_type': data['_special_contains']}
                
    if tags_exclude:
        tags_exclude = [item.strip() for item in tags_exclude.split(',')]
        
    if indicator_record:
        for i_id, i_data in indicator_record.items():
            skip_indicator = False
            
            # Skip indicators that contain an excluded tag
            if tags_exclude:
                for item in tags_exclude:
                    if item in i_data['indicator_tags']:
                        skip_indicator = True
                    
            if container_id and not skip_indicator:
                url = phantom.build_phantom_rest_url('indicator_common_container')
                params = {'indicator_ids': i_id}
                response = phantom.requests.get(url, params=params, verify=False).json()
                if response:
                    for container_item in response:
                        # Only add to outputs if the supplied container_id shows in the common_container results
                        if container_item['container_id'] == container_id:
                            outputs.append({'indicator_id': i_id, **indicator_record[i_id]})
                else:
                    phantom.debug("No indicators found for provided tags and container")
                    
            elif not skip_indicator:
                
                outputs.append({'indicator_id': i_id, **indicator_record[i_id]})
    else:
        phantom.debug("No indicators found for provided tags")
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
