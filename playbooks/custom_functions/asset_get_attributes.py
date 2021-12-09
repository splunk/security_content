def asset_get_attributes(asset=None, **kwargs):
    """
    Allows the retrieval of an attribute from an asset configuration for access in a playbook. This can be valuable in instances such as a dynamic note that references the Asset hostname. Must provide asset name or id.
    
    Args:
        asset: Asset numeric ID or asset name.
    
    Returns a JSON-serializable object that implements the configured data paths:
        id: Unique asset id
        name: Unique asset name
        configuration: Access individual configuration attributes by appending ".<keyname>"
            Example: configuration.device
        tags: Asset tags
        description: Asset description
        product_name: Asset product_name
        product_vendor: Asset product_vendor
        product_version: Asset product_version
        type: Asset type
        version: Asset version
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    url = phantom.build_phantom_rest_url('asset') 
    
    if isinstance(asset, int):
        url += '/{}'.format(asset)
        
    # Attempt to translate asset_name to asset_id
    elif isinstance(asset, str):
        params = {'_filter_name': '"{}"'.format(asset)}
        response = phantom.requests.get(uri=url, params=params, verify=False).json()
        if response['count'] == 1:
            url += '/{}'.format(response['data'][0]['id'])
        else:
            raise RuntimeError("No valid asset id found for provided asset name: {}".format(asset))
    else:
        raise TypeError("No valid asset id or name provided.")
        
    response = phantom.requests.get(uri=url, verify=False).json()
    if response.get('id'):
        outputs = response
    else:
        raise RuntimeError("No valid asset id found.")
        
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
