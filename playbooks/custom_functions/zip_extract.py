def zip_extract(container=None, vault_id=None, password=None, **kwargs):
    """
    Extract all files recursively from a .zip archive. Add the extracted files to the vault and return the vault IDs of the extracted files. Provide a password if needed to decrypt.
    
    Args:
        container (CEF type: phantom container id): The container that extracted files will be added to. Should be a container ID or a container dictionary.
        vault_id: The vault ID of the zip archive to be unzipped.
        password: The password to use for decryption of the zip archive if necessary.
    
    Returns a JSON-serializable object that implements the configured data paths:
        zip_file_info.name: File name of the zip file in the vault
        zip_file_info.user: User who added the zip file to the vault
        output_files.*.file_name: The names of the files extracted from the zip archive.
        output_files.*.file_path: The file paths of the files extracted from the zip archive.
        output_files.*.vault_id: The vault IDs of the files extracted from the zip archive.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom

    import os
    from pathlib import Path
    import zipfile
    
    outputs = {'output_files': []}

    # Ensure valid container input
    if isinstance(container, dict) and container.get('id'):
        container_id = container['id']
    elif isinstance(container, int):
        container_id = container
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor an int, so it cannot be used")
    
    # check the vault_id input
    success, message, info = phantom.vault_info(
        vault_id=vault_id,
        container_id=container_id
    )
    if not success:
        raise ValueError("Could not find file in vault")
    outputs['zip_file_info'] = info[0]

    if password and not isinstance(password, str):
        raise TypeError("password must be a string")

    # create a directory to store the extracted files before adding to the vault
    extract_path = Path("/opt/phantom/vault/tmp/") / vault_id
    extract_path.mkdir(parents=True, exist_ok=True)

    # extract the files with ZipFile
    with zipfile.ZipFile(info[0]["path"]) as f_zip:
        if password:
            f_zip.extractall(str(extract_path), pwd=password.encode())
        else:
            f_zip.extractall(str(extract_path))

    # add each extracted file to the vault and the output
    for p in extract_path.rglob("*"):
        if p.is_file():
            success, message, vault_id = phantom.vault_add(container=container_id, file_location=str(p), file_name=p.name)
            if not success:
                raise RuntimeError('failed to add file to vault with path {}'.format(str(p)))
            outputs['output_files'].append({'file_path': str(p), 'file_name': p.name, 'vault_id': vault_id})
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
