import os
import requests


def download_file_from_http(url:str, destination_file:str, overwrite_file:bool=False, chunk_size:int=1024*1024, verbose_print:bool=False)->None:
    if os.path.exists(destination_file) and overwrite_file is False:
        print(f"[{destination_file}] already exists...using cached version")
        return
    if verbose_print:
        print(f"downloading to [{destination_file}]...",end="")
    try:
        file_to_download = requests.get(url, stream=True)
        if file_to_download.status_code != 200:
            if verbose_print:
                print("FAILED")
            raise Exception(f"Error downloading the file {url}: Status Code {file_to_download.status_code}")
        with open(destination_file, "wb") as output:
            for piece in file_to_download.iter_content(chunk_size=chunk_size):
                output.write(piece)
        if verbose_print:
            print("Done")
    except Exception as e:
        if verbose_print:
            print("FAILED")
        raise e