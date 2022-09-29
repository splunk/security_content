import os
import pathlib
from typing import Tuple
from pydantic import ValidationError

from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject

class Utils:

    @staticmethod
    def get_all_yml_files_from_directory(path: str) -> list[pathlib.Path]:
        listOfFiles:list[pathlib.Path] = []
        for (dirpath, dirnames, filenames) in os.walk(path):
            for file in filenames:
                if file.endswith(".yml"):
                    listOfFiles.append(pathlib.Path(os.path.join(dirpath, file)))
    
        return sorted(listOfFiles)
        

    @staticmethod
    def add_id(id_dict:dict[str, list[pathlib.Path]], obj:SecurityContentObject, path:pathlib.Path) -> None:     
        if hasattr(obj, "id"):
            obj_id = obj.id
            if obj_id in id_dict:
                id_dict[obj_id].append(path)
            else:
                id_dict[obj_id] = [path]
    # Otherwise, no ID so nothing to add....
     
    @staticmethod
    def check_ids_for_duplicates(id_dict:dict[str, list[pathlib.Path]])->list[Tuple[pathlib.Path,  ValidationError]]:
        validation_errors:list[Tuple[pathlib.Path,  ValidationError]] = []

        for key, values in id_dict.items():
            if len(values) > 1:
                error_file_path = pathlib.Path("MULTIPLE")
                all_files = '\n\t'.join(str(pathlib.Path(p)) for p in values)
                exception = ValueError(f"Error validating id [{key}] - duplicate ID was used in the following files: \n\t{all_files}")
                validation_errors.append((error_file_path, exception))
                
        return validation_errors