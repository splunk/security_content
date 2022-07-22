import os

from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject

class Utils:

    @staticmethod
    def get_all_yml_files_from_directory(path: str) -> list:
        listOfFiles = list()
        for (dirpath, dirnames, filenames) in os.walk(path):
            for file in filenames:
                if file.endswith(".yml"):
                    listOfFiles.append(os.path.join(dirpath, file))
    
        return sorted(listOfFiles)

    @staticmethod
    def add_id(id_dict:dict[str, list[str]], obj:SecurityContentObject, path:str) -> None:     
        if hasattr(obj, "id"):
            obj_id = obj.id
            if obj_id in id_dict:
                id_dict[obj_id].append(path)
            else:
                id_dict[obj_id] = [path]
    # Otherwise, no ID so nothing to add....
     
    @staticmethod
    def check_ids_for_duplicates(id_dict:dict[str, list[str]])->bool:
        validation_error = False
        for key, values in id_dict.items():
            if len(values) > 1:
                validation_error = True
                id_conflicts_string = '\n\t* '.join(values)
                print(f"\nError validating id [{key}] - duplicate ID is used for the following content: \n\t* {id_conflicts_string}")
        return validation_error