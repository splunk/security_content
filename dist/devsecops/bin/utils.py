import sys
import base64
from mimetypes import guess_type

IS_PYTHON_3 = sys.version_info > (3, 0)

def strip_uuid(filename):
    name = filename.split("__", 1)[0]
    file_extension = filename.rsplit('.', 1)[1]
    return '{}.{}'.format(name, file_extension)
