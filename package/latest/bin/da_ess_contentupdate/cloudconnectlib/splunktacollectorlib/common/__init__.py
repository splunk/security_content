import json
import hashlib


def load_schema_file(schema_file):
    """
    Load schema file.
    """

    with open(schema_file) as f:
        ret = json.load(f)

    common = ret.get("_common_", dict())
    if common:
        for k, v in ret.items():
            if k == "_common_" or not isinstance(v, dict):
                continue
            # merge common into other values
            for _k, _v in common.items():
                if _k not in v:
                    v[_k] = _v
            ret[k] = v

    return ret


def md5_of_dict(data):
    """
    MD5 of dict data.
    """

    md5 = hashlib.sha256()
    if isinstance(data, dict):
        for key in sorted(data.keys()):
            md5.update(repr(key))
            md5.update(md5_of_dict(data[key]))
    elif isinstance(data, list):
        for item in sorted(data):
            md5.update(md5_of_dict(item))
    else:
        md5.update(repr(data))

    return md5.hexdigest()


class UCCException(Exception):
    """
    Dispatch engine exception.
    """

    pass

