from __future__ import absolute_import

import os.path

from .error import RestError


__all__ = [
    'get_base_app_name',
    'remove_http_proxy_env_vars',
]


def get_base_app_name():
    """
    Base App name, which this script belongs to.
    """
    import __main__
    main_name = __main__.__file__
    absolute_path = os.path.normpath(main_name)
    parts = absolute_path.split(os.path.sep)
    parts.reverse()
    for key in ("apps", "slave-apps", "master-apps"):
        try:
            idx = parts.index(key)
            if parts[idx + 1] == "etc":
                return parts[idx - 1]
        except (ValueError, IndexError):
            pass
    raise RestError(
        status=500,
        message='Cannot get app name from file: %s' % main_name
    )


def remove_http_proxy_env_vars():
    for k in ("http_proxy", "https_proxy"):
        if k in os.environ:
            del os.environ[k]
        elif k.upper() in os.environ:
            del os.environ[k.upper()]
