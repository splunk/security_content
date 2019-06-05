import os
import os.path as op
import platform
import sys

import __main__

from ..splunktacollectorlib.common import log as stulog


def get_main_file():
    """Return the running mod input file"""
    return __main__.__file__


def get_app_root_dir():
    """Return the root dir of app"""
    return op.dirname(op.dirname(op.abspath(get_main_file())))


def get_mod_input_script_name():
    """Return the name of running mod input"""
    script_name = os.path.basename(get_main_file())
    if script_name.lower().endswith('.py'):
        script_name = script_name[:-3]
    return script_name


def register_module(new_path):
    """ register_module(new_path): adds a directory to sys.path.
    Do nothing if it does not exist or if it's already in sys.path.
    """
    if not os.path.exists(new_path):
        return

    new_path = os.path.abspath(new_path)
    if platform.system() == 'Windows':
        new_path = new_path.lower()
    for x in sys.path:
        x = os.path.abspath(x)
        if platform.system() == 'Windows':
            x = x.lower()
        if new_path in (x, x + os.sep):
            return
    sys.path.insert(0, new_path)


def register_cacert_locater(cacerts_locater_path):
    for x in sys.modules:
        if (x == "httplib2" or x.endswith(".httplib2")) and sys.modules[x] \
                is not None:
            stulog.logger.warning("Httplib2 module '{}' is already installed. "
                                  "The ca_certs_locater may not work".format(x))
    register_module(cacerts_locater_path)
