# coding=utf-8
#
# Copyright © 2011-2015 Splunk, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

""" Sets the packages path and optionally starts the Python remote debugging client.
The Python remote debugging client depends on the settings of the variables defined in _pydebug_conf.py.  Set these
variables in _pydebug_conf.py to enable/disable debugging using either the JetBrains PyCharm or Eclipse PyDev remote
debug egg which must be copied to your application's bin directory and renamed as _pydebug.egg.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

settrace = stoptrace = lambda: NotImplemented
remote_debugging = None


def initialize():

    from os import path
    from sys import modules, path as python_path

    import platform

    module_dir = path.dirname(path.realpath(__file__))
    system = platform.system()

    for packages in path.join(module_dir, 'packages'), path.join(path.join(module_dir, 'packages', system)):
        if not path.isdir(packages):
            break
        python_path.insert(0, path.join(packages))

    configuration_file = path.join(module_dir, '_pydebug_conf.py')

    if not path.exists(configuration_file):
        return

    debug_client = path.join(module_dir, '_pydebug.egg')

    if not path.exists(debug_client):
        return

    _remote_debugging = {
        'client_package_location': debug_client,
        'is_enabled': False,
        'host': None,
        'port': 5678,
        'suspend': True,
        'stderr_to_server': False,
        'stdout_to_server': False,
        'overwrite_prev_trace': False,
        'patch_multiprocessing': False,
        'trace_only_current_thread': False}

    exec(compile(open(configuration_file).read(), configuration_file, 'exec'), {'__builtins__': __builtins__}, _remote_debugging)
    python_path.insert(1, debug_client)

    from splunklib.searchcommands import splunklib_logger as logger
    import pydevd

    def _settrace():
        host, port = _remote_debugging['host'], _remote_debugging['port']
        logger.debug('Connecting to Python debug server at %s:%d', host, port)

        try:
            pydevd.settrace(
                host=host,
                port=port,
                suspend=_remote_debugging['suspend'],
                stderrToServer=_remote_debugging['stderr_to_server'],
                stdoutToServer=_remote_debugging['stdout_to_server'],
                overwrite_prev_trace=_remote_debugging['overwrite_prev_trace'],
                patch_multiprocessing=_remote_debugging['patch_multiprocessing'],
                trace_only_current_thread=_remote_debugging['trace_only_current_thread'])
        except SystemExit as error:
            logger.error('Failed to connect to Python debug server at %s:%d: %s', host, port, error)
        else:
            logger.debug('Connected to Python debug server at %s:%d', host, port)

    global remote_debugging
    remote_debugging = _remote_debugging

    global settrace
    settrace = _settrace

    global stoptrace
    stoptrace = pydevd.stoptrace

    remote_debugging_is_enabled = _remote_debugging['is_enabled']

    if isinstance(remote_debugging_is_enabled, (list, set, tuple)):
        app_name = path.splitext(path.basename(modules['__main__'].__file__))[0]
        remote_debugging_is_enabled = app_name in remote_debugging_is_enabled

    if remote_debugging_is_enabled is True:
        settrace()

    return

initialize()
del initialize