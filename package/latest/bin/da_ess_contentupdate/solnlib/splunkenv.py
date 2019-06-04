# Copyright 2016 Splunk, Inc.
#
# Licensed under the Apache License, Version 2.0 (the 'License'): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

'''
Splunk platform related utilities.
'''

import os
import os.path as op
import subprocess
import socket
from ConfigParser import ConfigParser
from cStringIO import StringIO

from . import utils

__all__ = ['make_splunkhome_path',
           'get_splunk_host_info',
           'get_splunk_bin',
           'get_splunkd_access_info',
           'get_splunkd_uri',
           'get_conf_key_value',
           'get_conf_stanza',
           'get_conf_stanzas']

ETC_LEAF = 'etc'

# See validateSearchHeadPooling() in src/libbundle/ConfSettings.cpp
on_shared_storage = [os.path.join(ETC_LEAF, 'apps'),
                     os.path.join(ETC_LEAF, 'users'),
                     os.path.join('var', 'run', 'splunk', 'dispatch'),
                     os.path.join('var', 'run', 'splunk', 'srtemp'),
                     os.path.join('var', 'run', 'splunk', 'rss'),
                     os.path.join('var', 'run', 'splunk', 'scheduler'),
                     os.path.join('var', 'run', 'splunk', 'lookup_tmp')]


def _splunk_home():
    return os.path.normpath(os.environ['SPLUNK_HOME'])


def _splunk_etc():
    try:
        result = os.environ['SPLUNK_ETC']
    except KeyError:
        result = op.join(_splunk_home(), ETC_LEAF)

    return os.path.normpath(result)


def _get_shared_storage():
    '''Get splunk shared storage name.

    :returns: Splunk shared storage name.
    :rtype: ``string``
    '''

    try:
        state = get_conf_key_value('server', 'pooling', 'state')
        storage = get_conf_key_value('server', 'pooling', 'storage')
    except KeyError:
        state = 'disabled'
        storage = None

    if state == 'enabled' and storage:
        return storage

    return None


# Verify path prefix and return true if both paths have drives
def _verify_path_prefix(path, start):
    path_drive = os.path.splitdrive(path)[0]
    start_drive = os.path.splitdrive(start)[0]
    return len(path_drive) == len(start_drive)


def make_splunkhome_path(parts):
    '''Construct absolute path by $SPLUNK_HOME and `parts`.

    Concatenate $SPLUNK_HOME and `parts` to an absolute path.
    For example, `parts` is ['etc', 'apps', 'Splunk_TA_test'],
    the return path will be $SPLUNK_HOME/etc/apps/Splunk_TA_test.
    Note: this function assumed SPLUNK_HOME is in environment varialbes.

    :param parts: Path parts.
    :type parts: ``list, tuple``
    :returns: Absolute path.
    :rtype: ``string``

    :raises ValueError: Escape from intended parent directories.
    '''

    relpath = os.path.normpath(os.path.join(*parts))

    basepath = None
    shared_storage = _get_shared_storage()
    if shared_storage:
        for candidate in on_shared_storage:
            # SPL-100508 On windows if the path is missing the drive letter,
            # construct fullpath manually and call relpath
            if os.name == 'nt' and not _verify_path_prefix(relpath, candidate):
                break

            if os.path.relpath(relpath, candidate)[0:2] != '..':
                basepath = shared_storage
                break

    if basepath is None:
        etc_with_trailing_sep = os.path.join(ETC_LEAF, '')
        if relpath == ETC_LEAF or relpath.startswith(etc_with_trailing_sep):
            # Redirect $SPLUNK_HOME/etc to $SPLUNK_ETC.
            basepath = _splunk_etc()
            # Remove leading etc (and path separator, if present). Note: when
            # emitting $SPLUNK_ETC exactly, with no additional path parts, we
            # set <relpath> to the empty string.
            relpath = relpath[4:]
        else:
            basepath = _splunk_home()

    fullpath = os.path.normpath(os.path.join(basepath, relpath))

    # Check that we haven't escaped from intended parent directories.
    if os.path.relpath(fullpath, basepath)[0:2] == '..':
        raise ValueError('Illegal escape from parent directory "%s": %s' %
                         (basepath, fullpath))
    return fullpath


def get_splunk_host_info():
    '''Get splunk host info.

    :returns: Tuple of (server_name, host_name).
    :rtype: ``tuple``
    '''

    server_name = get_conf_key_value('server', 'general', 'serverName')
    host_name = socket.gethostname()
    return (server_name, host_name)


def get_splunk_bin():
    '''Get absolute path of splunk CLI.

    :returns: absolute path of splunk CLI
    :rtype: ``string``
    '''

    if os.name == 'nt':
        splunk_bin = 'splunk.exe'
    else:
        splunk_bin = 'splunk'
    return make_splunkhome_path(('bin', splunk_bin))


def get_splunkd_access_info():
    '''Get splunkd server access info.

    :returns: Tuple of (scheme, host, port).
    :rtype: ``tuple``
    '''

    if utils.is_true(get_conf_key_value(
            'server', 'sslConfig', 'enableSplunkdSSL')):
        scheme = 'https'
    else:
        scheme = 'http'

    host_port = get_conf_key_value('web', 'settings', 'mgmtHostPort')
    host_port = host_port.strip()
    host = host_port.split(':')[0]
    port = int(host_port.split(':')[1])

    if 'SPLUNK_BINDIP' in os.environ:
        bindip = os.environ['SPLUNK_BINDIP']
        port_idx = bindip.rfind(':')
        host = bindip[:port_idx] if port_idx > 0 else bindip

    return (scheme, host, port)


def get_splunkd_uri():
    '''Get splunkd uri.

    :returns: Splunkd uri.
    :rtype: ``string``
    '''

    if os.environ.get('SPLUNKD_URI'):
        return os.environ['SPLUNKD_URI']

    scheme, host, port = get_splunkd_access_info()
    return '{scheme}://{host}:{port}'.format(
        scheme=scheme, host=host, port=port)


def get_conf_key_value(conf_name, stanza, key):
    '''Get value of `key` of `stanza` in `conf_name`.

    :param conf_name: Config file.
    :type conf_name: ``string``
    :param stanza: Stanza name.
    :type stanza: ``string``
    :param key: Key name.
    :type key: ``string``
    :returns: Config value.
    :rtype: ``(string, list, dict)``

    :raises KeyError: If `stanza` or `key` doesn't exist.
    '''

    stanzas = get_conf_stanzas(conf_name)
    return stanzas[stanza][key]


def get_conf_stanza(conf_name, stanza):
    '''Get `stanza` in `conf_name`.

    :param conf_name: Config file.
    :type conf_name: ``string``
    :param stanza: Stanza name.
    :type stanza: ``string``
    :returns: Config stanza.
    :rtype: ``dict``

    :raises KeyError: If stanza doesn't exist.
    '''

    stanzas = get_conf_stanzas(conf_name)
    return stanzas[stanza]


def get_conf_stanzas(conf_name):
    '''Get stanzas of `conf_name`

    :param conf_name: Config file.
    :type conf_name: ``string``
    :returns: Config stanzas.
    :rtype: ``dict``

    Usage::
       >>> stanzas = get_conf_stanzas('server')
       >>> return: {'serverName': 'testServer', 'sessionTimeout': '1h', ...}
    '''

    if conf_name.endswith('.conf'):
        conf_name = conf_name[:-5]

    # TODO: dynamically caculate SPLUNK_HOME
    btool_cli = [op.join(os.environ['SPLUNK_HOME'], 'bin', 'btool'),
                 conf_name, 'list']
    p = subprocess.Popen(btool_cli,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    out, _ = p.communicate()

    out = StringIO(out)
    parser = ConfigParser()
    parser.optionxform = str
    parser.readfp(out)

    out = {}
    for section in parser.sections():
        out[section] = {item[0]: item[1] for item in parser.items(section)}
    return out
