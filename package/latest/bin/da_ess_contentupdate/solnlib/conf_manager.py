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
This module contains simple interfaces for Splunk config file management,
you can update/get/delete stanzas and encrypt/decrypt some fields of stanza
automatically.
'''

import json
import logging
import traceback

from . import splunk_rest_client as rest_client
from .credentials import CredentialManager
from .credentials import CredentialNotExistException
from .packages.splunklib import binding
from .utils import retry

__all__ = ['ConfStanzaNotExistException',
           'ConfFile',
           'ConfManagerException',
           'ConfManager']


class ConfStanzaNotExistException(Exception):
    pass


class ConfFile(object):
    '''Configuration file.

    :param name: Configuration file name.
    :type name: ``string``
    :param conf: Configuration file object.
    :type conf: ``splunklib.client.ConfigurationFile``
    :param session_key: Splunk access token.
    :type session_key: ``string``
    :param app: App name of namespace.
    :type app: ``string``
    :param owner: (optional) Owner of namespace, default is `nobody`.
    :type owner: ``string``
    :param realm: (optional) Realm of credential, default is None.
    :type realm: ``string``
    :param scheme: (optional) The access scheme, default is None.
    :type scheme: ``string``
    :param host: (optional) The host name, default is None.
    :type host: ``string``
    :param port: (optional) The port number, default is None.
    :type port: ``integer``
    :param context: Other configurations for Splunk rest client.
    :type context: ``dict``
    '''

    ENCRYPTED_TOKEN = '******'

    reserved_keys = ('userName', 'appName')

    def __init__(self, name, conf, session_key, app, owner='nobody',
                 scheme=None, host=None, port=None, **context):
        self._name = name
        self._conf = conf
        self._session_key = session_key
        self._app = app
        self._owner = owner
        self._scheme = scheme
        self._host = host
        self._port = port
        self._context = context
        self._cred_manager = None

    @property
    @retry(exceptions=[binding.HTTPError])
    def _cred_mgr(self):
        if self._cred_manager is None:
            self._cred_manager = CredentialManager(
                self._session_key, self._app, owner=self._owner,
                realm=self._app, scheme=self._scheme, host=self._host,
                port=self._port, **self._context)

        return self._cred_manager

    def _filter_stanza(self, stanza):
        for k in self.reserved_keys:
            if k in stanza:
                del stanza[k]

        return stanza

    def _encrypt_stanza(self, stanza_name, stanza, encrypt_keys):
        if not encrypt_keys:
            return stanza

        encrypt_stanza_keys = [ k for k in encrypt_keys if k in stanza ]
        encrypt_fields = {key: stanza[key] for key in encrypt_stanza_keys}
        if not encrypt_fields:
            return stanza
        self._cred_mgr.set_password(stanza_name, json.dumps(encrypt_fields))

        for key in encrypt_stanza_keys:
            stanza[key] = self.ENCRYPTED_TOKEN

        return stanza

    def _decrypt_stanza(self, stanza_name, encrypted_stanza):
        encrypted_keys = [key for key in encrypted_stanza if
                          encrypted_stanza[key] == self.ENCRYPTED_TOKEN]
        if encrypted_keys:
            encrypted_fields = json.loads(
                self._cred_mgr.get_password(stanza_name))
            for key in encrypted_keys:
                encrypted_stanza[key] = encrypted_fields[key]

        return encrypted_stanza

    def _delete_stanza_creds(self, stanza_name):
        self._cred_mgr.delete_password(stanza_name)

    @retry(exceptions=[binding.HTTPError])
    def stanza_exist(self, stanza_name):
        '''Check whether stanza exists.

        :param stanza_name: Stanza name.
        :type stanza_name: ``string``
        :returns: True if stanza exists else False.
        :rtype: ``bool``

        Usage::

           >>> from solnlib import conf_manager
           >>> cfm = conf_manager.ConfManager(session_key,
                                              'Splunk_TA_test')
           >>> conf = cfm.get_conf('test')
           >>> conf.stanza_exist('test_stanza')
        '''

        try:
            self._conf.list(name=stanza_name)[0]
        except binding.HTTPError as e:
            if e.status != 404:
                raise

            return False

        return True

    @retry(exceptions=[binding.HTTPError])
    def get(self, stanza_name, only_current_app=False):
        '''Get stanza from configuration file.

        :param stanza_name: Stanza name.
        :type stanza_name: ``string``
        :returns: Stanza, like: {
            'disabled': '0',
            'eai:appName': 'solnlib_demo',
            'eai:userName': 'nobody',
            'k1': '1',
            'k2': '2'}
        :rtype: ``dict``

        :raises ConfStanzaNotExistException: If stanza does not exist.

        Usage::

           >>> from solnlib import conf_manager
           >>> cfm = conf_manager.ConfManager(session_key,
                                              'Splunk_TA_test')
           >>> conf = cfm.get_conf('test')
           >>> conf.get('test_stanza')
        '''

        try:
            if only_current_app:
                stanza_mgrs = self._conf.list(
                    search='eai:acl.app={} name={}'.format(
                        self._app, stanza_name.replace('=', r'\=')))
            else:
                stanza_mgrs = self._conf.list(name=stanza_name)
        except binding.HTTPError as e:
            if e.status != 404:
                raise

            raise ConfStanzaNotExistException(
                'Stanza: %s does not exist in %s.conf' %
                (stanza_name, self._name))

        if len(stanza_mgrs) == 0:
            raise ConfStanzaNotExistException(
                'Stanza: %s does not exist in %s.conf' %
                (stanza_name, self._name))

        stanza = self._decrypt_stanza(stanza_mgrs[0].name, stanza_mgrs[0].content)
        stanza['eai:access'] = stanza_mgrs[0].access
        stanza['eai:appName'] = stanza_mgrs[0].access.app
        return stanza

    @retry(exceptions=[binding.HTTPError])
    def get_all(self, only_current_app=False):
        '''Get all stanzas from configuration file.

        :returns: All stanzas, like: {'test': {
            'disabled': '0',
            'eai:appName': 'solnlib_demo',
            'eai:userName': 'nobody',
            'k1': '1',
            'k2': '2'}}
        :rtype: ``dict``

        Usage::

           >>> from solnlib import conf_manager
           >>> cfm = conf_manager.ConfManager(session_key,
                                              'Splunk_TA_test')
           >>> conf = cfm.get_conf('test')
           >>> conf.get_all()
        '''

        if only_current_app:
            stanza_mgrs = self._conf.list(search='eai:acl.app={}'.format(self._app))
        else:
            stanza_mgrs = self._conf.list()
        res = {}
        for stanza_mgr in stanza_mgrs:
            name = stanza_mgr.name
            key_values = self._decrypt_stanza(name, stanza_mgr.content)
            key_values['eai:access'] = stanza_mgr.access
            key_values['eai:appName'] = stanza_mgr.access.app
            res[name] = key_values
        return res

    @retry(exceptions=[binding.HTTPError])
    def update(self, stanza_name, stanza, encrypt_keys=None):
        '''Update stanza.

        It will try to encrypt the credential automatically fist if
        encrypt_keys are not None else keep stanza untouched.

        :param stanza_name: Stanza name.
        :type stanza_name: ``string``
        :param stanza: Stanza to update, like: {
            'k1': 1,
            'k2': 2}.
        :type stanza: ``dict``
        :param encrypt_keys: Fields name to encrypt.
        :type encrypt_keys: ``list``

        Usage::

           >>> from solnlib import conf_manager
           >>> cfm = conf_manager.ConfManager(session_key,
                                              'Splunk_TA_test')
           >>> conf = cfm.get_conf('test')
           >>> conf.update('test_stanza', {'k1': 1, 'k2': 2}, ['k1'])
        '''

        stanza = self._filter_stanza(stanza)
        encrypted_stanza = self._encrypt_stanza(stanza_name,
                                                stanza,
                                                encrypt_keys)

        try:
            stanza_mgr = self._conf.list(name=stanza_name)[0]
        except binding.HTTPError as e:
            if e.status != 404:
                raise

            stanza_mgr = self._conf.create(stanza_name)

        stanza_mgr.submit(encrypted_stanza)

    @retry(exceptions=[binding.HTTPError])
    def delete(self, stanza_name):
        '''Delete stanza.

        :param stanza_name: Stanza name to delete.
        :type stanza_name: ``string``

        :raises ConfStanzaNotExistException: If stanza does not exist.

        Usage::

           >>> from solnlib import conf_manager
           >>> cfm = conf_manager.ConfManager(session_key,
                                              'Splunk_TA_test')
           >>> conf = cfm.get_conf('test')
           >>> conf.delete('test_stanza')
        '''

        try:
            self._cred_mgr.delete_password(stanza_name)
        except CredentialNotExistException:
            pass

        try:
            self._conf.delete(stanza_name)
        except KeyError as e:
            logging.error('Delete stanza: %s error: %s.',
                          stanza_name, traceback.format_exc(e))
            raise ConfStanzaNotExistException(
                'Stanza: %s does not exist in %s.conf' %
                (stanza_name, self._name))

    @retry(exceptions=[binding.HTTPError])
    def reload(self):
        '''Reload configuration file.

        Usage::

           >>> from solnlib import conf_manager
           >>> cfm = conf_manager.ConfManager(session_key,
                                              'Splunk_TA_test')
           >>> conf = cfm.get_conf('test')
           >>> conf.reload()
        '''

        self._conf.get('_reload')


class ConfManagerException(Exception):
    pass


class ConfManager(object):
    '''Configuration file manager.

    :param session_key: Splunk access token.
    :type session_key: ``string``
    :param app: App name of namespace.
    :type app: ``string``
    :param owner: (optional) Owner of namespace, default is `nobody`.
    :type owner: ``string``
    :param realm: (optional) Realm of credential, default is None.
    :type realm: ``string``
    :param scheme: (optional) The access scheme, default is None.
    :type scheme: ``string``
    :param host: (optional) The host name, default is None.
    :type host: ``string``
    :param port: (optional) The port number, default is None.
    :type port: ``integer``
    :param context: Other configurations for Splunk rest client.
    :type context: ``dict``

    Usage::

       >>> from solnlib import conf_manager
       >>> cfm = conf_manager.ConfManager(session_key,
                                          'Splunk_TA_test')
    '''

    def __init__(self, session_key, app, owner='nobody',
                 scheme=None, host=None, port=None, **context):
        self._session_key = session_key
        self._app = app
        self._owner = owner
        self._scheme = scheme
        self._host = host
        self._port = port
        self._context = context
        self._rest_client = rest_client.SplunkRestClient(
            self._session_key,
            self._app,
            owner=self._owner,
            scheme=self._scheme,
            host=self._host,
            port=self._port,
            **self._context)
        self._confs = None

    @retry(exceptions=[binding.HTTPError])
    def get_conf(self, name, refresh=False):
        '''Get conf file.

        :param name: Conf file name.
        :type name: ``string``
        :param refresh: (optional) Flag to refresh conf file list, default is False.
        :type refresh: ``bool``
        :returns: Conf file object.
        :rtype: ``solnlib.conf_manager.ConfFile``

        :raises ConfManagerException: If `conf_file` does not exist.
        '''

        if self._confs is None or refresh:
            # Fix bug that can't pass `-` as app name.
            curr_app = self._rest_client.namespace.app
            self._rest_client.namespace.app = "dummy"
            self._confs = self._rest_client.confs
            self._rest_client.namespace.app = curr_app

        try:
            conf = self._confs[name]
        except KeyError:
            raise ConfManagerException(
                'Config file: %s does not exist.' % name)

        return ConfFile(name, conf,
                        self._session_key, self._app, self._owner,
                        self._scheme, self._host, self._port, **self._context)

    @retry(exceptions=[binding.HTTPError])
    def create_conf(self, name):
        '''Create conf file.

        :param name: Conf file name.
        :type name: ``string``
        :returns: Conf file object.
        :rtype: ``solnlib.conf_manager.ConfFile``
        '''

        if self._confs is None:
            self._confs = self._rest_client.confs

        conf = self._confs.create(name)
        return ConfFile(name, conf,
                        self._session_key, self._app, self._owner,
                        self._scheme, self._host, self._port, **self._context)
