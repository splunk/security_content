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
This module contains interfaces that support CRUD operations on ACL.
'''

import json

from . import splunk_rest_client as rest_client
from .packages.splunklib import binding
from .utils import retry

__all__ = ['ACLException',
           'ACLManager']


class ACLException(Exception):
    pass


class ACLManager(object):
    '''ACL manager.

    :param session_key: Splunk access token.
    :type session_key: ``string``
    :param app: App name of namespace.
    :type app: ``string``
    :param owner: (optional) Owner of namespace, default is `nobody`.
    :type owner: ``string``
    :param scheme: (optional) The access scheme, default is None.
    :type scheme: ``string``
    :param host: (optional) The host name, default is None.
    :type host: ``string``
    :param port: (optional) The port number, default is None.
    :type port: ``integer``
    :param context: Other configurations for Splunk rest client.
    :type context: ``dict``

    Usage::

       >>> import solnlib.acl as sacl
       >>> saclm = sacl.ACLManager(session_key, 'Splunk_TA_test')
       >>> saclm.get('data/transforms/extractions')
       >>> saclm.update('data/transforms/extractions/_acl',
                        perms_read=['*'], perms_write=['*'])
    '''

    def __init__(self, session_key, app, owner='nobody',
                 scheme=None, host=None, port=None, **context):
        self._rest_client = rest_client.SplunkRestClient(session_key,
                                                         app,
                                                         owner=owner,
                                                         scheme=scheme,
                                                         host=host,
                                                         port=port,
                                                         **context)

    @retry(exceptions=[binding.HTTPError])
    def get(self, path):
        '''Get ACL of  /servicesNS/{`owner`}/{`app`}/{`path`}.

        :param path: Path of ACL relative to /servicesNS/{`owner`}/{`app`}
        :type path: ``string``
        :returns: A dict contains ACL.
        :rtype: ``dict``

        :raises ACLException: If `path` is invalid.

        Usage::
           >>> aclm = acl.ACLManager(session_key, 'Splunk_TA_test')
           >>> perms = aclm.get('data/transforms/extractions/_acl')
        '''

        try:
            content = self._rest_client.get(
                path, output_mode='json').body.read()
        except binding.HTTPError as e:
            if e.status != 404:
                raise

            raise ACLException('Invalid endpoint: %s.', path)

        return json.loads(content)['entry'][0]['acl']

    @retry(exceptions=[binding.HTTPError])
    def update(self, path, owner=None, perms_read=None, perms_write=None):
        '''Update ACL of /servicesNS/{`owner`}/{`app`}/{`path`}.

        If the ACL is per-entity (ends in /acl), owner can be reassigned. If
        the acl is endpoint-level (ends in _acl), owner will be ignored. The
        'sharing' setting is always retrieved from the current.

        :param path: Path of ACL relative to /servicesNS/{owner}/{app}. MUST
            end with /acl or /_acl indicating whether the permission is applied
            at the per-entity level or endpoint level respectively.
        :type path: ``string``
        :param owner: (optional) New owner of ACL, default is `nobody`.
        :type owner: ``string``
        :param perms_read: (optional) List of roles (['*'] for all roles). If
            unspecified we will POST with current (if available) perms.read,
            default is None.
        :type perms_read: ``list``
        :param perms_write: (optional) List of roles (['*'] for all roles). If
            unspecified we will POST with current (if available) perms.write,
            default is None.
        :type perms_write: ``list``
        :returns: A dict contains ACL after update.
        :rtype: ``dict``

        :raises ACLException: If `path` is invalid.

        Usage::
           >>> aclm = acl.ACLManager(session_key, 'Splunk_TA_test')
           >>> perms = aclm.update('data/transforms/extractions/_acl',
                                   perms_read=['admin'], perms_write=['admin'])
        '''

        if not path.endswith('/acl') and not path.endswith('/_acl'):
            raise ACLException(
                'Invalid endpoint: %s, must end with /acl or /_acl.' % path)

        curr_acl = self.get(path)

        postargs = {}
        if perms_read:
            postargs['perms.read'] = ','.join(perms_read)
        else:
            curr_read = curr_acl['perms'].get('read', [])
            if curr_read:
                postargs['perms.read'] = ','.join(curr_read)

        if perms_write:
            postargs['perms.write'] = ','.join(perms_write)
        else:
            curr_write = curr_acl['perms'].get('write', [])
            if curr_write:
                postargs['perms.write'] = ','.join(curr_write)

        if path.endswith('/acl'):
            # Allow ownership to be reset only at entity level.
            postargs['owner'] = owner or curr_acl['owner']

        postargs['sharing'] = curr_acl['sharing']

        try:
            content = self._rest_client.post(
                path, body=binding._encode(**postargs),
                output_mode='json').body.read()
        except binding.HTTPError as e:
            if e.status != 404:
                raise

            raise ACLException('Invalid endpoint: %s.', path)

        return json.loads(content)['entry'][0]['acl']
