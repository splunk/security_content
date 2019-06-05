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
Splunk user access control related utilities.
'''

import json
import re

from . import splunk_rest_client as rest_client
from .packages.splunklib import binding
from .utils import retry

__all__ = ['ObjectACLException',
           'ObjectACL',
           'ObjectACLManagerException',
           'ObjectACLManager',
           'AppCapabilityManagerException',
           'AppCapabilityManager',
           'UserAccessException',
           'check_user_access',
           'InvalidSessionKeyException',
           'get_current_username',
           'UserNotExistException',
           'get_user_capabilities',
           'user_is_capable',
           'get_user_roles']


class ObjectACLException(Exception):
    pass


class ObjectACL(object):
    '''Object ACL record.

    :param obj_collection: Collection where object currently stored.
    :type obj_collection: ``string``
    :param obj_id: ID of this object.
    :type obj_id: ``string``
    :param obj_app: App of this object.
    :param obj_type: ``string``
    :param obj_owner: Owner of this object.
    :param obj_owner: ``string``
    :param obj_perms: Object perms, like: {
        'read': ['*'],
        'write': ['admin'],
        'delete': ['admin']}.
    :type obj_perms: ``dict``
    :param obj_shared_by_inclusion: Flag of object is shared by inclusion.
    :type obj_shared_by_inclusion: ``bool``

    Usage::

       >>> from solnlib import user_access
       >>> obj_acl = user_access.ObjectACL(
       >>>    'test_collection',
       >>>    '9defa6f510d711e6be16a45e60e34295',
       >>>    'test_object',
       >>>    'Splunk_TA_test',
       >>>    'admin',
       >>>    {'read': ['*'], 'write': ['admin'], 'delete': ['admin']},
       >>>    False)
    '''

    OBJ_COLLECTION_KEY = 'obj_collection'
    OBJ_ID_KEY = 'obj_id'
    OBJ_TYPE_KEY = 'obj_type'
    OBJ_APP_KEY = 'obj_app'
    OBJ_OWNER_KEY = 'obj_owner'
    OBJ_PERMS_KEY = 'obj_perms'
    OBJ_PERMS_READ_KEY = 'read'
    OBJ_PERMS_WRITE_KEY = 'write'
    OBJ_PERMS_DELETE_KEY = 'delete'
    OBJ_PERMS_ALLOW_ALL = '*'
    OBJ_SHARED_BY_INCLUSION_KEY = 'obj_shared_by_inclusion'

    def __init__(self, obj_collection, obj_id, obj_type,
                 obj_app, obj_owner, obj_perms, obj_shared_by_inclusion):
        self.obj_collection = obj_collection
        self.obj_id = obj_id
        self.obj_type = obj_type
        self.obj_app = obj_app
        self.obj_owner = obj_owner
        self._check_perms(obj_perms)
        self._obj_perms = obj_perms
        self.obj_shared_by_inclusion = obj_shared_by_inclusion

    @classmethod
    def _check_perms(cls, obj_perms):
        if not isinstance(obj_perms, dict):
            raise ObjectACLException(
                'Invalid object acl perms type: %s, should be a dict.' %
                type(obj_perms))

        if not (cls.OBJ_PERMS_READ_KEY in obj_perms and
                cls.OBJ_PERMS_WRITE_KEY in obj_perms and
                cls.OBJ_PERMS_DELETE_KEY in obj_perms):
            raise ObjectACLException(
                'Invalid object acl perms: %s, '
                'should include read, write and delete perms.' % obj_perms)

    @property
    def obj_perms(self):
        return self._obj_perms

    @obj_perms.setter
    def obj_perms(self, obj_perms):
        self._check_perms(obj_perms)
        self._obj_perms = obj_perms

    @property
    def record(self):
        '''Get object acl record.

        :returns: Object acl record, like: {
            '_key': 'test_collection-1234',
            'obj_collection': 'test_collection',
            'obj_id': '1234',
            'obj_type': 'test_object',
            'obj_app': 'Splunk_TA_test',
            'obj_owner': 'admin',
            'obj_perms': {'read': ['*'], 'write': ['admin'], 'delete': ['admin']},
            'obj_shared_by_inclusion': True}
        :rtype: ``dict``
        '''

        return {
            '_key': self.generate_key(self.obj_collection, self.obj_id),
            self.OBJ_COLLECTION_KEY: self.obj_collection,
            self.OBJ_ID_KEY: self.obj_id,
            self.OBJ_TYPE_KEY: self.obj_type,
            self.OBJ_APP_KEY: self.obj_app,
            self.OBJ_OWNER_KEY: self.obj_owner,
            self.OBJ_PERMS_KEY: self._obj_perms,
            self.OBJ_SHARED_BY_INCLUSION_KEY: self.obj_shared_by_inclusion}

    @staticmethod
    def generate_key(obj_collection, obj_id):
        '''Generate object acl record key.

        :param obj_collection: Collection where object currently stored.
        :type obj_collection: ``string``
        :param obj_id: ID of this object.
        :type obj_id: ``string``
        :returns: Object acl record key.
        :rtype: ``string``
        '''

        return '{obj_collection}_{obj_id}'.format(
            obj_collection=obj_collection, obj_id=obj_id)

    @staticmethod
    def parse(obj_acl_record):
        '''Parse object acl record and construct a new `ObjectACL` object from it.

        :param obj_acl_record: Object acl record.
        :type obj_acl: ``dict``
        :returns: New `ObjectACL` object.
        :rtype: `ObjectACL`
        '''

        return ObjectACL(
            obj_acl_record[ObjectACL.OBJ_COLLECTION_KEY],
            obj_acl_record[ObjectACL.OBJ_ID_KEY],
            obj_acl_record[ObjectACL.OBJ_TYPE_KEY],
            obj_acl_record[ObjectACL.OBJ_APP_KEY],
            obj_acl_record[ObjectACL.OBJ_OWNER_KEY],
            obj_acl_record[ObjectACL.OBJ_PERMS_KEY],
            obj_acl_record[ObjectACL.OBJ_SHARED_BY_INCLUSION_KEY])

    def merge(self, obj_acl):
        '''Merge current object perms with perms of `obj_acl`.

        :param obj_acl: Object acl to merge.
        :type obj_acl: ``ObjectACL``
        '''

        for perm_key in self._obj_perms:
            self._obj_perms[perm_key] = list(
                set.union(
                    set(self._obj_perms[perm_key]),
                    set(obj_acl._obj_perms[perm_key])))
            if self.OBJ_PERMS_ALLOW_ALL in self._obj_perms[perm_key]:
                self._obj_perms[perm_key] = [self.OBJ_PERMS_ALLOW_ALL]

    def __str__(self):
        return json.dumps(self.record)


@retry(exceptions=[binding.HTTPError])
def _get_collection_data(collection_name, session_key, app, owner,
                         scheme, host, port, **context):
    kvstore = rest_client.SplunkRestClient(session_key,
                                           app,
                                           owner=owner,
                                           scheme=scheme,
                                           host=host,
                                           port=port,
                                           **context).kvstore

    collection_name = re.sub(r'[^\w]+', '_', collection_name)
    try:
        kvstore.get(name=collection_name)
    except binding.HTTPError as e:
        if e.status != 404:
            raise

        kvstore.create(collection_name)

    collections = kvstore.list(search=collection_name)
    for collection in collections:
        if collection.name == collection_name:
            return collection.data
    else:
        raise KeyError('Get collection data: %s failed.' % collection_name)


class ObjectACLManagerException(Exception):
    pass


class ObjectACLNotExistException(Exception):
    pass


class ObjectACLManager(object):
    '''Object ACL manager.

    :param collection_name: Collection name to store object ACL info.
    :type collection_name: ``string``
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

    :raises ObjectACLManagerException: If init ObjectACLManager failed.

    Usage::

       >>> from solnlib import user_access
       >>> oaclm = user_access.ObjectACLManager(session_key,
                                                'Splunk_TA_test')
    '''

    def __init__(self, collection_name, session_key, app, owner='nobody',
                 scheme=None, host=None, port=None, **context):
        collection_name = '{app}_{collection_name}'.format(
            app=app, collection_name=collection_name)
        try:
            self._collection_data = _get_collection_data(
                collection_name, session_key, app, owner,
                scheme, host, port, **context)
        except KeyError:
            raise ObjectACLManagerException(
                'Get object acl collection: %s fail.' % collection_name)

    @retry(exceptions=[binding.HTTPError])
    def update_acl(self, obj_collection, obj_id, obj_type, obj_app, obj_owner,
                   obj_perms, obj_shared_by_inclusion=True, replace_existing=True):
        '''Update acl info of object.

        Construct a new object acl info first, if `replace_existing` is True
        then replace existing acl info else merge new object acl info with the
        old one and replace the old acl info with merged acl info.

        :param obj_collection: Collection where object currently stored.
        :type obj_collection: ``string``
        :param obj_id: ID of this object.
        :type obj_id: ``string``
        :param obj_app: App of this object.
        :param obj_type: ``string``
        :param obj_owner: Owner of this object.
        :param obj_owner: ``string``
        :param obj_perms: Object perms, like: {
            'read': ['*'],
            'write': ['admin'],
            'delete': ['admin']}.
        :type obj_perms: ``dict``
        :param obj_shared_by_inclusion: (optional) Flag of object is shared by
            inclusion, default is True.
        :type obj_shared_by_inclusion: ``bool``
        :param replace_existing: (optional) Replace existing acl info flag, True
            indicates replace old acl info with new one else merge with old acl
            info, default is True.
        :type replace_existing: ``bool``
        '''

        obj_acl = ObjectACL(
            obj_collection, obj_id, obj_type,
            obj_app, obj_owner, obj_perms, obj_shared_by_inclusion)

        if not replace_existing:
            try:
                old_obj_acl = self.get_acl(obj_collection, obj_id)
            except ObjectACLNotExistException:
                old_obj_acl = None

            if old_obj_acl:
                obj_acl.merge(old_obj_acl)

        self._collection_data.batch_save(obj_acl.record)

    @retry(exceptions=[binding.HTTPError])
    def update_acls(self, obj_collection, obj_ids, obj_type, obj_app, obj_owner,
                    obj_perms, obj_shared_by_inclusion=True, replace_existing=True):
        '''Batch update object acl info to all provided `obj_ids`.

        :param obj_collection: Collection where objects currently stored.
        :type obj_collection: ``string``
        :param obj_id: IDs list of objects.
        :type obj_id: ``list``
        :param obj_app: App of this object.
        :param obj_type: ``string``
        :param obj_owner: Owner of this object.
        :param obj_owner: ``string``
        :param obj_perms: Object perms, like: {
            'read': ['*'],
            'write': ['admin'],
            'delete': ['admin']}.
        :type obj_perms: ``dict``
        :param obj_shared_by_inclusion: (optional) Flag of object is shared by
            inclusion, default is True.
        :type obj_shared_by_inclusion: ``bool``
        :param replace_existing: (optional) Replace existing acl info flag, True
            indicates replace old acl info with new one else merge with old acl
            info, default is True.
        :type replace_existing: ``bool``
        '''

        obj_acl_records = []
        for obj_id in obj_ids:
            obj_acl = ObjectACL(
                obj_collection, obj_id, obj_type,
                obj_app, obj_owner, obj_perms, obj_shared_by_inclusion)

            if not replace_existing:
                try:
                    old_obj_acl = self.get_acl(obj_collection, obj_id)
                except ObjectACLNotExistException:
                    old_obj_acl = None

                if old_obj_acl:
                    obj_acl.merge(old_obj_acl)

            obj_acl_records.append(obj_acl.record)

        self._collection_data.batch_save(*obj_acl_records)

    @retry(exceptions=[binding.HTTPError])
    def get_acl(self, obj_collection, obj_id):
        '''Get acl info.

        Query object acl info with parameter of the combination of
        `obj_collection` and `obj_id` from `self.collection_name` and
        return it.

        :param obj_collection: Collection where object currently stored.
        :type obj_collection: ``string``
        :param obj_id: ID of this object.
        :type obj_id: ``string``
        :returns: Object acl info if success else None.
        :rtype: ``ObjectACL``

        :raises ObjectACLNotExistException: If object ACL info does not exist.
        '''

        key = ObjectACL.generate_key(obj_collection, obj_id)
        try:
            obj_acl = self._collection_data.query_by_id(key)
        except binding.HTTPError as e:
            if e.status != 404:
                raise

            raise ObjectACLNotExistException(
                'Object ACL info of %s_%s does not exist.' %
                (obj_collection, obj_id))

        return ObjectACL.parse(obj_acl)

    @retry(exceptions=[binding.HTTPError])
    def get_acls(self, obj_collection, obj_ids):
        '''Batch get acl info.

        Query objects acl info with parameter of the combination of
        `obj_collection` and `obj_ids` from KVStore and return them.

        :param obj_collection: Collection where object currently stored.
        :type obj_collection: ``string``
        :param obj_ids: IDs of objects.
        :type obj_ids: ``list``
        :returns: List of `ObjectACL` instances.
        :rtype: ``list``
        '''

        query = json.dumps(
            {'$or': [{'_key': ObjectACL.generate_key(obj_collection, obj_id)}
                     for obj_id in obj_ids]})
        obj_acls = self._collection_data.query(query=query)

        return [ObjectACL.parse(obj_acl) for obj_acl in obj_acls]

    @retry(exceptions=[binding.HTTPError])
    def delete_acl(self, obj_collection, obj_id):
        '''Delete acl info.

        Query object acl info with parameter of the combination of
        `obj_collection` and `obj_ids` from KVStore and delete it.

        :param obj_collection: Collection where object currently stored.
        :type obj_collection: ``string``
        :param obj_id: ID of this object.
        :type obj_id: ``string``

        :raises ObjectACLNotExistException: If object ACL info does not exist.
        '''

        key = ObjectACL.generate_key(obj_collection, obj_id)
        try:
            self._collection_data.delete_by_id(key)
        except binding.HTTPError as e:
            if e.status != 404:
                raise

            raise ObjectACLNotExistException(
                'Object ACL info of %s_%s does not exist.' %
                (obj_collection, obj_id))

    @retry(exceptions=[binding.HTTPError])
    def delete_acls(self, obj_collection, obj_ids):
        '''Batch delete acl info.

        Query objects acl info with parameter of the combination of
        `obj_collection` and `obj_ids` from KVStore and delete them.

        :param obj_collection: Collection where object currently stored.
        :type obj_collection: ``string``
        :param obj_ids: IDs of objects.
        :type obj_id: ``list``
        '''

        query = json.dumps(
            {'$or': [{'_key': ObjectACL.generate_key(obj_collection, obj_id)}
                     for obj_id in obj_ids]})
        self._collection_data.delete(query=query)

    @retry(exceptions=[binding.HTTPError])
    def get_accessible_object_ids(self, user, operation, obj_collection, obj_ids):
        '''Get accessible IDs of objects from `obj_acls`.

        :param user: User name of current `operation`.
        :type user: ``string``
        :param operation: User operation, possible option: (read/write/delete).
        :type operation: ``string``
        :param obj_collection: Collection where object currently stored.
        :type obj_collection: ``string``
        :param obj_ids: IDs of objects.
        :type obj_id: ``list``
        :returns: List of IDs of accessible objects.
        :rtype: ``list``
        '''

        obj_acls = self.get_acls(obj_collection, obj_ids)
        accessible_obj_ids = []
        for obj_acl in obj_acls:
            perms = obj_acl.obj_perms[operation]
            if ObjectACL.OBJ_PERMS_ALLOW_ALL in perms or user in perms:
                accessible_obj_ids.append(obj_acl.obj_id)

        return accessible_obj_ids


class AppCapabilityManagerException(Exception):
    pass


class AppCapabilityNotExistException(Exception):
    pass


class AppCapabilityManager(object):
    '''App capability manager.

    :param collection_name: Collection name to store capabilities.
    :type collection_name: ``string``
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

    :raises AppCapabilityManagerException: If init AppCapabilityManager failed.

    Usage::

       >>> from solnlib import user_access
       >>> acm = user_access.AppCapabilityManager('test_collection',
                                                  session_key,
                                                  'Splunk_TA_test')
       >>> acm.register_capabilities(...)
       >>> acm.unregister_capabilities(...)
    '''

    def __init__(self, collection_name, session_key, app, owner='nobody',
                 scheme=None, host=None, port=None, **context):
        self._app = app

        collection_name = '{app}_{collection_name}'.format(
            app=app, collection_name=collection_name)
        try:
            self._collection_data = _get_collection_data(
                collection_name, session_key, app, owner,
                scheme, host, port, **context)
        except KeyError:
            raise AppCapabilityManagerException(
                'Get app capabilities collection: %s failed.' %
                collection_name)

    @retry(exceptions=[binding.HTTPError])
    def register_capabilities(self, capabilities):
        '''Register app capabilities.

        :param capabilities: App capabilities, example: {
            'object_type1': {
            'read': 'read_app_object_type1',
            'write': 'write_app_object_type1',
            'delete': 'delete_app_object_type1'},
            'object_type2': {
            'read': 'read_app_object_type2',
            'write': 'write_app_object_type2',
            'delete': 'delete_app_object_type2'},
            ...}
        :type capabilities: ``dict``
        '''

        record = {'_key': self._app, 'capabilities': capabilities}
        self._collection_data.batch_save(record)

    @retry(exceptions=[binding.HTTPError])
    def unregister_capabilities(self):
        '''Unregister app capabilities.

        :raises AppCapabilityNotExistException: If app capabilities are
            not registered.
        '''

        try:
            self._collection_data.delete_by_id(self._app)
        except binding.HTTPError as e:
            if e.status != 404:
                raise

            raise AppCapabilityNotExistException(
                'App capabilities for %s have not been registered.' % self._app)

    @retry(exceptions=[binding.HTTPError])
    def capabilities_are_registered(self):
        '''Check if app capabilities are registered.

        :returns: True if app capabilities are registered else
            False.
        :rtype: ``bool``
        '''

        try:
            self._collection_data.query_by_id(self._app)
        except binding.HTTPError as e:
            if e.status != 404:
                raise

            return False

        return True

    @retry(exceptions=[binding.HTTPError])
    def get_capabilities(self):
        '''Get app capabilities.

        :returns: App capabilities.
        :rtype: ``dict``

        :raises AppCapabilityNotExistException: If app capabilities are
            not registered.
        '''

        try:
            record = self._collection_data.query_by_id(self._app)
        except binding.HTTPError as e:
            if e.status != 404:
                raise

            raise AppCapabilityNotExistException(
                'App capabilities for %s have not been registered.' % self._app)

        return record['capabilities']


class UserAccessException(Exception):
    pass


def check_user_access(session_key, capabilities, obj_type, operation,
                      scheme=None, host=None, port=None, **context):
    '''User access checker.

    It will fetch user capabilities from given `session_key` and check if
    the capability extracted from `capabilities`, `obj_type` and `operation`
    is contained, if user capabilities include the extracted capability user
    access is ok else fail.

    :param session_key: Splunk access token.
    :type session_key: ``string``
    :param capabilities: App capabilities, example: {
        'object_type1': {
        'read': 'read_app_object_type1',
        'write': 'write_app_object_type1',
        'delete': 'delete_app_object_type1'},
        'object_type2': {
        'read': 'read_app_object_type2',
        'write': 'write_app_object_type2',
        'delete': 'delete_app_object_type2'},
        ...}
    :type capabilities: ``dict``
    :param obj_type: Object type.
    :type obj_type: ``string``
    :param operation: User operation, possible option: (read/write/delete).
    :type operation: ``string``
    :param scheme: (optional) The access scheme, default is None.
    :type scheme: ``string``
    :param host: (optional) The host name, default is None.
    :type host: ``string``
    :param port: (optional) The port number, default is None.
    :type port: ``integer``
    :param context: Other configurations for Splunk rest client.
    :type context: ``dict``

    :raises UserAccessException: If user access permission is denied.

    Usage::
       >>> from solnlib.user_access import check_user_access
       >>> def fun():
       >>>     check_user_access(
       >>>         session_key, capabilities, 'test_object', 'read')
       >>>     ...
    '''

    username = get_current_username(
        session_key, scheme=scheme, host=host, port=port, **context)
    capability = capabilities[obj_type][operation]
    if not user_is_capable(session_key, username, capability,
                           scheme=scheme, host=host, port=port, **context):
        raise UserAccessException(
            'Permission denied, %s does not have the capability: %s.' %
            (username, capability))


class InvalidSessionKeyException(Exception):
    pass


@retry(exceptions=[binding.HTTPError])
def get_current_username(session_key,
                         scheme=None, host=None, port=None, **context):
    '''Get current user name from `session_key`.

    :param session_key: Splunk access token.
    :type session_key: ``string``
    :param scheme: (optional) The access scheme, default is None.
    :type scheme: ``string``
    :param host: (optional) The host name, default is None.
    :type host: ``string``
    :param port: (optional) The port number, default is None.
    :type port: ``integer``
    :param context: Other configurations for Splunk rest client.
    :type context: ``dict``
    :returns: Current user name.
    :rtype: ``string``

    :raises InvalidSessionKeyException: If `session_key` is invalid.

    Usage::

       >>> from solnlib import user_access
       >>> user_name = user_access.get_current_username(session_key)
    '''

    _rest_client = rest_client.SplunkRestClient(
        session_key,
        '-',
        scheme=scheme,
        host=host,
        port=port,
        **context)
    try:
        response = _rest_client.get('/services/authentication/current-context',
                                    output_mode='json').body.read()
    except binding.HTTPError as e:
        if e.status != 401:
            raise

        raise InvalidSessionKeyException('Invalid session key.')

    return json.loads(response)['entry'][0]['content']['username']


class UserNotExistException(Exception):
    pass


@retry(exceptions=[binding.HTTPError])
def get_user_capabilities(session_key, username,
                          scheme=None, host=None, port=None, **context):
    '''Get user capabilities.

    :param session_key: Splunk access token.
    :type session_key: ``string``
    :param username: User name of capabilities to get.
    :type username: ``string``
    :param scheme: (optional) The access scheme, default is None.
    :type scheme: ``string``
    :param host: (optional) The host name, default is None.
    :type host: ``string``
    :param port: (optional) The port number, default is None.
    :type port: ``integer``
    :param context: Other configurations for Splunk rest client.
    :type context: ``dict``
    :returns: User capabilities.
    :rtype: ``list``

    :raises UserNotExistException: If `username` does not exist.

    Usage::

       >>> from solnlib import user_access
       >>> user_capabilities = user_access.get_user_capabilities(
       >>>     session_key, 'test_user')
    '''

    _rest_client = rest_client.SplunkRestClient(
        session_key,
        '-',
        scheme=scheme,
        host=host,
        port=port,
        **context)
    url = '/services/authentication/users/{username}'.format(username=username)
    try:
        response = _rest_client.get(url, output_mode='json').body.read()
    except binding.HTTPError as e:
        if e.status != 404:
            raise

        raise UserNotExistException('User: %s does not exist.' % username)

    return json.loads(response)['entry'][0]['content']['capabilities']


def user_is_capable(session_key, username, capability,
                    scheme=None, host=None, port=None, **context):
    '''Check if user is capable for given `capability`.

    :param session_key: Splunk access token.
    :type session_key: ``string``
    :param username: (optional) User name of roles to get.
    :type username: ``string``
    :param capability: The capability we wish to check for.
    :type capability: ``string``
    :param scheme: (optional) The access scheme, default is None.
    :type scheme: ``string``
    :param host: (optional) The host name, default is None.
    :type host: ``string``
    :param port: (optional) The port number, default is None.
    :type port: ``integer``
    :param context: Other configurations for Splunk rest client.
    :type context: ``dict``
    :returns: True if user is capable else False.
    :rtype: ``bool``

    :raises UserNotExistException: If `username` does not exist.

    Usage::

       >>> from solnlib import user_access
       >>> is_capable = user_access.user_is_capable(
       >>>     session_key, 'test_user', 'object_read_capability')
    '''

    capabilities = get_user_capabilities(
        session_key, username, scheme=scheme, host=host, port=port, **context)
    return capability in capabilities


@retry(exceptions=[binding.HTTPError])
def get_user_roles(session_key, username,
                   scheme=None, host=None, port=None, **context):
    '''Get user roles.

    :param session_key: Splunk access token.
    :type session_key: ``string``
    :param username: (optional) User name of roles to get.
    :type username: ``string``
    :param scheme: (optional) The access scheme, default is None.
    :type scheme: ``string``
    :param host: (optional) The host name, default is None.
    :type host: ``string``
    :param port: (optional) The port number, default is None.
    :type port: ``integer``
    :param context: Other configurations for Splunk rest client.
    :type context: ``dict``
    :returns: User roles.
    :rtype: ``list``

    :raises UserNotExistException: If `username` does not exist.

    Usage::

       >>> from solnlib import user_access
       >>> user_roles = user_access.get_user_roles(session_key, 'test_user')
    '''

    _rest_client = rest_client.SplunkRestClient(
        session_key,
        '-',
        scheme=scheme,
        host=host,
        port=port,
        **context)
    url = '/services/authentication/users/{username}'.format(username=username)
    try:
        response = _rest_client.get(url, output_mode='json').body.read()
    except binding.HTTPError as e:
        if e.status != 404:
            raise

        raise UserNotExistException('User: %s does not exist.' % username)

    return json.loads(response)['entry'][0]['content']['roles']
