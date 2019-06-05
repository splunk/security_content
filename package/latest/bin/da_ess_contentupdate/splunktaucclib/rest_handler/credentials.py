"""Credentials Management for REST Endpoint
"""

from __future__ import absolute_import

import json
from urlparse import urlparse
from solnlib.credentials import (
    CredentialManager,
    CredentialNotExistException,
)

from .util import get_base_app_name
from .error import RestError


__all__ = [
    'RestCredentialsContext',
    'RestCredentials',
]


class RestCredentialsContext(object):
    """
    Credentials' context, including realm, username and password.
    """

    REALM = '__REST_CREDENTIAL__#{base_app}#{endpoint}'

    def __init__(self, endpoint, name, *args, **kwargs):
        self._endpoint = endpoint
        self._name = name
        self._args = args
        self._kwargs = kwargs

    def realm(self):
        """
        RestCredentials context ``realm``.
        :return:
        """
        return self.REALM.format(
            base_app=get_base_app_name(),
            endpoint=self._endpoint.internal_endpoint.strip('/'),
        )

    def username(self):
        """
        RestCredentials context ``username``.
        :return:
        """
        return self._name

    def dump(self, data):
        """
        RestCredentials context ``password``.
        Dump data to string.
        :param data: data to be encrypted
        :type data: dict
        :return:
        """
        return json.dumps(data)

    def load(self, string):
        """
        RestCredentials context ``password``.
        Load data from string.
        :param string: data has been decrypted
        :type string: basestring
        :return:
        """
        try:
            return json.loads(string)
        except ValueError:
            raise RestError(
                500,
                'Fail to load encrypted string, invalid JSON'
            )


class RestCredentials(object):
    """
    Credential Management stored in passwords.conf
    """

    PASSWORD = u'********'
    EMPTY_VALUE = u''

    def __init__(
            self,
            splunkd_uri,
            session_key,
            endpoint
    ):
        self._splunkd_uri = splunkd_uri
        self._splunkd_info = urlparse(self._splunkd_uri)
        self._session_key = session_key
        self._endpoint = endpoint
        self._realm = '__REST_CREDENTIAL__#{base_app}#{endpoint}'.format(
            base_app=get_base_app_name(),
            endpoint=self._endpoint.internal_endpoint.strip('/')
        )

    def get_encrypted_field_names(self, name, data):
        return [x.name for x in self._endpoint.model(name, data).fields if x.encrypted]

    def encrypt_for_create(self, name, data):
        """
            force to encrypt all fields that need to be encrypted
            used for create scenarios
        :param name:
        :param data:
        :return:
        """
        encrypted_field_names = self.get_encrypted_field_names(name, data)
        encrypting = {}
        for field_name in encrypted_field_names:
            if field_name in data and data[field_name]:
                # if it exist in data and it's not empty,
                # encrypt it and set original value as "****..."
                encrypting[field_name] = data[field_name]
                data[field_name] = self.PASSWORD

        if encrypting:
            # only save credential when the stanza is existing in
            # passwords.conf or encrypting data is not empty
            self._set(name, encrypting)

    def encrypt_for_update(self, name, data):
        """

        :param name:
        :param data:
        :return:
        """
        encrypted_field_names = self.get_encrypted_field_names(name, data)
        encrypting = {}
        if not encrypted_field_names:
            # return if there are not encrypted fields
            return
        for field_name in encrypted_field_names:
            if field_name in data and data[field_name]:
                if data[field_name] != self.PASSWORD:
                    # if the field in data and not empty and it's not '*******', encrypted it
                    encrypting[field_name] = data[field_name]
                    data[field_name] = self.PASSWORD
                else:
                    # if the field value is '********', keep the original value
                    original_clear_password = self._get(name)
                    if original_clear_password and original_clear_password.get(field_name):
                        encrypting[field_name] = original_clear_password[field_name]
                    else:
                        # original password does not exist, use '********' as password
                        encrypting[field_name] = data[field_name]
            elif field_name in data and not data[field_name]:
                data[field_name] = ''
            else:
                # field not in data
                # if the optional encrypted field is not passed, keep original if it exist
                original_clear_password = self._get(name)
                if original_clear_password and original_clear_password.get(field_name):
                    encrypting[field_name] = original_clear_password[field_name]
                    data[field_name] = self.PASSWORD

        if encrypting:
            self._set(name, encrypting)
        else:
            self.delete(name)

    def decrypt_for_get(self, name, data):
        """
            encrypt password if conf changed and return data that needs to write back to conf
        :param name:
        :param data:
        :return:
        """
        data_need_write_to_conf = dict()
        # password dict needs to be encrypted
        encrypting = dict()
        encrypted_field_names = self.get_encrypted_field_names(name, data)
        if not encrypted_field_names:
            return
        try:
            # try to get clear password for the entity
            clear_password = self._get(name)
            # password exist for the entity
            for field_name in encrypted_field_names:
                if field_name in data and data[field_name]:
                    if data[field_name] != self.PASSWORD:
                        # if the field exist in data and not equals to '*******'
                        # add to dict to be encrypted, else treat it as unchanged
                        encrypting[field_name] = data[field_name]
                        data_need_write_to_conf[field_name] = self.PASSWORD

                    else:
                        # get clear password for the field
                        data[field_name] = clear_password[field_name]
                        encrypting[field_name] = clear_password[field_name]

            if encrypting and clear_password != encrypting:
                # update passwords.conf if password changed
                self._set(name, encrypting)
        except CredentialNotExistException:
            # password does not exist for the entity
            for field_name in encrypted_field_names:
                if field_name in data and data[field_name]:
                    if data[field_name] != self.PASSWORD:
                        # if the field exist in data and not equals to '*******'
                        # add to dict to be encrypted
                        encrypting[field_name] = data[field_name]
                        data_need_write_to_conf[field_name] = self.PASSWORD
                    else:
                        # treat '*******' as password
                        encrypting[field_name] = self.PASSWORD

            if encrypting:
                # set passwords.conf if encrypting data is not empty
                self._set(name, encrypting)

        return data_need_write_to_conf

    def encrypt(self, name, data):
        """

        :param name:
        :param data:
        :return:
        """
        # Check if encrypt is needed
        model = self._endpoint.model(name, data)
        need_encrypting = all(field.encrypted for field in model.fields)
        if not need_encrypting:
            return
        try:
            encrypted = self._get(name)
            existing = True
        except CredentialNotExistException:
            encrypted = {}
            existing = False
        encrypting = self._filter(name, data, encrypted)
        self._merge(name, data, encrypted, encrypting)
        if existing or encrypting:
            # only save credential when the stanza is existing in
            # passwords.conf or encrypting data is not empty
            self._set(name, encrypting)

    def decrypt(self, name, data, show_credentials=False):
        """

        :param name:
        :param data:
        :return: If the passwords.conf is updated, masked data.
            Else, None.
        """
        try:
            # clear password object loads from json
            encrypted = self._get(name)
            existing = True
        except CredentialNotExistException:
            encrypted = {}
            existing = False
        # get fields to be encrypted
        encrypting = self._filter(name, data, encrypted)
        self._merge(name, data, encrypted, encrypting)
        if existing or encrypting:
            # only save credential when the stanza is existing in
            # passwords.conf or encrypting data is not empty
            self._set(name, encrypting)
        data.update(encrypting)
        return encrypted

    def decrypt_all(self, data):
        """
        :param data:
        :return: changed stanza list
        """
        credential_manager = CredentialManager(
            self._session_key,
            owner=self._endpoint.user,
            app=self._endpoint.app,
            realm=self._realm,
            scheme=self._splunkd_info.scheme,
            host=self._splunkd_info.hostname,
            port=self._splunkd_info.port
        )

        all_passwords = credential_manager._get_all_passwords()
        # filter by realm
        realm_passwords = filter(lambda x: x['realm'] == self._realm, all_passwords)
        return self._merge_passwords(data, realm_passwords)

    @staticmethod
    def _delete_empty_value_for_dict(dct):
        empty_value_names = [k for k, v in dct.iteritems() if v == '']
        for k in empty_value_names:
            del dct[k]

    def _merge_passwords(self, data, passwords):
        """
            return if some fields need to write with new "******"
        """
        # merge clear passwords to response data
        changed_item_list = []

        password_dict = {pwd['username']: json.loads(pwd['clear_password']) for pwd in passwords}
        # existed passwords models: previously has encrypted value
        existing_encrypted_items = filter(lambda x: x['name'] in password_dict, data)

        # previously has no encrypted value
        not_encrypted_items = filter(lambda x: x['name'] not in password_dict, data)

        # For model that password existed
        # 1.Password changed: Update it and add to changed_item_list
        # 2.Password unchanged: Get the password and update the response data
        for existed_model in existing_encrypted_items:
            name = existed_model['name']
            clear_password = password_dict[name]
            need_write_magic_pwd = False
            need_write_back_pwd = False
            for k, v in clear_password.iteritems():
                # make sure key exist in model content
                if k in existed_model['content']:
                    if existed_model['content'][k] == self.PASSWORD:
                        # set existing as raw value
                        existed_model['content'][k] = v
                    elif existed_model['content'][k] == '':
                        # mark to delete it
                        clear_password[k] = ''
                        need_write_back_pwd = True
                        continue
                    else:
                        need_write_magic_pwd = True
                        need_write_back_pwd = True
                        clear_password[k] = existed_model['content'][k]
                else:
                    # mark to delete it
                    clear_password[k] = ''
                    need_write_back_pwd = True

            # update the password storage
            if need_write_magic_pwd:
                changed_item_list.append(existed_model)

            if need_write_back_pwd:
                self._delete_empty_value_for_dict(clear_password)
                if clear_password:
                    self._set(name, clear_password)
                else:
                    # there's no any pwd any more, directly delete it.
                    self.delete(name)

        # For other models, encrypt the password and return
        for other_model in not_encrypted_items:
            name = other_model['name']
            content = other_model['content']
            fields = filter(lambda x: x.encrypted, self._endpoint.model(None, data).fields)
            clear_password = {}
            for field in fields:
                # make sure key exist in model content
                if field.name in content and content[field.name] != '':
                    clear_password[field.name] = content[field.name]
            if clear_password:
                self._set(name, clear_password)

        changed_item_list.extend(not_encrypted_items)
        return changed_item_list

    def delete(self, name):
        context = RestCredentialsContext(self._endpoint, name)
        mgr = self._get_manager(context)
        try:
            mgr.delete_password(user=context.username())
        except CredentialNotExistException:
            pass

    def _set(self, name, credentials):
        if credentials is None:
            return
        context = RestCredentialsContext(self._endpoint, name)
        mgr = self._get_manager(context)
        mgr.set_password(
            user=context.username(),
            password=context.dump(credentials)
        )

    def _get(self, name):
        context = RestCredentialsContext(self._endpoint, name)
        mgr = self._get_manager(context)
        try:
            string = mgr.get_password(user=context.username())
        except CredentialNotExistException:
            return None
        return context.load(string)

    def _filter(self, name, data, encrypted_data):
        model = self._endpoint.model(name, data)
        encrypting_data = {}
        for field in model.fields:
            if not field.encrypted:
                # remove non-encrypted fields
                if field.name in encrypted_data:
                    del encrypted_data[field.name]
                continue
            if field.name not in data:
                # ignore un-posted fields
                continue
            if data[field.name] == self.PASSWORD:
                # ignore already-encrypted fields
                continue
            if data[field.name] != self.EMPTY_VALUE:
                encrypting_data[field.name] = data[field.name]
                # non-empty fields
                data[field.name] = self.PASSWORD
                if field.name in encrypted_data:
                    del encrypted_data[field.name]
        return encrypting_data

    def _merge(self, name, data, encrypted, encrypting):
        model = self._endpoint.model(name, data)
        for field in model.fields:
            if field.encrypted is False:
                continue

            val_encrypting = encrypting.get(field.name)
            if val_encrypting:
                encrypted[field.name] = self.PASSWORD
                continue
            elif val_encrypting == self.EMPTY_VALUE:
                del encrypting[field.name]
                encrypted[field.name] = self.EMPTY_VALUE
                continue

            val_encrypted = encrypted.get(field.name)
            if val_encrypted:
                encrypting[field.name] = val_encrypted
                del encrypted[field.name]

    def _get_manager(self, context):
        return CredentialManager(
            self._session_key,
            owner=self._endpoint.user,
            app=self._endpoint.app,
            realm=context.realm(),
            scheme=self._splunkd_info.scheme,
            host=self._splunkd_info.hostname,
            port=self._splunkd_info.port
        )
