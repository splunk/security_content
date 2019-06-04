"""
This module hanles high level TA configuration related stuff
"""

import copy
import os.path as op

from . import conf_manager as conf
from . import request as conf_req
from .. import credentials as cred
from ..common import util as utils


class TAConfManager(object):

    encrypted_token = "******"
    reserved_keys = ("userName", "appName")

    def __init__(self, conf_file, splunkd_uri, session_key, appname=None):
        if appname is None:
            appname = utils.get_appname_from_path(op.abspath(__file__))
        self._conf_file = conf.conf_file2name(conf_file)
        self._conf_mgr = conf.ConfManager(splunkd_uri, session_key,
                                          app_name=appname)
        self._cred_mgr = cred.CredentialManager(
            splunkd_uri, session_key, app=appname,
            owner="nobody", realm=appname)
        self._keys = None

    def set_appname(self, appname):
        """
        This are cases we need edit/remove/create confs in different app
        context. call this interface to switch app context before manipulate
        the confs in different app context
        """

        self._conf_mgr.set_appname(appname)
        self._cred_mgr.set_appname(appname)

    def _delete_reserved_keys(self, stanza):
        new_stanza = copy.deepcopy(stanza)
        for k in self.reserved_keys:
            if k in new_stanza:
                del new_stanza[k]
        return new_stanza

    def create(self, stanza):
        """
        @stanza: dick like object
        {
        "name": xxx,
        "k1": v1,
        "k2": v2,
        ...
        }
        @return exception if failure
        """

        stanza = self._delete_reserved_keys(stanza)
        encrypted_stanza = self._encrypt(stanza)
        self._conf_mgr.create_stanza(self._conf_file,
                                     encrypted_stanza["name"],
                                     encrypted_stanza)

    def update(self, stanza):
        """
        @stanza: dick like object
        {
        "name": xxx,
        "k1": v1,
        "k2": v2,
        ...
        }

        @return: exception if failure
        """

        if not self._conf_mgr.stanza_exist(self._conf_file, stanza["name"]):
            self.create(stanza)
        else:
            stanza = self._delete_reserved_keys(stanza)
            encrypted_stanza = self._encrypt(stanza)
            self._conf_mgr.update_properties(
                self._conf_file, encrypted_stanza["name"], encrypted_stanza)

    def delete(self, stanza_name):
        """
        @return: exception if failure
        """

        try:
            stanza = self._conf_mgr.get_stanza(self._conf_file, stanza_name)
        except conf_req.ConfNotExistsException:
            return

        self._delete_creds(stanza)
        self._conf_mgr.delete_stanza(self._conf_file, stanza_name)

    def get(self, stanza_name, return_acl=False):
        """
        @return: dict object if sucess otherwise raise exception
        """

        stanza = self._conf_mgr.get_stanza(self._conf_file, stanza_name,
                                           ret_metadata=return_acl)
        stanza = self._decrypt(stanza)
        stanza["disabled"] = utils.is_true(stanza.get("disabled"))
        return stanza

    def all(self, filter_disabled=False, return_acl=True):
        """
        @return: a dict of dict objects if success
        otherwise exception
        """

        results = {}
        stanzas = self._conf_mgr.all_stanzas(self._conf_file,
                                             ret_metadata=return_acl)
        for stanza in stanzas:
            stanza = self._decrypt(stanza)
            stanza["disabled"] = utils.is_true(stanza.get("disabled"))
            if filter_disabled and stanza["disabled"]:
                continue
            results[stanza["name"]] = stanza
        return results

    def reload(self):
        self._conf_mgr.reload_conf(self._conf_file)

    def set_encrypt_keys(self, keys):
        """
        :keys: a list keys of a stanza which need to be encrypted
        for example: ["username", "password"]
        """

        self._keys = keys

    def is_encrypted(self, stanza):
        """
        :stanza: dict object
        return True if the values of encrypt keys equals self.encrypted_token
        otherwise return False
        """

        if self._keys is None:
            return False

        for k in stanza.iterkeys():
            if k in self._keys:
                if stanza.get(k) == self.encrypted_token:
                    return True
        return False

    def _encrypt(self, stanza):
        """
        :stanza: if self._keys are in stanza, encrypt the values of the key
        and then mask the value to self.encrypted_token
        """

        if self._keys is None:
            return stanza

        stanza_to_be_encrypted = {}
        for key in self._keys:
            if key in stanza:
                stanza_to_be_encrypted[key] = stanza[key]

        if stanza_to_be_encrypted:
            self._cred_mgr.update({stanza["name"]: stanza_to_be_encrypted})
            encrypted_stanza = copy.deepcopy(stanza)
            for key in stanza_to_be_encrypted.iterkeys():
                encrypted_stanza[key] = self.encrypted_token
            return encrypted_stanza
        return stanza

    def _decrypt(self, stanza):
        """
        :stanza: if there are keys in self._keys in stanza and if the values of
        the keys are self.encrypted_token, decrypt the value
        """

        if self._keys is None:
            return stanza

        stanza_name = stanza["name"]
        clear_password = None
        for key in self._keys:
            if key in stanza and stanza[key] == self.encrypted_token:
                clear_password = self._cred_mgr.get_clear_password(
                    stanza_name)
                break

        if clear_password:
            for key in self._keys:
                if key in clear_password[stanza_name]:
                    stanza[key] = clear_password[stanza_name][key]
        return stanza

    def _delete_creds(self, stanza):
        """
        :stanza: if there are keys of self._keys and the keys are in stanza,
        delete the encrypted creds
        """

        if self._keys is None:
            return

        for key in self._keys:
            if key in stanza:
                self._cred_mgr.delete(stanza["name"])
                break
