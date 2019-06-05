"""
This module hanles configuration related stuff
"""

import os.path as op

from . import conf_endpoints as scmc
from . import data_input_endpoints as scmdi
from . import property_endpoints as scmp
from . import request as req


def conf_file2name(conf_file):
    conf_name = op.basename(conf_file)
    if conf_name.endswith(".conf"):
        conf_name = conf_name[:-5]
    return conf_name


class ConfManager(object):

    def __init__(self, splunkd_uri, session_key, owner="nobody", app_name="-"):
        """
        :app_name: when creating conf stanza, app_name is required to set not
        to "-"
        :owner: when creating conf stanza, app_name is required to set not
        to "-"
        """

        self.splunkd_uri = splunkd_uri
        self.session_key = session_key
        self.owner = owner
        self.app_name = app_name

    def set_appname(self, appname):
        """
        This are cases we need edit/remove/create confs in different app
        context. call this interface to switch app context before manipulate
        the confs in different app context
        """

        self.app_name = appname

    def all_stanzas(self, conf_name, do_reload=False, ret_metadata=False):
        """
        :return: a list of dict stanza objects if successful.
                 Otherwise raise exception
        """

        if do_reload:
            self.reload_conf(conf_name)

        stanzas = scmc.get_conf(self.splunkd_uri, self.session_key,
                                "-", "-", conf_name)
        return self._delete_metadata(stanzas, ret_metadata)

    def all_stanzas_as_dicts(self, conf_name, do_reload=False,
                             ret_metadata=False):
        """
        :return: a dict of dict stanza objects if successful.
                 otherwise raise exception
        """

        stanzas = self.all_stanzas(conf_name, do_reload, ret_metadata)
        return {stanza["name"]: stanza for stanza in stanzas}

    def get_stanza(self, conf_name, stanza,
                   do_reload=False, ret_metadata=False):
        """
        @return dict if success otherwise raise exception
        """

        if do_reload:
            self.reload_conf(conf_name)

        stanzas = scmc.get_conf(self.splunkd_uri, self.session_key,
                                "-", "-", conf_name, stanza)
        stanzas = self._delete_metadata(stanzas, ret_metadata)
        return stanzas[0]

    def reload_conf(self, conf_name):
        scmc.reload_conf(self.splunkd_uri, self.session_key, "-", conf_name)

    def enable_conf(self, conf_name, stanza):
        scmc.operate_conf(self.splunkd_uri, self.session_key,
                          self.owner, self.app_name,
                          conf_name, stanza, "enable")

    def disable_conf(self, conf_name, stanza):
        scmc.operate_conf(self.splunkd_uri, self.session_key,
                          self.owner, self.app_name,
                          conf_name, stanza, "disable")

    def get_property(self, conf_name, stanza, key, do_reload=False):
        if do_reload:
            self.reload_conf(conf_name)

        return scmp.get_property(self.splunkd_uri, self.session_key,
                                 "-", "-", conf_name, stanza, key)

    def stanza_exist(self, conf_name, stanza):
        return scmc.stanza_exist(self.splunkd_uri, self.session_key,
                                 "-", "-", conf_name, stanza)

    def create_stanza(self, conf_name, stanza, key_values):
        scmc.create_stanza(self.splunkd_uri, self.session_key,
                           self.owner, self.app_name,
                           conf_name, stanza, key_values)

    def update_stanza(self, conf_name, stanza, key_values):
        scmc.update_stanza(self.splunkd_uri, self.session_key,
                           self.owner, self.app_name,
                           conf_name, stanza, key_values)

    def delete_stanza(self, conf_name, stanza):
        scmc.delete_stanza(self.splunkd_uri, self.session_key,
                           self.owner, self.app_name,
                           conf_name, stanza)

    def create_properties(self, conf_name, stanza):
        scmp.create_properties(self.splunkd_uri, self.session_key,
                               self.owner, self.app_name,
                               conf_name, stanza)

    def update_properties(self, conf_name, stanza, key_values):
        scmp.update_properties(self.splunkd_uri, self.session_key,
                               self.owner, self.app_name,
                               conf_name, stanza, key_values)

    def delete_stanzas(self, conf_name, stanzas):
        """
        :param stanzas: list of stanzas
        :return: list of failed stanzas
        """

        failed_stanzas = []
        for stanza in stanzas:
            try:
                self.delete_stanza(conf_name, stanza)
            except Exception:
                failed_stanzas.append(stanza)
        return failed_stanzas

    # data input management
    def create_data_input(self, input_type, name, key_values=None):
        scmdi.create_data_input(self.splunkd_uri, self.session_key,
                                self.owner, self.app_name,
                                input_type, name, key_values)

    def update_data_input(self, input_type, name, key_values):
        scmdi.update_data_input(self.splunkd_uri, self.session_key,
                                self.owner, self.app_name,
                                input_type, name, key_values)

    def delete_data_input(self, input_type, name):
        scmdi.delete_data_input(self.splunkd_uri, self.session_key,
                                self.owner, self.app_name,
                                input_type, name)

    def get_data_input(self, input_type, name=None, do_reload=False):
        if do_reload:
            self.reload_data_input(input_type)

        return scmdi.get_data_input(self.splunkd_uri, self.session_key,
                                    "-", "-", input_type, name)

    def reload_data_input(self, input_type):
        scmdi.reload_data_input(self.splunkd_uri, self.session_key,
                                "-", "-", input_type)

    def enable_data_input(self, input_type, name):
        scmdi.operate_data_input(self.splunkd_uri, self.session_key,
                                 self.owner, self.app_name,
                                 input_type, name, "enable")

    def disable_data_input(self, input_type, name):
        scmdi.operate_data_input(self.splunkd_uri, self.session_key,
                                 self.owner, self.app_name,
                                 input_type, name, "disable")

    def data_input_exist(self, input_type, name):
        try:
            result = self.get_data_input(input_type, name)
        except req.ConfNotExistsException:
            return False

        return result is not None

    def all_data_input_stanzas(self, input_type, do_reload=False,
                               ret_metadata=False):
        stanzas = self.get_data_input(input_type, do_reload=do_reload)
        for stanza in stanzas:
            if "eai:acl" in stanza and "app" in stanza["eai:acl"]:
                stanza["appName"] = stanza["eai:acl"]["app"]
                stanza["userName"] = stanza["eai:acl"].get("owner", "nobody")
        return self._delete_metadata(stanzas, ret_metadata)

    def get_data_input_stanza(self, input_type, name, do_reload=False,
                              ret_metadata=False):

        stanzas = self.get_data_input(input_type, name, do_reload)
        stanzas = self._delete_metadata(stanzas, ret_metadata)
        return stanzas[0]

    def delete_data_input_stanzas(self, input_type, names):
        """
        :param stanzas: list of stanzas
        :return: list of failed stanzas
        """

        failed_names = []
        for name in names:
            try:
                self.delete_data_input(input_type, name)
            except Exception:
                failed_names.append(name)
        return failed_names

    def _delete_metadata(self, stanzas, ret_metadata):
        if stanzas and not ret_metadata:
            for stanza in stanzas:
                for key in stanza.keys():
                    if key.startswith("eai:"):
                        del stanza[key]
        return stanzas
