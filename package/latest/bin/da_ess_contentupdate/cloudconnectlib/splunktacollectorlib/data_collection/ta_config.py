import os.path as op
import socket

import ta_consts as c
import ta_helper as th
from ..common import log as stulog
from ...splunktalib import modinput as modinput
from ...splunktalib import splunk_cluster as sc
from ...splunktalib.common import util


# methods can be overrided by subclass : process_task_configs
class TaConfig(object):
    _current_hostname = socket.gethostname()
    _appname = util.get_appname_from_path(op.abspath(__file__))

    def __init__(self, meta_config, client_schema, log_suffix=None,
                 stanza_name=None, input_type=None,
                 single_instance=True):
        self._meta_config = meta_config
        self._stanza_name = stanza_name
        self._input_type = input_type
        self._log_suffix = log_suffix
        self._single_instance = single_instance
        self._task_configs = []
        self._client_schema = client_schema
        self._server_info = sc.ServerInfo(meta_config[c.server_uri],
                                          meta_config[c.session_key])
        self._all_conf_contents = {}
        self._get_division_settings = {}
        self.set_logging()
        self._load_task_configs()

    def is_shc_member(self):
        return self._server_info.is_shc_member()

    def is_search_head(self):
        return self._server_info.is_search_head()

    def is_single_instance(self):
        return self._single_instance

    def get_meta_config(self):
        return self._meta_config

    def get_task_configs(self):
        return self._task_configs

    def get_all_conf_contents(self):
        if self._all_conf_contents:
            return self._all_conf_contents.get(c.inputs), \
                   self._all_conf_contents.get(c.all_configs), \
                   self._all_conf_contents.get(c.global_settings)

        inputs, configs, global_settings = th.get_all_conf_contents(
            self._meta_config[c.server_uri],
            self._meta_config[c.session_key],
            self._client_schema, self._input_type)
        self._all_conf_contents[c.inputs] = inputs
        self._all_conf_contents[c.all_configs] = configs
        self._all_conf_contents[c.global_settings] = global_settings
        return inputs, configs, global_settings

    def set_logging(self):
        # The default logger name is "cloud_connect_engine"
        if self._stanza_name and self._log_suffix:
            logger_name = self._log_suffix + "_" + th.format_name_for_file(
                self._stanza_name)
            stulog.reset_logger(logger_name)
        inputs, configs, global_settings = self.get_all_conf_contents()
        log_level = "INFO"
        for item in global_settings.get("settings"):
            if item.get(c.name) == "logging" and item.get("loglevel"):
                log_level = item["loglevel"]
                break
        stulog.set_log_level(log_level)
        stulog.logger.info("Set log_level={}".format(log_level))
        stulog.logger.info("Start {} task".format(self._stanza_name))

    def get_input_type(self):
        return self._input_type

    def _get_checkpoint_storage_type(self, config):
        cs_type = config.get(c.checkpoint_storage_type)
        stulog.logger.debug("Checkpoint storage type=%s", cs_type)

        cs_type = cs_type.strip() if cs_type else c.checkpoint_auto

        # Allow user configure 'auto' and 'file' only.
        if cs_type not in (c.checkpoint_auto, c.checkpoint_file):
            stulog.logger.warning(
                "Checkpoint storage type='%s' is invalid, change it to '%s'",
                cs_type, c.checkpoint_auto
            )
            cs_type = c.checkpoint_auto

        if cs_type == c.checkpoint_auto and self.is_search_head():
            stulog.logger.info(
                "Checkpoint storage type is '%s' and instance is "
                "search head, set checkpoint storage type to '%s'.",
                c.checkpoint_auto,
                c.checkpoint_kv_storage
            )
            cs_type = c.checkpoint_kv_storage
        return cs_type

    def _load_task_configs(self):
        inputs, configs, global_settings = self.get_all_conf_contents()
        if self._input_type:
            inputs = inputs.get(self._input_type)
        if not self._single_instance:
            inputs = [input for input in inputs if
                      input[c.name] == self._stanza_name]
        all_task_configs = []
        for input in inputs:
            task_config = {}
            task_config.update(input)
            task_config[c.configs] = configs
            task_config[c.settings] = \
                {item[c.name]: item for item in global_settings["settings"]}
            if self.is_single_instance():
                collection_interval = "collection_interval"
                task_config[c.interval] = task_config.get(collection_interval)
            task_config[c.interval] = int(task_config[c.interval])
            if task_config[c.interval] <= 0:
                raise ValueError(
                    "The interval value {} is invalid."
                    " It should be a positive integer".format(
                        task_config[c.interval]))

            task_config[c.checkpoint_storage_type] = \
                self._get_checkpoint_storage_type(task_config)

            task_config[c.appname] = TaConfig._appname
            task_config[c.mod_input_name] = self._input_type
            task_config[c.stanza_name] = task_config[c.name]

            all_task_configs.append(task_config)
        self._task_configs = all_task_configs

    # Override this method if some transforms or validations needs to be done
    # before task_configs is exposed
    def process_task_configs(self, task_configs):
        pass


def create_ta_config(settings, config_cls=TaConfig, log_suffix=None,
                     single_instance=True):
    meta_config, configs = modinput.get_modinput_configs_from_stdin()
    stanza_name = None
    input_type = None
    if configs and "://" in configs[0].get("name", ""):
        input_type, stanza_name = configs[0].get("name").split("://", 1)
    return config_cls(meta_config, settings, log_suffix, stanza_name,
                      input_type, single_instance=single_instance)
