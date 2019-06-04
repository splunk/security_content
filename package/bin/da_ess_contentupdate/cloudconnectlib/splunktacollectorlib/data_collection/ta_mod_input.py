#!/usr/bin/python

"""
This is the main entry point for My TA
"""

import os.path as op
import platform
import sys
import time

from . import ta_checkpoint_manager as cpmgr
from . import ta_config as tc
from . import ta_data_client as tdc
from . import ta_data_loader as dl
from ..common import load_schema_file as ld
from ..common import log as stulog
from ...common.lib_util import get_app_root_dir, get_mod_input_script_name
from ...splunktalib import file_monitor as fm
from ...splunktalib import modinput
from ...splunktalib import orphan_process_monitor as opm
from ...splunktalib.common import util as utils

utils.remove_http_proxy_env_vars()

__CHECKPOINT_DIR_MAX_LEN__ = 180


def do_scheme(
        mod_input_name,
        schema_para_list=None,
        single_instance=True,
):
    """
    Feed splunkd the TA's scheme

    """
    builtin_names = {
        "name", "index", "sourcetype", "host", "source",
        "disabled", "interval"
    }

    param_string_list = []
    if schema_para_list is None:
        schema_para_list = ()

    for param in schema_para_list:
        if param in builtin_names:
            continue

        param_string_list.append(
            """
        <arg name="{param}">
          <title>{param}</title>
          <required_on_create>0</required_on_create>
          <required_on_edit>0</required_on_edit>
        </arg>
        """.format(param=param)
        )

    description = ("Go to the add-on's configuration UI and configure"
                   " modular inputs under the Inputs menu.")

    print """
    <scheme>
    <title>{data_input_title}</title>
    <description>{description}</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>
    <use_single_instance>{single_instance}</use_single_instance>
    <endpoint>
      <args>
        <arg name="name">
          <title>{data_input_title} Data Input Name</title>
        </arg>
        {param_str}
      </args>
    </endpoint>
    </scheme>
    """.format(
        single_instance=(str(single_instance)).lower(),
        data_input_title=mod_input_name,
        param_str=''.join(param_string_list),
        description=description,
    )


def _setup_signal_handler(data_loader, ta_short_name):
    """
    Setup signal handlers
    :data_loader: data_loader.DataLoader instance
    """

    def _handle_exit(signum, frame):
        stulog.logger.info("{} receives exit signal".format(ta_short_name))
        if data_loader is not None:
            data_loader.tear_down()

    utils.handle_tear_down_signals(_handle_exit)


def _handle_file_changes(data_loader):
    """
    :reload conf files and exit
    """

    def _handle_refresh(changed_files):
        stulog.logger.info("Detect {} changed, reboot itself".format(
            changed_files))
        data_loader.tear_down()

    return _handle_refresh


def _get_conf_files(settings):
    rest_root = settings.get("meta").get("restRoot")
    file_list = [rest_root + "_settings.conf"]
    if settings.get("pages") and settings.get("pages").get("configuration"):
        configs = settings.get("pages").get("configuration")
        tabs = configs.get("tabs") if configs.get("tabs") else []
        for tab in tabs:
            if tab.get("table"):
                file_list.append(rest_root + "_" + tab.get("name") + ".conf")
    ta_dir = get_app_root_dir()
    return [op.join(ta_dir, "local", f) for f in file_list]


def run(collector_cls, settings, checkpoint_cls=None, config_cls=None,
        log_suffix=None, single_instance=True, cc_json_file=None):
    """
    Main loop. Run this TA forever
    """
    ta_short_name = settings["meta"]["name"].lower()

    # This is for stdout flush
    utils.disable_stdout_buffer()

    # http://bugs.python.org/issue7980
    time.strptime('2016-01-01', '%Y-%m-%d')

    loader = dl.create_data_loader()

    # handle signal
    _setup_signal_handler(loader, ta_short_name)

    # monitor files to reboot
    try:
        monitor = fm.FileMonitor(_handle_file_changes(loader),
                                 _get_conf_files(settings))
        loader.add_timer(monitor.check_changes, time.time(), 10)
    except Exception:
        stulog.logger.exception("Fail to add files for monitoring")

    # add orphan process handling, which will check each 1 second
    orphan_checker = opm.OrphanProcessChecker(loader.tear_down)
    loader.add_timer(orphan_checker.check_orphan, time.time(), 1)

    tconfig = tc.create_ta_config(settings, config_cls or tc.TaConfig,
                                  log_suffix, single_instance=single_instance)
    task_configs = tconfig.get_task_configs()

    if not task_configs:
        stulog.logger.debug("No task and exiting...")
        return
    meta_config = tconfig.get_meta_config()
    meta_config["cc_json_file"] = cc_json_file

    if tconfig.is_shc_member():
        # Don't support SHC env
        stulog.logger.error("This host is in search head cluster environment , "
                            "will exit.")
        return

    # In this case, use file for checkpoint
    if _is_checkpoint_dir_length_exceed_limit(tconfig,
                                              meta_config["checkpoint_dir"]):
        stulog.logger.error("The length of the checkpoint directory path: '{}' "
                            "is too long. The max length we support is {}",
                            meta_config["checkpoint_dir"],
                            __CHECKPOINT_DIR_MAX_LEN__)
        return

    jobs = [
        tdc.create_data_collector(
            loader,
            tconfig,
            meta_config,
            task_config,
            collector_cls,
            checkpoint_cls=checkpoint_cls or cpmgr.TACheckPointMgr
        )
        for task_config in task_configs
        ]

    loader.run(jobs)


def _is_checkpoint_dir_length_exceed_limit(config, checkpoint_dir):
    return platform.system() == 'Windows' \
           and not config.is_search_head() \
           and len(checkpoint_dir) >= __CHECKPOINT_DIR_MAX_LEN__


def validate_config():
    """
    Validate inputs.conf
    """

    _, configs = modinput.get_modinput_configs_from_stdin()
    return 0


def usage():
    """
    Print usage of this binary
    """

    hlp = "%s --scheme|--validate-arguments|-h"
    print >> sys.stderr, hlp % sys.argv[0]
    sys.exit(1)


def main(
        collector_cls,
        schema_file_path,
        log_suffix="modinput",
        checkpoint_cls=None,
        config_cls=None,
        cc_json_file=None,
        schema_para_list=None,
        single_instance=True
):
    """
    Main entry point
    """
    assert collector_cls, "ucc modinput collector is None."
    assert schema_file_path, "ucc modinput schema file is None"

    settings = ld(schema_file_path)

    mod_input_name = get_mod_input_script_name()

    args = sys.argv
    if len(args) > 1:
        if args[1] == "--scheme":
            do_scheme(
                mod_input_name=mod_input_name,
                schema_para_list=schema_para_list,
                single_instance=single_instance
            )
        elif args[1] == "--validate-arguments":
            sys.exit(validate_config())
        elif args[1] in ("-h", "--h", "--help"):
            usage()
        else:
            usage()
    else:
        try:
            run(
                collector_cls,
                settings,
                checkpoint_cls=checkpoint_cls,
                config_cls=config_cls,
                log_suffix=log_suffix,
                single_instance=single_instance,
                cc_json_file=cc_json_file
            )
        except Exception:
            stulog.logger.exception(
                "{} task encounter exception".format(mod_input_name))
        stulog.logger.info("End {} task".format(mod_input_name))
    sys.exit(0)
