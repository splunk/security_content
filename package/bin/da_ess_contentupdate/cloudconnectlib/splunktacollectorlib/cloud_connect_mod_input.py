import ConfigParser
import os.path as op

from .data_collection import ta_mod_input as ta_input
from .ta_cloud_connect_client import TACloudConnectClient as CollectorCls
from ..common.lib_util import (
    get_main_file, get_app_root_dir, get_mod_input_script_name
)


def _load_options_from_inputs_spec(app_root, stanza_name):
    input_spec_file = 'inputs.conf.spec'
    file_path = op.join(app_root, 'README', input_spec_file)

    if not op.isfile(file_path):
        raise RuntimeError("README/%s doesn't exist" % input_spec_file)

    parser = ConfigParser.RawConfigParser(allow_no_value=True)
    parser.read(file_path)
    options = parser.defaults().keys()
    stanza_prefix = '%s://' % stanza_name

    stanza_exist = False
    for section in parser.sections():
        if section == stanza_name or section.startswith(stanza_prefix):
            options.extend(parser.options(section))
            stanza_exist = True
    if not stanza_exist:
        raise RuntimeError("Stanza %s doesn't exist" % stanza_name)
    return set(options)


def _find_ucc_global_config_json(app_root, ucc_config_filename):
    """Find UCC config file from all possible directories"""
    candidates = ['local', 'default', 'bin',
                  op.join('appserver', 'static', 'js', 'build')]

    for candidate in candidates:
        file_path = op.join(app_root, candidate, ucc_config_filename)
        if op.isfile(file_path):
            return file_path
    raise RuntimeError(
        'Unable to load %s from [%s]'
        % (ucc_config_filename, ','.join(candidates))
    )


def _get_cloud_connect_config_json(script_name):
    config_file_name = '.'.join([script_name, 'cc.json'])
    return op.join(op.dirname(get_main_file()), config_file_name)


def run(single_instance=False):
    script_name = get_mod_input_script_name()

    cce_config_file = _get_cloud_connect_config_json(script_name)

    app_root = get_app_root_dir()
    ucc_config_path = _find_ucc_global_config_json(
        app_root, 'globalConfig.json'
    )

    schema_params = _load_options_from_inputs_spec(app_root, script_name)
    ta_input.main(
        CollectorCls,
        schema_file_path=ucc_config_path,
        log_suffix=script_name,
        cc_json_file=cce_config_file,
        schema_para_list=schema_params,
        single_instance=single_instance
    )
