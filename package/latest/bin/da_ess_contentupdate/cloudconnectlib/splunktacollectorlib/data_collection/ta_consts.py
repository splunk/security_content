server_uri = "server_uri"
session_key = "session_key"
version = "version"
appname = "appname"
event_writer = "event_writer"
index = "index"
default_index = "default"
source = "source"
sourcetype = "sourcetype"
data_loader = "data_loader"

meta_configs = "meta_configs"
disabled = "disabled"
resource = "resource"
events = "events"
scope = "scope"
checkpoint_dir = "checkpoint_dir"

ckpt_dict = "ckpt_dict"
inputs = "inputs"
input_name = "input_name"
input_data = "input_data"
interval = "interval"
data = "data"
batch_size = 'batch_size'
time_fmt = "%Y-%m-%dT%H:%M:%S"
utc_time_fmt = "%Y-%m-%dT%H:%M:%S.%fZ"

# system setting keys
checkpoint_storage_type = "builtin_system_checkpoint_storage_type"

# Possible values for checkpoint storage type
checkpoint_auto = 'auto'
checkpoint_kv_storage = 'kv_store'
checkpoint_file = 'file'

# For cache file
use_cache_file = "builtin_system_use_cache_file"
max_cache_seconds = "builtin_system_max_cache_seconds"
# For kv store
collection_name = "builtin_system_kvstore_collection_name"

settings = "__settings__"
configs = "__configs__"

name = "name"
config = "config"
division = "division"
stanza_name = "stanza_name"
divide_key = "_divide_key"
divide_endpoint = "_divide_endpoint"
mod_input_name = "mod_input_name"
global_settings = "global_settings"
all_configs = "all_configs"
